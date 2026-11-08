"""Executor: the only path from an approved action to a real operation.

Order of operations is deliberate::

    get action -> revalidate parameters -> consume single-use approval
    -> atomically claim the action -> run one registered handler
    -> verify -> record audit -> finish

The approval is consumed *before* anything runs, so a crash or timeout leaves
the action un-retryable without a fresh approval. State-changing actions never
run in this process: they go through the one-shot elevation adapter.
"""

from __future__ import annotations

import time

from defense import policy, rollback
from defense.models import (
    ACTION_TTL_SECONDS,
    ActionError,
    ActionPreview,
    ActionRequest,
    AuditEvent,
    DefenseError,
    ExecutionResult,
    PolicyError,
    canonical_json,
    new_id,
    params_hash,
)
from defense.registry import get_spec
from defense.windows import inspection
from defense.windows.firewall import RegistryError


class Executor:
    def __init__(self, actions, approvals, audit, rules, elevation,
                 clock=time.time, inspection_runner=None,
                 firewall_runner=None):
        self.actions = actions
        self.approvals = approvals
        self.audit = audit
        self.rules = rules
        self.elevation = elevation
        self.clock = clock
        self.inspection_runner = inspection_runner
        self.firewall_runner = firewall_runner

    # ------------------------------------------------------------- preview
    def preview(self, action_type, params):
        spec = get_spec(action_type)
        canonical = policy.validate_action(action_type, params)

        if action_type == "remove_cyberguard_firewall_rule":
            try:
                record = self.rules.assert_owned(canonical["rule_name"])
            except RegistryError as exc:
                raise PolicyError(
                    "The ownership registry is corrupt or unreadable; "
                    "refusing to prepare a removal.",
                    error_category=exc.category,
                ) from None
            if record is None:
                raise PolicyError(
                    "This rule is not recorded as CyberGuard-owned. "
                    "Refusing to prepare its removal."
                )

        now = float(self.clock())
        info = spec.preview_builder(canonical, rules=self.rules)

        action = ActionRequest(
            action_id=new_id(),
            action_type=action_type,
            params=canonical,
            target=info["target"],
            risk=spec.risk,
            requires_admin=spec.requires_admin,
            rollback_supported=spec.rollback_supported,
            created_at=now,
            expires_at=now + ACTION_TTL_SECONDS,
            params_hash=params_hash(canonical),
            description=info.get("title", spec.title),
        )
        self.actions.add(action)

        self._audit(
            event_type="preview",
            action=action,
            approval="not_required",
            outcome="previewed",
            elevation="not_required",
            rollback_available=spec.rollback_supported,
            rollback_status="not_applicable",
        )

        preview = ActionPreview(
            action_id=action.action_id,
            action_type=action_type,
            title=info.get("title", spec.title),
            target=info["target"],
            params=canonical,
            expected_effect=info["expected_effect"],
            risk=spec.risk,
            requires_admin=spec.requires_admin,
            rollback_supported=spec.rollback_supported,
            warnings=list(info.get("warnings") or []),
            existing_rule=info.get("existing_rule"),
            idempotent=bool(info.get("idempotent")),
            created_at=action.created_at,
            expires_at=action.expires_at,
        )
        return action, preview

    # ------------------------------------------------------------ approval
    def approve(self, action_id, confirm):
        action = self.actions.get(action_id)
        spec = get_spec(action.action_type)

        if spec.read_only:
            raise ActionError(
                "Read-only actions need no approval; run them through "
                "/api/defense/inspect.",
                action_id=action.action_id,
                error_category="approval_not_required",
                http_status=400,
            )

        if not isinstance(confirm, str) or confirm.strip() != action.action_type:
            raise DefenseError(
                "Approval is explicit: send 'confirm' equal to the exact "
                f"action type ({action.action_type}).",
                action_id=action.action_id,
                error_category="approval_invalid",
                http_status=409,
            )

        record, token = self.approvals.issue(action)

        self._audit(
            event_type="approval",
            action=action,
            approval="granted",
            outcome="pending",
            elevation="not_required",
            rollback_available=spec.rollback_supported,
            rollback_status="not_applicable",
        )

        return {
            "approval": record.public_dict(),
            "approval_token": token,
            "action": action.to_dict(),
        }

    # ------------------------------------------------------------- execute
    def execute(self, action_id, token=None):
        action = self.actions.get(action_id)
        spec = get_spec(action.action_type)

        # 1. Revalidate the canonical parameters even though they were
        #    validated at preview time.
        try:
            canonical = policy.validate_action(action.action_type, action.params)
        except DefenseError as exc:
            self._audit(
                event_type="execution",
                action=action,
                approval="invalid",
                outcome="rejected",
                error_category=exc.error_category,
                elevation="not_required",
            )
            raise

        if (
            canonical_json(canonical) != canonical_json(action.params)
            or params_hash(canonical) != action.params_hash
        ):
            self._audit(
                event_type="execution",
                action=action,
                approval="invalid",
                outcome="rejected",
                error_category="parameters_changed",
                elevation="not_required",
            )
            from defense.models import ApprovalInvalid

            raise ApprovalInvalid(
                "The action parameters changed after approval; refusing to "
                "execute.",
                action_id=action.action_id,
            )

        # 2. Consume the single-use approval before any change is possible.
        approval_status = "not_required"
        if not spec.read_only:
            try:
                self.approvals.consume(
                    action.action_id,
                    token,
                    expected_params_hash=action.params_hash,
                    expected_action_type=action.action_type,
                )
            except DefenseError as exc:
                self._audit(
                    event_type="execution",
                    action=action,
                    approval=exc.error_category,
                    outcome="rejected",
                    error_category=exc.error_category,
                    elevation="not_required",
                )
                raise
            approval_status = "granted"

        # 3. Claim the action exactly once, then run.
        self.actions.claim(action.action_id)
        started = time.perf_counter()

        result = None
        try:
            result = self._run(
                action, spec, canonical, approval_status, started
            )
        finally:
            self.actions.finish(
                action.action_id,
                outcome=result.status if result is not None else "failure",
            )

        self._audit(
            event_type="execution",
            action=action,
            approval=result.approval,
            outcome=result.status,
            error_category=result.error_category,
            elevation=result.elevation,
            rollback_available=result.rollback_available,
            rollback_status=result.rollback_status,
        )
        return result

    def _run(self, action, spec, canonical, approval_status, started):
        # Read-only preview: report the would-be effect, change nothing.
        if action.action_type == "preview_firewall_block_rule":
            info = spec.preview_builder(canonical, rules=self.rules)
            detail = {
                "available": True,
                "action_type": action.action_type,
                "target": info["target"],
                "expected_effect": info["expected_effect"],
                "warnings": list(info.get("warnings") or []),
                "rule_name": info.get("rule_name"),
                "idempotent": bool(info.get("idempotent")),
                "state_changed": False,
            }
            return self._result(
                action, "success", approval_status, "not_required",
                changed=False, detail=detail, verified=True, started=started,
            )

        # Other read-only actions run the fixed inspection commands.
        if spec.read_only:
            try:
                detail = inspection.run_inspection(
                    action.action_type, canonical,
                    runner=self.inspection_runner,
                )
            except Exception as exc:
                return self._result(
                    action, "failure", approval_status, "not_required",
                    changed=False,
                    error=f"{type(exc).__name__}: {exc}",
                    error_category="inspection_failed",
                    detail={}, verified=None, started=started,
                )

            if detail.get("available"):
                return self._result(
                    action, "success", approval_status, "not_required",
                    changed=False, detail=detail, verified=True,
                    started=started,
                )

            return self._result(
                action, "failure", approval_status, "not_required",
                changed=False,
                error=detail.get("error"),
                error_category=detail.get("error_category", "inspection_failed"),
                detail=detail, verified=None, started=started,
            )

        # State-changing action: one-shot elevated helper only.
        elevated = self.elevation.execute(
            action.action_type, canonical, action.action_id
        )

        status = elevated.get("status", "failure")
        changed = bool(elevated.get("changed"))
        verified = elevated.get("verified")
        detail = dict(elevated.get("detail") or {})
        rollback_available = False
        rollback_status = (
            "not_applicable" if not spec.rollback_supported else "unavailable"
        )

        # Never describe an execution that did not verify as a confirmed
        # success.  The helper already returns ``unverified`` in its normal
        # path; this also covers third-party adapters.
        if status == "success" and verified is not True:
            status = "unverified"

        if status in ("success", "unverified") and changed:
            now = float(self.clock())
            try:
                if action.action_type == "create_firewall_block_rule":
                    expected_name = policy.rule_name_for(canonical)
                    reported_name = detail.get("rule_name")
                    if reported_name is not None and (
                        reported_name != expected_name
                    ):
                        detail["ownership_error"] = "rule_name_mismatch"
                        rollback_status = "unavailable"
                    else:
                        rule_name = expected_name
                        detail["rule_name"] = rule_name
                        if status == "unverified":
                            # The change may have happened, but without a
                            # verified firewall query we cannot claim a
                            # trustworthy ownership record for rollback.
                            detail["ownership_error"] = "unverified_execution"
                            rollback_status = "unavailable"
                        else:
                            self.rules.upsert({
                                "rule_name": rule_name,
                                "action_id": action.action_id,
                                "params": canonical,
                                "created_at": now,
                                "expires_at": now + (
                                    int(canonical.get(
                                        "lifetime_minutes", 60
                                    )) * 60
                                ),
                                "description": canonical.get("description"),
                            })
                            rollback_available = bool(
                                spec.rollback_supported
                            )
                            if rollback_available:
                                rollback_status = "available"
                elif action.action_type == "remove_cyberguard_firewall_rule":
                    if status == "unverified":
                        detail["ownership_error"] = "unverified_execution"
                        rollback_status = "unavailable"
                    else:
                        self.rules.mark_removed(
                            canonical["rule_name"],
                            action_id=action.action_id,
                        )
                        rollback_available = bool(spec.rollback_supported)
                        if rollback_available:
                            rollback_status = "available"
            except RegistryError as exc:
                detail["ownership_error"] = exc.category
                rollback_status = "unavailable"
            except (OSError, ValueError) as exc:
                # The firewall change already happened. Do not report a false
                # failure; report that ownership/rollback metadata is missing
                # so rollback is not claimed to be available.
                detail["ownership_error"] = type(exc).__name__
                rollback_status = "unavailable"

        return self._result(
            action,
            status,
            approval_status,
            elevated.get("elevation", "failed"),
            changed=changed,
            error=elevated.get("error"),
            error_category=elevated.get("error_category"),
            detail=detail,
            verified=verified,
            rollback_available=rollback_available,
            rollback_status=rollback_status,
            started=started,
        )

    @staticmethod
    def _result(action, status, approval, elevation, changed=False, error=None,
                error_category=None, detail=None, verified=None,
                rollback_available=False, rollback_status="not_applicable",
                started=None):
        duration = 0
        if started is not None:
            duration = int((time.perf_counter() - started) * 1000)
        return ExecutionResult(
            action_id=action.action_id,
            action_type=action.action_type,
            status=status,
            changed=bool(changed),
            approval=approval,
            elevation=elevation,
            error=error,
            error_category=error_category,
            detail=dict(detail or {}),
            rollback_available=bool(rollback_available),
            rollback_status=rollback_status,
            verified=verified,
            duration_ms=duration,
        )

    # ------------------------------------------------------------- cancel
    def cancel(self, action_id):
        action = self.actions.cancel(action_id)
        self.approvals.revoke(action_id)

        self._audit(
            event_type="cancellation",
            action=action,
            approval="revoked",
            outcome="cancelled",
            elevation="not_required",
        )
        return {"action": action.to_dict(), "cancelled": True}

    # ----------------------------------------------------------- rollback
    def prepare_rollback(self, action_id):
        action = self.actions.get_any(action_id)
        spec = get_spec(action.action_type)

        if not spec.rollback_supported:
            raise ActionError(
                "This action type has no rollback.",
                action_id=action.action_id,
                error_category="rollback_not_applicable",
                http_status=409,
            )

        inverse_type, inverse_params = rollback.rollback_for(action, self.rules)
        new_action, preview = self.preview(inverse_type, inverse_params)

        self._audit(
            event_type="rollback",
            action=action,
            approval="not_required",
            outcome="prepared",
            elevation="not_required",
            rollback_available=True,
            rollback_status="available",
        )

        return {
            "source_action_id": action.action_id,
            "action": new_action.to_dict(),
            "preview": preview.to_dict(),
        }

    # ------------------------------------------------------------- inspect
    def inspect(self, action_type, params):
        spec = get_spec(action_type)

        if not spec.read_only:
            from defense.models import PolicyError

            raise PolicyError(
                "Only read-only actions can be inspected directly. Prepare a "
                "state-changing action and approve it explicitly."
            )

        canonical = policy.validate_action(action_type, params)

        if action_type == "preview_firewall_block_rule":
            info = spec.preview_builder(canonical, rules=self.rules)
            result = {
                "available": True,
                "action_type": action_type,
                "target": info["target"],
                "expected_effect": info["expected_effect"],
                "warnings": list(info.get("warnings") or []),
                "rule_name": info.get("rule_name"),
                "idempotent": bool(info.get("idempotent")),
                "params": canonical,
                "state_changed": False,
            }
        else:
            result = inspection.run_inspection(
                action_type, canonical, runner=self.inspection_runner
            )

        self.audit.record(AuditEvent(
            event_type="inspection",
            action_id="",
            action_type=action_type,
            target=result.get("target") or spec.title,
            params_summary=policy.safe_params(action_type, canonical),
            approval="not_required",
            outcome="success" if result.get("available") else "failure",
            error_category=(
                None if result.get("available")
                else result.get("error_category", "inspection_failed")
            ),
            elevation="not_required",
            rollback_available=False,
            rollback_status="not_applicable",
            timestamp=float(self.clock()),
        ))
        return result

    # --------------------------------------------------------------- audit
    def _audit(self, *, event_type, action, approval, outcome,
               error_category=None, elevation="not_required",
               rollback_available=False, rollback_status="not_applicable"):
        self.audit.record_action(
            event_type=event_type,
            action=action,
            approval=approval,
            outcome=outcome,
            error_category=error_category,
            elevation=elevation,
            rollback_available=rollback_available,
            rollback_status=rollback_status,
        )
