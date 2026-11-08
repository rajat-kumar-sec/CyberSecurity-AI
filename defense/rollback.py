"""Rollback planning limited to changes CyberGuard created and can identify.

Rollback is deliberately *not* automatic. It produces an inverse action that
goes through the same preview -> explicit approval -> execute pipeline, so a
user cannot be surprised by a second privileged change.

Ownership rules
---------------
* A created rule can be removed by rollback only while it is still recorded as
  active *and* the record carries the action id that created it.
* A removed rule can be re-created only when CyberGuard recorded the exact
  parameters at removal time and the record names the removing action.
* Read-only actions and previews have no rollback.
"""

from __future__ import annotations

from defense import policy
from defense.models import ActionError
from defense.windows.firewall import RegistryError


def rollback_for(action, rules):
    """Return ``(action_type, params)`` for the inverse of ``action``.

    Raises :class:`ActionError` when rollback is not positively available.
    """
    if action.action_type == "create_firewall_block_rule":
        rule_name = policy.rule_name_for(action.params)
        try:
            record = rules.assert_owned(rule_name)
        except RegistryError:
            raise ActionError(
                "Rollback is unavailable: the ownership registry is corrupt "
                "or unreadable.",
                action_id=action.action_id,
                error_category="rollback_unavailable",
            ) from None

        if record is None:
            raise ActionError(
                "Rollback is unavailable: the rule is no longer recorded as "
                "active.",
                action_id=action.action_id,
                error_category="rollback_unavailable",
            )

        if record.get("action_id") != action.action_id:
            raise ActionError(
                "Rollback is unavailable: this action did not create that "
                "rule.",
                action_id=action.action_id,
                error_category="rollback_not_owned",
            )

        recorded = record.get("params")
        try:
            canonical = policy.validate_action(
                "create_firewall_block_rule", recorded
            )
        except Exception:
            raise ActionError(
                "Rollback is unavailable: the ownership record has invalid "
                "parameters.",
                action_id=action.action_id,
                error_category="rollback_unavailable",
            ) from None
        if canonical != action.params:
            raise ActionError(
                "Rollback is unavailable: the ownership record does not match "
                "the action's exact parameters.",
                action_id=action.action_id,
                error_category="rollback_not_owned",
            )

        return "remove_cyberguard_firewall_rule", {"rule_name": rule_name}

    if action.action_type == "remove_cyberguard_firewall_rule":
        rule_name = action.params["rule_name"]
        matches = [
            record for record in rules.list_removed()
            if record.get("rule_name") == rule_name
            and record.get("removed_by_action_id") == action.action_id
        ]

        if not matches:
            raise ActionError(
                "Rollback is unavailable: no removal record belongs to this "
                "action.",
                action_id=action.action_id,
                error_category="rollback_not_owned",
            )

        record = matches[-1]
        if record.get("rule_name") != rule_name:
            raise ActionError(
                "Rollback is unavailable: the removal record does not match "
                "the rule name.",
                action_id=action.action_id,
                error_category="rollback_not_owned",
            )

        original = record.get("params")
        if not isinstance(original, dict):
            raise ActionError(
                "Rollback is unavailable: the original parameters were not "
                "recorded.",
                action_id=action.action_id,
                error_category="rollback_unavailable",
            )

        try:
            canonical = policy.validate_action(
                "create_firewall_block_rule", original
            )
        except Exception as exc:
            raise ActionError(
                f"Rollback is unavailable: the recorded parameters no longer "
                f"validate ({type(exc).__name__}).",
                action_id=action.action_id,
                error_category="rollback_unavailable",
            ) from None

        if policy.rule_name_for(canonical) != rule_name:
            raise ActionError(
                "Rollback is unavailable: the recorded parameters do not "
                "derive the removed rule identity.",
                action_id=action.action_id,
                error_category="rollback_not_owned",
            )

        return "create_firewall_block_rule", canonical

    raise ActionError(
        "This action type has no rollback.",
        action_id=action.action_id,
        error_category="rollback_not_applicable",
    )
