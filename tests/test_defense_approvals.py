"""Action and approval store tests: TTL, single use, binding and replay."""

import time

import pytest

from defense.approvals import ActionStore, ApprovalStore
from defense.models import (
    ActionCancelled,
    ActionExpired,
    ActionNotFound,
    ApprovalExpired,
    ApprovalInvalid,
    ApprovalRequired,
    ApprovalUsed,
    DuplicateExecution,
    params_hash,
)
from defense_support import Clock


def make_action(action_id="a" * 32, action_type="create_firewall_block_rule",
                now=None):
    from defense.models import ActionRequest

    if now is None:
        now = time.time()

    return ActionRequest(
        action_id=action_id,
        action_type=action_type,
        params={"remote_address": "203.0.113.7/32"},
        target="Windows Firewall",
        risk="medium",
        requires_admin=True,
        rollback_supported=True,
        created_at=now,
        expires_at=now + 900,
        params_hash=params_hash({"remote_address": "203.0.113.7/32"}),
    )


# ------------------------------------------------------------- ActionStore


def test_action_store_returns_a_pending_action():
    clock = Clock()
    store = ActionStore(clock=clock)
    action = make_action(now=clock.now)
    store.add(action)

    assert store.get(action.action_id) is action
    assert len(store) == 1


@pytest.mark.parametrize("action_id", ["missing", "", "not-hex", None, 7])
def test_action_store_rejects_unknown_or_malformed_ids(action_id):
    store = ActionStore()
    with pytest.raises(ActionNotFound):
        store.get(action_id)


def test_action_store_expires_an_old_action():
    clock = Clock()
    store = ActionStore(clock=clock)
    action = make_action(now=clock.now)
    store.add(action)

    clock.advance(901)
    with pytest.raises(ActionExpired):
        store.get(action.action_id)


def test_action_store_never_revives_an_expired_action():
    clock = Clock()
    store = ActionStore(clock=clock)
    action = make_action(now=clock.now)
    store.add(action)

    clock.advance(901)
    with pytest.raises(ActionExpired):
        store.get(action.action_id)
    clock.now = 1000.0
    with pytest.raises(ActionExpired):
        store.get(action.action_id)


def test_cancelled_action_cannot_be_read_as_pending():
    store = ActionStore()
    action = make_action()
    store.add(action)
    store.cancel(action.action_id)

    with pytest.raises(ActionCancelled):
        store.get(action.action_id)


def test_claim_is_single_use():
    store = ActionStore()
    action = make_action()
    store.add(action)

    store.claim(action.action_id)
    with pytest.raises(DuplicateExecution):
        store.claim(action.action_id)


def test_finish_marks_the_action_executed():
    store = ActionStore()
    action = make_action()
    store.add(action)
    store.claim(action.action_id)
    store.finish(action.action_id)

    assert action.status == "executed"
    with pytest.raises(DuplicateExecution):
        store.get(action.action_id)


def test_cancelled_action_cannot_be_cancelled_after_execution():
    store = ActionStore()
    action = make_action()
    store.add(action)
    store.claim(action.action_id)
    store.finish(action.action_id)

    with pytest.raises(DuplicateExecution):
        store.cancel(action.action_id)


def test_prune_keeps_the_store_bounded():
    store = ActionStore()
    actions = []
    for index in range(10):
        action = make_action(action_id=f"{index:032x}", now=float(index))
        action.status = "executed"
        store.add(action)
        actions.append(action)

    removed = store.prune(keep=4)

    assert removed == 6
    assert len(store) == 4


# ----------------------------------------------------------- ApprovalStore


def test_issue_returns_a_one_time_token_and_stores_only_its_hash():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)

    record, token = store.issue(action)

    assert record.used is False
    assert record.token_hash != token
    assert token not in record.token_hash
    assert record.action_id == action.action_id
    assert record.expires_at == clock.now + 300


def test_consume_marks_the_approval_used():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    _, token = store.issue(action)

    consumed = store.consume(
        action.action_id,
        token,
        expected_params_hash=action.params_hash,
        expected_action_type=action.action_type,
    )

    assert consumed.used is True
    with pytest.raises(ApprovalUsed):
        store.consume(action.action_id, token)


def test_consume_without_an_approval_raises_required():
    store = ApprovalStore()

    with pytest.raises(ApprovalRequired):
        store.consume("a" * 32, "token")


@pytest.mark.parametrize("token", ["", None, 123, "x" * 201])
def test_consume_rejects_structurally_invalid_tokens(token):
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    store.issue(action)

    with pytest.raises(ApprovalInvalid):
        store.consume(action.action_id, token)


def test_consume_rejects_a_different_token():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    store.issue(action)

    with pytest.raises(ApprovalInvalid):
        store.consume(action.action_id, "not-the-token")


def test_consume_rejects_an_expired_approval():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    _, token = store.issue(action)

    clock.advance(301)
    with pytest.raises(ApprovalExpired):
        store.consume(action.action_id, token)


def test_consume_rejects_changed_parameters():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    _, token = store.issue(action)

    with pytest.raises(ApprovalInvalid):
        store.consume(
            action.action_id,
            token,
            expected_params_hash=params_hash({"remote_address": "x"}),
        )


def test_consume_rejects_a_different_action_type():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    _, token = store.issue(action)

    with pytest.raises(ApprovalInvalid):
        store.consume(
            action.action_id,
            token,
            expected_action_type="remove_cyberguard_firewall_rule",
        )


def test_reissuing_replaces_the_previous_token():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    _, first = store.issue(action)
    _, second = store.issue(action)

    assert first != second
    with pytest.raises(ApprovalInvalid):
        store.consume(action.action_id, first)
    store.consume(action.action_id, second)


def test_revoke_removes_the_approval():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    _, token = store.issue(action)

    assert store.revoke(action.action_id) is True
    assert store.revoke(action.action_id) is False
    with pytest.raises(ApprovalRequired):
        store.consume(action.action_id, token)


def test_peek_does_not_consume():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    record, _ = store.issue(action)

    assert store.peek(action.action_id) is record
    assert record.used is False


def test_clear_empties_the_store():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    action = make_action(now=clock.now)
    store.issue(action)

    assert len(store) == 1
    store.clear()
    assert len(store) == 0
