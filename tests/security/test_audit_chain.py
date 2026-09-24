"""Audit-chain integrity tests.

The audit log is the record of who did what. It is useful only if a quiet edit
or deletion is *detectable*, so these tests attack the chain rather than trust
it: they tamper, truncate, cross tenants, and reorder keys, and they assert that
verification notices.

The regression this file exists to guard against: two audit writes in the same
transaction must chain to *each other*, not both to genesis. If ``last_entry_hash``
forgets to flush, entry 2 links to entry 1's predecessor and the chain looks
valid while describing a history that never happened.
"""

from __future__ import annotations

import uuid

from veyl_api.audit import (
    GENESIS_HASH,
    AuditRecord,
    canonical_payload,
    compute_entry_hash,
    last_entry_hash,
    verify_chain,
    write_audit,
)
from veyl_api.db.base import utcnow
from veyl_api.enums import AuditAction
from veyl_api.models import AuditLog


def _record(org_id: str, *, action=AuditAction.SCAN_CREATED, **kwargs) -> AuditRecord:
    defaults = {
        "action": action,
        "organization_id": org_id,
        "actor_email": "analyst@example.com",
        "resource_type": "scan",
        "resource_id": uuid.uuid4().hex,
        "detail": "test entry",
    }
    defaults.update(kwargs)
    return AuditRecord(**defaults)


def _payload_for(entry: AuditLog) -> str:
    """Rebuild the canonical payload of a persisted entry, as verify_chain does."""
    action = entry.action.value if hasattr(entry.action, "value") else str(entry.action)
    return canonical_payload(
        organization_id=entry.organization_id,
        action=action,
        actor_user_id=entry.actor_user_id,
        actor_email=entry.actor_email,
        resource_type=entry.resource_type,
        resource_id=entry.resource_id,
        result=entry.result,
        detail=entry.detail,
        metadata=entry.metadata_json,
        created_at=entry.created_at,
    )


def _seed(session, org_id: str, count: int = 3) -> list[AuditLog]:
    entries = [_record(org_id, detail=f"entry {i}") for i in range(count)]
    written = [write_audit(session, r) for r in entries]
    session.commit()
    return written


def test_chain_verifies_when_intact(session, organization):
    _seed(session, organization.id, 3)

    result = verify_chain(session, organization.id)

    assert result.is_valid is True
    assert result.entries_checked == 3
    assert result.first_bad_entry_id is None
    assert result.reason is None


def test_entries_link_to_each_other_not_to_genesis(session, organization):
    """The flush regression: entry 2 must chain to entry 1, not to genesis.

    Without a flush inside ``last_entry_hash``, both entries read the same
    predecessor and the chain is internally consistent but historically false.
    """
    written = _seed(session, organization.id, 3)
    session.expire_all()

    assert written[0].prev_hash == GENESIS_HASH
    assert written[1].prev_hash == written[0].entry_hash
    assert written[2].prev_hash == written[1].entry_hash
    assert written[1].prev_hash != GENESIS_HASH
    assert len({w.entry_hash for w in written}) == 3

    assert verify_chain(session, organization.id).is_valid is True


def test_tampering_is_detected(session, organization):
    """Editing a field after the fact must invalidate that entry."""
    written = _seed(session, organization.id, 3)
    target = written[1]

    target.detail = "a detail nobody wrote"
    session.commit()

    result = verify_chain(session, organization.id)

    assert result.is_valid is False
    assert result.first_bad_entry_id == target.id
    assert "content hash mismatch" in result.reason
    assert result.entries_checked == 1  # entries 0 passed, 1 failed


def test_recomputed_hash_on_a_tampered_entry_still_breaks_the_link(session, organization):
    """An attacker who fixes the hash still desynchronises the next link.

    This is why the chain is worth having: correcting one row's hash makes the
    following row's ``prev_hash`` wrong, so the break simply moves forward.
    """
    written = _seed(session, organization.id, 3)
    target = written[0]

    target.detail = "rewritten"
    target.entry_hash = compute_entry_hash(_payload_for(target), target.prev_hash)
    session.commit()

    result = verify_chain(session, organization.id)

    assert result.is_valid is False
    assert result.first_bad_entry_id == written[1].id
    assert "broken link" in result.reason


def test_truncation_is_detected(session, organization):
    """Deleting a middle entry must be detectable, not silently absorbed."""
    written = _seed(session, organization.id, 3)

    session.delete(written[1])
    session.commit()

    result = verify_chain(session, organization.id)

    assert result.is_valid is False
    assert result.first_bad_entry_id == written[2].id
    assert "broken link" in result.reason


def test_chain_is_per_tenant(session, organization, other_organization):
    """One tenant's log must verify independently of another's."""
    _seed(session, organization.id, 2)
    _seed(session, other_organization.id, 3)

    assert verify_chain(session, organization.id).entries_checked == 2
    assert verify_chain(session, other_organization.id).entries_checked == 3

    # Tampering in one tenant must not disturb the other's verdict.
    victim = session.query(AuditLog).filter_by(organization_id=organization.id).first()
    victim.result = "FAILURE"
    session.commit()

    assert verify_chain(session, organization.id).is_valid is False
    assert verify_chain(session, other_organization.id).is_valid is True


def test_empty_chain_is_valid(session, organization):
    result = verify_chain(session, organization.id)

    assert result.is_valid is True
    assert result.entries_checked == 0


def test_hash_is_deterministic_and_key_dependent():
    payload = "canonical-string"

    first = compute_entry_hash(payload, GENESIS_HASH, "key-a")
    assert first == compute_entry_hash(payload, GENESIS_HASH, "key-a")

    # A different secret must yield a different hash, or the secret is decorative.
    assert first != compute_entry_hash(payload, GENESIS_HASH, "key-b")
    # A different predecessor must too, or entries could be replayed positionally.
    assert first != compute_entry_hash(payload, "f" * 64, "key-a")
    # A different payload must too.
    assert first != compute_entry_hash("canonical-string ", GENESIS_HASH, "key-a")


def test_canonicalisation_is_insensitive_to_key_order():
    """Key order must not change the hash, or verification would be flaky.

    The canonical form is produced by ``canonical_payload``; the same logical
    dict must always serialise to the same string.
    """
    kwargs = {
        "organization_id": "org-1",
        "action": "SCAN_CREATED",
        "actor_user_id": None,
        "actor_email": "a@example.com",
        "resource_type": "scan",
        "resource_id": "r-1",
        "result": "SUCCESS",
        "detail": "hello",
        "metadata": {"b": 2, "a": 1},
        "created_at": utcnow(),
    }
    reordered = dict(reversed(list(kwargs.items())))

    a = canonical_payload(**kwargs)
    b = canonical_payload(**reordered)

    assert a == b
    # Nested keys are sorted too, not just the top level.
    assert '"a":1,"b":2' in a
    # The hash operates on the canonical string, so equal strings hash equally.
    assert compute_entry_hash(a, GENESIS_HASH, "k") == compute_entry_hash(b, GENESIS_HASH, "k")


def test_last_entry_hash_flushes_pending_rows(session, organization):
    """An uncommitted entry must still be visible to the next writer."""
    assert last_entry_hash(session, organization.id) == GENESIS_HASH

    write_audit(session, _record(organization.id, detail="pending"))
    assert last_entry_hash(session, organization.id) != GENESIS_HASH

    # Rolling back to genesis proves the flush was a flush, not a commit.
    session.rollback()
    assert last_entry_hash(session, organization.id) == GENESIS_HASH
