"""Tamper-evident audit logging.

Each organization maintains its own hash chain. Row *n* stores

    entry_hash = sha256(canonical_payload || prev_hash || secret)

so removing, reordering, or editing any row invalidates every subsequent hash.
``verify_chain`` walks a tenant's log and reports the first break.

This is tamper-*evident*, not tamper-*proof*: an attacker with database write
access can recompute the whole chain. It defends against the realistic threat —
a user quietly editing or deleting their own entries — and it turns silent
tampering into a detectable event. Real tamper-proofing requires shipping the
chain head to append-only external storage, which is noted in the threat model.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from veyl_api.config import settings
from veyl_api.db.base import utcnow
from veyl_api.enums import AuditAction
from veyl_api.models import AuditLog

GENESIS_HASH = "0" * 64


def canonical_payload(
    *,
    organization_id: str,
    action: str,
    actor_user_id: str | None,
    actor_email: str | None,
    resource_type: str | None,
    resource_id: str | None,
    result: str,
    detail: str | None,
    metadata: dict[str, Any] | None,
    created_at: datetime,
) -> str:
    """Produce a stable string to hash.

    Keys are sorted and separators are fixed so the same logical entry always
    hashes identically, on any Python version and any database backend.
    """
    payload = {
        "organization_id": organization_id,
        "action": action,
        "actor_user_id": actor_user_id,
        "actor_email": actor_email,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "result": result,
        "detail": detail,
        "metadata": metadata or {},
        "created_at": created_at.isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_entry_hash(payload: str, prev_hash: str, secret: str | None = None) -> str:
    """Hash a canonical payload together with the previous entry's hash."""
    key = secret if secret is not None else settings.secret_key
    digest = hashlib.sha256()
    digest.update(payload.encode("utf-8"))
    digest.update(b"|")
    digest.update(prev_hash.encode("utf-8"))
    digest.update(b"|")
    digest.update(key.encode("utf-8"))
    return digest.hexdigest()


def last_entry_hash(session: Session, organization_id: str) -> str:
    """Return the hash of the newest audit row for a tenant, or the genesis hash.

    Pending (unflushed) rows are flushed first so that two audit writes in the
    same transaction chain correctly instead of both linking to the same
    predecessor.
    """
    session.flush()
    stmt = (
        select(AuditLog.entry_hash)
        .where(AuditLog.organization_id == organization_id)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(1)
    )
    value = session.execute(stmt).scalar_one_or_none()
    return value or GENESIS_HASH


@dataclass
class AuditRecord:
    """A pending audit entry, before it is persisted."""

    action: AuditAction
    organization_id: str
    actor_user_id: str | None = None
    actor_email: str | None = None
    actor_role: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    result: str = "SUCCESS"
    detail: str | None = None
    metadata: dict[str, Any] | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime | None = None


def write_audit(session: Session, record: AuditRecord) -> AuditLog:
    """Append an audit entry, chaining it to the tenant's previous entry.

    The caller is responsible for committing. This keeps the audit write inside
    the same transaction as the action it describes, so an action cannot commit
    without its audit record.
    """
    created_at = record.created_at or utcnow()
    prev_hash = last_entry_hash(session, record.organization_id)

    payload = canonical_payload(
        organization_id=record.organization_id,
        action=record.action.value,
        actor_user_id=record.actor_user_id,
        actor_email=record.actor_email,
        resource_type=record.resource_type,
        resource_id=record.resource_id,
        result=record.result,
        detail=record.detail,
        metadata=record.metadata,
        created_at=created_at,
    )
    entry_hash = compute_entry_hash(payload, prev_hash)

    entry = AuditLog(
        organization_id=record.organization_id,
        action=record.action,
        actor_user_id=record.actor_user_id,
        actor_email=record.actor_email,
        actor_role=record.actor_role,
        resource_type=record.resource_type,
        resource_id=record.resource_id,
        result=record.result,
        detail=record.detail,
        metadata_json=record.metadata or {},
        ip_address=record.ip_address,
        user_agent=record.user_agent,
        created_at=created_at,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    session.add(entry)
    return entry


@dataclass
class ChainVerification:
    """Result of verifying a tenant's audit chain."""

    organization_id: str
    entries_checked: int
    is_valid: bool
    first_bad_entry_id: str | None = None
    reason: str | None = None
    checked_at: datetime | None = None


def verify_chain(session: Session, organization_id: str) -> ChainVerification:
    """Walk a tenant's audit log and confirm every link and hash is intact."""
    stmt = (
        select(AuditLog)
        .where(AuditLog.organization_id == organization_id)
        .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
    )
    entries = list(session.execute(stmt).scalars())

    expected_prev = GENESIS_HASH
    for index, entry in enumerate(entries):
        if entry.prev_hash != expected_prev:
            return ChainVerification(
                organization_id=organization_id,
                entries_checked=index,
                is_valid=False,
                first_bad_entry_id=entry.id,
                reason=(
                    "broken link: entry's prev_hash does not match the preceding entry's "
                    "entry_hash (a row was inserted, removed, or reordered)"
                ),
                checked_at=utcnow(),
            )

        payload = canonical_payload(
            organization_id=entry.organization_id,
            action=entry.action.value if hasattr(entry.action, "value") else str(entry.action),
            actor_user_id=entry.actor_user_id,
            actor_email=entry.actor_email,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            result=entry.result,
            detail=entry.detail,
            metadata=entry.metadata_json,
            created_at=entry.created_at,
        )
        recomputed = compute_entry_hash(payload, entry.prev_hash)
        if recomputed != entry.entry_hash:
            return ChainVerification(
                organization_id=organization_id,
                entries_checked=index,
                is_valid=False,
                first_bad_entry_id=entry.id,
                reason="content hash mismatch: the entry's fields were modified after writing",
                checked_at=utcnow(),
            )

        expected_prev = entry.entry_hash

    return ChainVerification(
        organization_id=organization_id,
        entries_checked=len(entries),
        is_valid=True,
        checked_at=utcnow(),
    )
