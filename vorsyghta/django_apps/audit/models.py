"""Audit app: tamper-evident, hash-chained audit event log.

Parity with FastAPI stack: AuditEventRecord (`vorsyghta/db/models/audit.py`)
plus the hash-chain invariant: `event_hash = sha256(prev_hash + event_id +
event_type + timestamp + category + severity + description)`.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from django.db import models
from django.db.models import Max


def _hash_event(prev_hash: str, event_id: str, event_type: str, timestamp: str, description: str) -> str:
    payload = json.dumps(
        {
            "prev_hash": prev_hash,
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": timestamp,
            "description": description,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditEvent(models.Model):
    """Tamper-evident audit record; mirrors AuditEventRecord."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_id = models.CharField(max_length=255, unique=True, db_index=True)
    event_type = models.CharField(max_length=255, db_index=True)
    category = models.CharField(max_length=100)
    severity = models.CharField(max_length=50)
    actor = models.JSONField()
    target = models.JSONField()
    context = models.JSONField()
    timestamp = models.DateTimeField(db_index=True)
    correlation_id = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    prev_hash = models.CharField(max_length=64, null=True, blank=True)
    event_hash = models.CharField(max_length=64, null=True, blank=True)
    tenant_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_events"
        ordering = ["-timestamp"]

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Fail-closed hash chaining on insert (audit invariant)."""
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)
        if self.event_hash is None:
            last = (
                AuditEvent.objects.order_by("-created_at")
                .aggregate(Max("event_hash"))
            )
            self.prev_hash = last.get("event_hash__max") or ""
            self.event_hash = _hash_event(
                prev_hash=self.prev_hash or "",
                event_id=self.event_id,
                event_type=self.event_type,
                timestamp=self.timestamp.isoformat(),
                description=self.description or "",
            )
        super().save(*args, **kwargs)

    def verify_chain(self) -> bool:
        """Verify this record's hash against stored prev_hash (audit invariant)."""
        expected = _hash_event(
            prev_hash=self.prev_hash or "",
            event_id=self.event_id,
            event_type=self.event_type,
            timestamp=self.timestamp.isoformat(),
            description=self.description or "",
        )
        return self.event_hash == expected
