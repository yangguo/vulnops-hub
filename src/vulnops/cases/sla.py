from __future__ import annotations

from datetime import datetime, timezone, timedelta

from vulnops.cases.models import PRIORITY_SLA_DAYS


def calculate_due_date(priority: str, created_at: datetime | None = None) -> datetime:
    created_at = created_at or datetime.now(timezone.utc)
    days = PRIORITY_SLA_DAYS.get(priority, 30)
    return created_at + timedelta(days=days)


def is_breached(due_at: datetime, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    return now > due_at
