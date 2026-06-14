"""Builds a chronological event timeline from file metadata records."""

import datetime
from dataclasses import dataclass
from typing import Literal
from .metadata import FileMetadata

EventKind = Literal['created', 'modified', 'accessed']


@dataclass
class TimelineEvent:
    timestamp: datetime.datetime
    kind: EventKind
    path: str
    size: int
    extension: str
    is_hidden: bool
    is_system: bool


def build_timeline(
    metas: list[FileMetadata],
    include_accessed: bool = False,
) -> list[TimelineEvent]:
    """Convert metadata list into a sorted list of timeline events.

    Access timestamps are excluded by default because many systems update
    them continuously, generating noise that obscures meaningful activity.
    """
    events: list[TimelineEvent] = []

    for m in metas:
        common = dict(path=m.path, size=m.size, extension=m.extension,
                      is_hidden=m.is_hidden, is_system=m.is_system)
        events.append(TimelineEvent(timestamp=m.created,  kind='created',  **common))
        events.append(TimelineEvent(timestamp=m.modified, kind='modified', **common))
        if include_accessed:
            events.append(TimelineEvent(timestamp=m.accessed, kind='accessed', **common))

    events.sort(key=lambda e: e.timestamp)
    return events


def filter_by_range(
    events: list[TimelineEvent],
    start: datetime.datetime,
    end: datetime.datetime,
) -> list[TimelineEvent]:
    return [e for e in events if start <= e.timestamp <= end]


def filter_by_kind(
    events: list[TimelineEvent],
    kind: EventKind,
) -> list[TimelineEvent]:
    return [e for e in events if e.kind == kind]


def group_by_day(events: list[TimelineEvent]) -> dict[datetime.date, list[TimelineEvent]]:
    groups: dict[datetime.date, list[TimelineEvent]] = {}
    for e in events:
        groups.setdefault(e.timestamp.date(), []).append(e)
    return groups


def find_timestamp_anomalies(metas) -> list[dict]:
    """Return files where modified < created -- indicates timestamp tampering.

    Under normal Windows operation a file cannot be modified before it was
    created. When this condition is found it strongly suggests timestamps were
    manipulated by an attacker or an anti-forensics tool.
    """
    anomalies = []
    for m in metas:
        if m.modified < m.created:
            anomalies.append({
                "path": m.path,
                "created": m.created.strftime("%Y-%m-%d %H:%M:%S"),
                "modified": m.modified.strftime("%Y-%m-%d %H:%M:%S"),
                "delta": str(m.created - m.modified).split(".")[0],
                "note": "MODIFIED before CREATED -- possible tampering",
            })
    return anomalies
