from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Logline:
    # None: the line has no timestamp, reason says why
    timestamp: datetime | None
    raw: str
    lineno: int
    filename: str
    # repr=False keeps the CLI output as it was but allows api users to
    # see the reason for a line having no timestamp
    reason: str | None = field(default=None, repr=False)
