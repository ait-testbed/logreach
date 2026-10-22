from dataclasses import dataclass
from datetime import datetime


@dataclass
class Logline:
    timestamp: datetime
    raw: str
    lineno: int
    filename: str
