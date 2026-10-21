from dataclasses import dataclass
from datetime import datetime


@dataclass
class Logline:
    timestamp: datetime
    msg: str
    lineno: int
    filename: str
