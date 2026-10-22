from datetime import datetime

from logreach.schemas.logline import Logline


def test_logfile_initialisation():
    timestamp: datetime = datetime.now()
    raw: str = "Sep  1 14:08:07 host app: some message"
    assert Logline(timestamp=timestamp, raw=raw, lineno=10, filename="test")
