from logmate.schemas.logline import Logline
from datetime import datetime

def test_logfile_initialisation():
    timestamp: datetime = datetime.now()
    msg: str = "some message"
    assert Logline(timestamp=timestamp, msg=msg, lineno=10, filename="test")
