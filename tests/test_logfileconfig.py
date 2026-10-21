import re
import pytest
from logreach.schemas.logfileconfig import TimestampRegex


@pytest.mark.parametrize("line, expected", [
    pytest.param("2026-09-01 13:25:38 status installed mailcap:all 3.69",
                 "2026-09-01 13:25:38", id="date-space-time"),
    pytest.param("2026-09-01T14:09:21.639533+00:00 docker systemd[1]: "
                 "session-46.scope: Deactivated successfully.",
                 "2026-09-01T14:09:21.639533+00:00", id="iso8601"),
    pytest.param("Sep  1 14:08:07 videoserver systemd[1]: Started Session 16 of user superuser.\n",
                 "Sep  1 14:08:07", id="bsd-padded-day"),
    pytest.param("Sep  1 14:08:07 14:08:06 systemd[1]: Started Session 16 of user superuser.\n",
                 "Sep  1 14:08:07", id="bsd-time-as-hostname"),
    pytest.param("Aug 31 16:49:00 raspberrypi systemd[1093]: "
                 "Queued start job for default target default.target.",
                 "Aug 31 16:49:00", id="bsd-two-digit-day"),
])
def test_timestampregex_syslog(line, expected):
    match = re.match(TimestampRegex.syslog.value, line)
    assert match is not None
    assert match.group(1) == expected


def test_audit_logs():
    match = re.match(TimestampRegex.audit.value,
                     'type=DAEMON_START msg=audit(1788266693.261:9117): op=start ver=3.0.9 format=enriched '
                     'kernel=6.6.62+rpt-rpi-2712 auid=4294967295 pid=700 uid=0 ses=4294967295 '
                     'res=successAUID="unset" UID="root"')
    assert match.group(1) == "1788266693.261"
