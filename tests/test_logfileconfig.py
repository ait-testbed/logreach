import json
import re
from datetime import UTC, datetime

import pytest

from logreach.exceptions import NoTimestamp
from logreach.logfile import config_factory
from logreach.schemas.logfileconfig import LogType, TimestampRegex

# --- timestamp regexes


@pytest.mark.parametrize('line, expected', [
    pytest.param('2026-09-01 13:25:38 status installed mailcap:all 3.69',
                 '2026-09-01 13:25:38', id='date-space-time'),
    pytest.param('2026-09-01T14:09:21.639533+00:00 docker systemd[1]: '
                 'session-46.scope: Deactivated successfully.',
                 '2026-09-01T14:09:21.639533+00:00', id='iso8601'),
    pytest.param('Sep  1 14:08:07 videoserver systemd[1]: Started Session 16 of user superuser.\n',
                 'Sep  1 14:08:07', id='bsd-padded-day'),
    pytest.param('Sep  1 14:08:07 14:08:06 systemd[1]: Started Session 16 of user superuser.\n',
                 'Sep  1 14:08:07', id='bsd-time-as-hostname'),
    pytest.param('Aug 31 16:49:00 raspberrypi systemd[1093]: '
                 'Queued start job for default target default.target.',
                 'Aug 31 16:49:00', id='bsd-two-digit-day'),
])
def test_timestampregex_syslog(line, expected):
    match = re.match(TimestampRegex.SYSLOG.value, line)
    assert match is not None
    assert match.group(1) == expected


def test_audit_logs():
    match = re.match(TimestampRegex.AUDIT.value,
                     'type=DAEMON_START msg=audit(1788266693.261:9117): op=start ver=3.0.9 format=enriched '
                     'kernel=6.6.62+rpt-rpi-2712 auid=4294967295 pid=700 uid=0 ses=4294967295 '
                     'res=successAUID="unset" UID="root"')
    assert match.group(1) == '1788266693.261'


# --- missing year

@pytest.mark.parametrize('window, line, expected', [
    pytest.param({'begin': datetime(2020, 9, 1)}, 'Sep  1 13:25:26 host app: x\n',
                 datetime(2020, 9, 1, 13, 25, 26), id='from-begin'),
    pytest.param({'end': datetime(2020, 9, 1)}, 'Sep  1 13:25:26 host app: x\n',
                 datetime(2020, 9, 1, 13, 25, 26), id='from-end'),
    pytest.param({'begin': datetime(2020, 1, 1)}, '2026-09-01 13:25:35 status x\n',
                 datetime(2026, 9, 1, 13, 25, 35), id='year-in-line-kept'),
])
def test_missing_year_comes_from_begin_or_end(window, line, expected):
    config = config_factory('syslog', LogType.SYSLOG, **window)
    assert config.parse_timestamp(line) == expected


# --- dayfirst

@pytest.mark.parametrize('line, dayfirst, expected', [
    pytest.param('1/9/2026 -- 13:25:40 - <Info> x\n', True,
                 datetime(2026, 9, 1, 13, 25, 40), id='suricata-dayfirst'),
    pytest.param('1/9/2026 -- 13:25:40 - <Info> x\n', False,
                 datetime(2026, 1, 9, 13, 25, 40), id='suricata-default'),
    pytest.param('09/01/2026-13:25:37 [**] x\n', False,
                 datetime(2026, 9, 1, 13, 25, 37), id='monthfirst-default'),
])
def test_dayfirst_decides_ambiguous_dates(line, dayfirst, expected):
    config = config_factory('suricata.log', LogType.SYSLOG, dayfirst=dayfirst)
    assert config.dayfirst is dayfirst
    assert config.parse_timestamp(line) == expected


def test_dayfirst_json():
    config = config_factory('app.json', LogType.JSON, datetime_key='time', dayfirst=True)
    assert config.parse_timestamp('{"time": "1/9/2026 13:25:40"}') == datetime(2026, 9, 1, 13, 25, 40)


@pytest.mark.parametrize('value, expected', [
    pytest.param(1756735200, datetime(2025, 9, 1, 14, 0, tzinfo=UTC), id='epoch-seconds'),
    pytest.param(1756735200.5, datetime(2025, 9, 1, 14, 0, 0, 500000, tzinfo=UTC), id='epoch-float'),
])
def test_json_timestamp_values(value, expected):
    config = config_factory('app.json', LogType.JSON, datetime_key='time')
    assert config.parse_timestamp(json.dumps({'time': value})) == expected


@pytest.mark.parametrize('line, reason', [
    pytest.param('{"time": "2026-09-01', 'invalid JSON (Unterminated string starting at, column 10)',
                 id='cut-off'),
    pytest.param('[1, 2]', 'no JSON object', id='no-object'),
    pytest.param('{"msg": "x"}', 'no "time" key', id='no-key'),
    pytest.param('{"time": "not a date"}', '"time" is no date', id='no-date'),
    pytest.param('{"time": 1756735200123}', '"time" is no date', id='epoch-milliseconds'),
    pytest.param('{"time": true}', '"time" is no date', id='bool'),
    pytest.param('{"time": null}', '"time" is no date', id='null'),
])
def test_json_line_without_timestamp_says_why(line, reason):
    config = config_factory('app.json', LogType.JSON, datetime_key='time')
    with pytest.raises(NoTimestamp) as error:
        config.parse_timestamp(line)
    assert str(error.value) == reason
