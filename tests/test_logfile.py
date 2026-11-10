from datetime import datetime
from pathlib import Path

import pytest

from logreach.logfile import MAX_KEPT_UNPARSED, config_factory
from logreach.schemas.logfileconfig import JsonLogConfig, LogType, RegexLogConfig, TimestampRegex

# --- config_factory


@pytest.mark.parametrize('logtype, regex', [
    (LogType.SYSLOG, TimestampRegex.SYSLOG),
    (LogType.AUDIT, TimestampRegex.AUDIT),
    (LogType.ACCESS, TimestampRegex.ACCESS),
])
def test_config_factory_uses_default_regex(logtype, regex):
    config = config_factory('some.log', logtype)
    assert isinstance(config, RegexLogConfig)
    assert config.regex_pattern.pattern == regex.value
    assert config.logfile_path == Path('some.log')


@pytest.mark.parametrize('logtype', [LogType.SYSLOG, LogType.AUDIT, LogType.ACCESS])
def test_config_factory_prefers_custom_regex(logtype):
    config = config_factory('some.log', logtype, datetime_regex=r'\A(.+?UTC)')
    assert isinstance(config, RegexLogConfig)
    assert config.regex_pattern.pattern == r'\A(.+?UTC)'


def test_config_factory_json():
    config = config_factory('eve.json', LogType.JSON, datetime_key='timestamp', allow_empty_timestamp=False)
    assert isinstance(config, JsonLogConfig)
    assert config.datetime_key == 'timestamp'
    assert config.allow_empty_timestamp is False


def test_config_factory_json_requires_datetimekey():
    with pytest.raises(TypeError):
        config_factory('eve.json', LogType.JSON)


# --- Logfile

def test_logfile_skips_lines_outside_window_and_without_timestamp(tmp_path, read_logfile):
    logfile = tmp_path / 'syslog'
    logfile.write_text('Sep  1 13:00:00 host app: before\n'
                       'Sep  1 14:00:00 host app: inside\n'
                       'no timestamp\n'
                       'Sep  1 15:00:00 host app: after\n'
                       'Sep  1 14:30:00 host app: inside again\n')
    config = config_factory(str(logfile), LogType.SYSLOG, begin=datetime(2026, 9, 1, 13, 30),
                            end=datetime(2026, 9, 1, 14, 45))
    lines, logfile = read_logfile(config)
    assert [line.lineno for line in lines] == [2, 5]
    assert logfile.unparsed == [(3, 'no timestamp', 'no timestamp\n')]


def test_logfile_keeps_only_first_unparsed_lines_but_counts_all(tmp_path, read_logfile):
    logfile = tmp_path / 'syslog'
    logfile.write_text('Sep  1 14:08:07 host app: ok\n' + 'no timestamp\n' * (MAX_KEPT_UNPARSED + 3))
    config = config_factory(str(logfile), LogType.SYSLOG)
    lines, logfile = read_logfile(config)
    assert len(lines) == 1
    assert logfile.unparsed_count == MAX_KEPT_UNPARSED + 3
    assert logfile.unparsed == [(lineno, 'no timestamp', 'no timestamp\n')
                                for lineno in range(2, MAX_KEPT_UNPARSED + 2)]
