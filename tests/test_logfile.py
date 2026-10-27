import logging
from datetime import datetime
from pathlib import Path

import pytest

from logreach.logfile import MAX_KEPT_UNPARSED, Logfile, config_factory
from logreach.schemas.logfileconfig import JsonLogConfig, LogType, RegexLogConfig, TimestampRegex


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


def test_logfile_keeps_only_first_unparsed_lines_but_counts_all(tmp_path):
    logfile = tmp_path / 'syslog'
    logfile.write_text('Sep  1 14:08:07 host app: ok\n' + 'no timestamp\n' * (MAX_KEPT_UNPARSED + 3))
    config = config_factory(str(logfile), LogType.SYSLOG)
    with Logfile(config, logger=logging.getLogger()) as lf:
        assert len(list(lf)) == 1
    assert lf.unparsed_count == MAX_KEPT_UNPARSED + 3
    assert lf.unparsed == [(lineno, 'no timestamp\n') for lineno in range(2, MAX_KEPT_UNPARSED + 2)]


def test_syslog_without_year_takes_year_from_begin():
    config = config_factory('syslog', LogType.SYSLOG, begin=datetime(2020, 9, 1))
    assert config.parse_timestamp('Sep  1 13:25:26 host app: x\n') == datetime(2020, 9, 1, 13, 25, 26)


def test_syslog_without_year_takes_year_from_end_if_no_begin():
    config = config_factory('syslog', LogType.SYSLOG, end=datetime(2020, 9, 1))
    assert config.parse_timestamp('Sep  1 13:25:26 host app: x\n').year == 2020


def test_explicit_year_is_kept():
    config = config_factory('dpkg.log', LogType.SYSLOG, begin=datetime(2020, 1, 1))
    assert config.parse_timestamp('2026-09-01 13:25:35 status x\n').year == 2026
