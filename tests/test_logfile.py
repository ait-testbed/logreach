import logging
import re
from datetime import datetime

import pytest

from logreach.logfile import MAX_KEPT_UNPARSED, Logfile, config_factory
from logreach.schemas.logfileconfig import LogType, TimestampRegex


def at(time):
    return f'Sep  1 {time} host app: x\n'


def read(tmp_path, text, grep=(), **options):
    """Read text as syslog; return the lines Logfile yields and the closed
    Logfile."""
    path = tmp_path / 'syslog'
    path.write_text(text)
    config = config_factory(str(path), LogType.SYSLOG, **options)
    config.grep = [re.compile(pattern) for pattern in grep]
    with Logfile(config, logger=logging.getLogger()) as logfile:
        lines = list(logfile)
    return lines, logfile


@pytest.mark.parametrize('logtype', [LogType.SYSLOG, LogType.AUDIT, LogType.ACCESS])
def test_config_factory_regex(logtype):
    assert config_factory('x', logtype).regex_pattern.pattern == TimestampRegex[logtype.name].value
    assert config_factory('x', logtype, datetime_regex='(a)').regex_pattern.pattern == '(a)'


def test_config_factory_json():
    assert config_factory('x', LogType.JSON, datetime_key='ts').datetime_key == 'ts'
    with pytest.raises(TypeError):
        config_factory('x', LogType.JSON)


def test_line_without_timestamp_shares_time_window_of_line_before(tmp_path):
    text = at('13:00:00') + at('14:00:00') + 'none\n' + at('15:00:00') + 'none\n' + at('14:30:00')
    lines, _ = read(tmp_path, text, begin=datetime(2026, 9, 1, 13, 30), end=datetime(2026, 9, 1, 14, 45))
    assert [line.lineno for line in lines] == [2, 3, 6]
    assert (lines[1].timestamp, lines[1].reason) == (None, 'no timestamp')


def test_lines_before_first_timestamp_only_without_time_window(tmp_path):
    lines, _ = read(tmp_path, 'none\n' + at('14:00:00'))
    assert [line.lineno for line in lines] == [1, 2]
    lines, _ = read(tmp_path, 'none\n' + at('14:00:00'), begin=datetime(2026, 1, 1))
    assert [line.lineno for line in lines] == [2]


def test_grep_applies_to_lines_without_timestamp(tmp_path):
    lines, logfile = read(tmp_path, at('14:00:00') + '  at Foo\n  at Bar\n', grep=['Bar'])
    assert [line.lineno for line in lines] == [3]
    assert logfile.unparsed_count == 2  # counted whether they match or not


def test_keeps_only_first_unparsed_lines_for_report_but_yields_all(tmp_path):
    lines, logfile = read(tmp_path, at('14:00:00') + 'none\n' * (MAX_KEPT_UNPARSED + 3))
    assert len(lines) == MAX_KEPT_UNPARSED + 4
    assert logfile.unparsed_count == MAX_KEPT_UNPARSED + 3
    assert len(logfile.unparsed) == MAX_KEPT_UNPARSED
