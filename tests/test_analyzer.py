from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from logreach.analyzer import Analyzer, IgnoreList, KnownLogfilePaths
from logreach.exceptions import LogTypeError
from logreach.schemas.logfileconfig import JsonLogConfig, LogConfig, RegexLogConfig, TimestampRegex
from samples import ACCESS, AUDIT, EVE_JSON, JSON_TIME, SYSLOG


def detect(tmp_path, content: str) -> LogConfig:
    """Detect the config of a file with content, without ignore list or types
    file."""
    logfile = tmp_path / 'logfile'
    logfile.write_text(content)
    return Analyzer(types_file='', ignores_file='').detect_config(str(logfile))


# --- type detection

@pytest.mark.parametrize('content, regex', [
    pytest.param(SYSLOG, TimestampRegex.SYSLOG, id='syslog'),
    pytest.param(AUDIT, TimestampRegex.AUDIT, id='audit'),
    pytest.param(ACCESS, TimestampRegex.ACCESS, id='access'),
])
def test_detects_regex_type(tmp_path, content, regex):
    config = detect(tmp_path, content)
    assert isinstance(config, RegexLogConfig)
    assert config.regex_pattern.pattern == regex.value


@pytest.mark.parametrize('content, key', [
    pytest.param(JSON_TIME, 'time', id='time'),
    pytest.param(EVE_JSON, 'timestamp', id='eve-timestamp'),
])
def test_detects_json_and_its_timestamp_key(tmp_path, content, key):
    config = detect(tmp_path, content)
    assert isinstance(config, JsonLogConfig)
    assert config.datetime_key == key


def test_detect_config_empty_file(tmp_path):
    with pytest.raises(LogTypeError, match='is empty'):
        detect(tmp_path, '')


def test_detect_config_file_without_timestamps(tmp_path):
    with pytest.raises(LogTypeError, match='Unable to determine logtype'):
        detect(tmp_path, 'no timestamps here\njust text\n')


def test_detect_config_uses_types_file(tmp_path, types_file):
    # a format no built-in regex knows, so only the types file entry can read it
    logfile = tmp_path / 'web_php.log'
    logfile.write_text('9/1/26, 1:25:44 PM UTC.519574 web_php[1170].INF [Login successful]\n')
    entries = types_file({'logfile_path': str(logfile), 'type': 'syslog', 'datetimeregex': r'\A(.+?UTC)'})
    config = Analyzer(types_file=str(entries), ignores_file='').detect_config(str(logfile))
    assert isinstance(config, RegexLogConfig)
    assert config.regex_pattern.pattern == r'\A(.+?UTC)'


@pytest.mark.parametrize('entry, dayfirst', [
    pytest.param({'dayfirst': True}, True, id='set'),
    pytest.param({}, False, id='default'),
])
def test_detect_config_reads_dayfirst_from_types_file(tmp_path, types_file, entry, dayfirst):
    logfile = tmp_path / 'suricata.log'
    logfile.write_text('1/9/2026 -- 13:25:40 - <Info> x\n')
    entries = types_file({'logfile_path': str(logfile), 'type': 'syslog', **entry})
    config = Analyzer(types_file=str(entries), ignores_file='').detect_config(str(logfile))
    assert config.dayfirst is dayfirst
    assert config.parse_timestamp(logfile.read_text()).month == (9 if dayfirst else 1)


def test_detect_config_finds_type_without_lines_in_time_window(tmp_path):
    # detection must not use the window: no line of this file is inside it
    logfile = tmp_path / 'syslog'
    logfile.write_text(SYSLOG)
    begin = datetime(2026, 9, 2, tzinfo=UTC)
    config = Analyzer(types_file='', ignores_file='').detect_config(
        str(logfile), begin=begin, dayfirst=True, timezone=ZoneInfo('Europe/Vienna'))
    assert config.describe() == 'syslog (Europe/Vienna)'
    assert (config.begin, config.end, config.dayfirst) == (begin, None, True)


@pytest.mark.parametrize('entry, timezone', [
    pytest.param({'timezone': 'Europe/Vienna'}, 'Europe/Vienna', id='from-types-file'),
    pytest.param({}, 'America/New_York', id='from-argument'),
])
def test_detect_config_types_file_settings_take_precedence(tmp_path, types_file, entry, timezone):
    logfile = tmp_path / 'syslog'
    logfile.write_text(SYSLOG)
    entries = types_file({'logfile_path': str(logfile), 'type': 'syslog', **entry})
    begin = datetime(2026, 9, 1, tzinfo=UTC)
    config = Analyzer(types_file=str(entries), ignores_file='').detect_config(
        str(logfile), begin=begin, timezone=ZoneInfo('America/New_York'))
    assert config.timezone == ZoneInfo(timezone)
    assert config.begin == begin


# --- ignore list and types file

def test_ignore_list_reads_patterns_from_file_and_extensions(ignore_list):
    ignore_file = ignore_list('# compressed logs', 'README\\Z  ', '', '   ')
    analyzer = Analyzer(types_file='', ignores_file=str(ignore_file), ignored_extensions=['gz'])
    # blank lines and comments are skipped, surrounding spaces stripped
    assert [pattern.pattern for pattern, _source in analyzer.ignores.patterns] == ['README\\Z', '\\.gz\\Z']
    assert analyzer.ignores.ignore_reason('/var/log/README') == f'{ignore_file} pattern README\\Z'
    assert analyzer.ignores.ignore_reason('/var/log/syslog.1.gz') == 'extension .gz'
    assert analyzer.ignores.ignore_reason('/var/log/syslog') is None


@pytest.mark.parametrize('path, reason', [
    ('/var/log/syslog.1.gz', 'extension .gz'),
    ('/var/log/journal/system.journal~', 'extension .journal~'),
    ('/etc/app.conf', 'extension .conf'),  # extension given without dot
    ('/etc/app.config', None),
    ('/var/log/gz', None),
    ('/var/log/syslog', None),
])
def test_ignore_list_ignores_extensions(path, reason):
    assert IgnoreList(extensions=['.gz', '.journal~', 'conf']).ignore_reason(path) == reason


def test_known_logfile_paths_contains_listed_paths(types_file):
    known = KnownLogfilePaths(str(types_file({'logfile_path': '/var/log/suricata/eve.json', 'type': 'json'})))
    assert '/var/log/suricata/eve.json' in known
    assert '/var/log/syslog' not in known
