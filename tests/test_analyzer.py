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


# --- ignore list and types file

def test_ignore_list_skips_blank_lines_and_comments(ignore_list):
    ignores = IgnoreList(str(ignore_list('# compressed logs', '\\.gz\\Z  ', '', '   ')))
    assert [pattern.pattern for pattern, _source in ignores.patterns] == ['\\.gz\\Z']
    assert ignores.ignore_reason('/var/log/syslog.1.gz') is not None
    assert ignores.ignore_reason('/var/log/syslog') is None


@pytest.mark.parametrize('path, ignored', [
    ('/var/log/syslog.1.gz', True),
    ('/var/log/journal/system.journal~', True),
    ('/etc/app.conf', True),  # extension given without dot
    ('/etc/app.config', False),
    ('/var/log/gz', False),
    ('/var/log/syslog', False),
])
def test_ignore_list_ignores_extensions(path, ignored):
    ignores = IgnoreList(extensions=['.gz', '.journal~', 'conf'])
    assert (ignores.ignore_reason(path) is not None) is ignored


def test_ignore_list_combines_file_and_extensions(ignore_list):
    ignores = IgnoreList(str(ignore_list('README')), extensions=['.gz'])
    assert ignores.ignore_reason('/var/log/README') is not None
    assert ignores.ignore_reason('/var/log/syslog.1.gz') is not None
    assert ignores.ignore_reason('/var/log/syslog') is None


def test_known_logfile_paths_contains_listed_paths(types_file):
    known = KnownLogfilePaths(str(types_file({'logfile_path': '/var/log/suricata/eve.json', 'type': 'json'})))
    assert '/var/log/suricata/eve.json' in known
    assert '/var/log/syslog' not in known


def test_ignore_list_names_the_matching_pattern(ignore_list):
    ignore_file = ignore_list('README\\Z')
    ignores = IgnoreList(str(ignore_file), extensions=['gz'])
    assert ignores.ignore_reason('/var/log/README') == f'{ignore_file} pattern README\\Z'
    assert ignores.ignore_reason('/var/log/syslog.1.gz') == 'extension .gz'
    assert ignores.ignore_reason('/var/log/syslog') is None


def test_analyzer_ignores_paths_from_ignores_file_and_extensions(ignore_list):
    analyzer = Analyzer(types_file='', ignores_file=str(ignore_list('README\\Z')), ignored_extensions=['.gz'])
    assert analyzer.ignores.ignore_reason('/var/log/README') is not None
    assert analyzer.ignores.ignore_reason('/var/log/syslog.1.gz') is not None
    assert analyzer.ignores.ignore_reason('/var/log/syslog') is None
