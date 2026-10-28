import json

import pytest

from logreach.analyzer import Analyzer, IgnoreList, KnownLogfilePaths
from logreach.exceptions import LogTypeError
from logreach.schemas.logfileconfig import JsonLogConfig, LogConfig, RegexLogConfig, TimestampRegex

SYSLOG = ('Sep  1 14:08:07 videoserver systemd[1]: Started Session 16 of user superuser.\n'
          'Sep  1 14:09:00 videoserver systemd[1]: Started Session 17 of user superuser.\n')
AUDIT = 'type=DAEMON_START msg=audit(1788266693.261:9117): op=start ver=3.0.9 res=success\n'
ACCESS = '127.0.0.1 - - [01/Sep/2026:14:08:07 +0000] "GET / HTTP/1.1" 200 512\n'
# spaces after the separators: the loose syslog regex used to claim this line
JSON_TIME = '{"time": "2026-09-01T14:09:21+00:00", "msg": "session started"}\n'
EVE_JSON = '{"timestamp": "2026-09-01T14:09:21.639533+0000", "event_type": "alert"}\n'


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


def test_detect_config_uses_types_file(tmp_path):
    # a format no built-in regex knows, so only the types file entry can read it
    logfile = tmp_path / 'web_php.log'
    logfile.write_text('9/1/26, 1:25:44 PM UTC.519574 web_php[1170].INF [Login successful]\n')
    entry = {'logfile_path': str(logfile), 'type': 'syslog', 'datetimeregex': r'\A(.+?UTC)'}
    types_file = tmp_path / 'logtypes.json'
    types_file.write_text(json.dumps(entry) + '\n')
    config = Analyzer(types_file=str(types_file), ignores_file='').detect_config(str(logfile))
    assert isinstance(config, RegexLogConfig)
    assert config.regex_pattern.pattern == r'\A(.+?UTC)'


@pytest.mark.parametrize('entry, dayfirst', [
    pytest.param({'dayfirst': True}, True, id='set'),
    pytest.param({}, False, id='default'),
])
def test_detect_config_reads_dayfirst_from_types_file(tmp_path, entry, dayfirst):
    logfile = tmp_path / 'suricata.log'
    logfile.write_text('1/9/2026 -- 13:25:40 - <Info> x\n')
    types_file = tmp_path / 'logtypes.json'
    types_file.write_text(json.dumps({'logfile_path': str(logfile), 'type': 'syslog', **entry}) + '\n')
    config = Analyzer(types_file=str(types_file), ignores_file='').detect_config(str(logfile))
    assert config.dayfirst is dayfirst
    assert config.parse_timestamp(logfile.read_text()).month == (9 if dayfirst else 1)


# --- ignore list and types file

def test_ignore_list_skips_blank_lines_and_comments(tmp_path):
    ignore_file = tmp_path / 'ignore_list.txt'
    ignore_file.write_text('# compressed logs\n\\.gz\\Z  \n\n   \n')
    ignores = IgnoreList(str(ignore_file))
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


def test_ignore_list_combines_file_and_extensions(tmp_path):
    ignore_file = tmp_path / 'ignore_list.txt'
    ignore_file.write_text('README\n')
    ignores = IgnoreList(str(ignore_file), extensions=['.gz'])
    assert ignores.ignore_reason('/var/log/README') is not None
    assert ignores.ignore_reason('/var/log/syslog.1.gz') is not None
    assert ignores.ignore_reason('/var/log/syslog') is None


def test_known_logfile_paths_contains_listed_paths(tmp_path):
    types_file = tmp_path / 'logtypes.json'
    types_file.write_text('{"logfile_path": "/var/log/suricata/eve.json", "type": "json"}\n')
    known = KnownLogfilePaths(str(types_file))
    assert '/var/log/suricata/eve.json' in known
    assert '/var/log/syslog' not in known


def test_ignore_list_names_the_matching_pattern(tmp_path):
    ignore_file = tmp_path / 'ignore_list.txt'
    ignore_file.write_text('README\\Z\n')
    ignores = IgnoreList(str(ignore_file), extensions=['gz'])
    assert ignores.ignore_reason('/var/log/README') == f'{ignore_file} pattern README\\Z'
    assert ignores.ignore_reason('/var/log/syslog.1.gz') == 'extension .gz'
    assert ignores.ignore_reason('/var/log/syslog') is None


def test_analyzer_ignores_paths_from_ignores_file_and_extensions(tmp_path):
    ignores_file = tmp_path / 'ignore_list.txt'
    ignores_file.write_text('README\\Z\n')
    analyzer = Analyzer(types_file='', ignores_file=str(ignores_file), ignored_extensions=['.gz'])
    assert analyzer.ignores.ignore_reason('/var/log/README') is not None
    assert analyzer.ignores.ignore_reason('/var/log/syslog.1.gz') is not None
    assert analyzer.ignores.ignore_reason('/var/log/syslog') is None
