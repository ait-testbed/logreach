import json
import sys

import pytest

import logtype.__cli__ as cli
from logreach.schemas.logfileconfig import JsonLogConfig, LogConfig, RegexLogConfig, TimestampRegex
from logreach.schemas.logline import Logline
from logtype.analyzer import Analyzer, IgnoreList, KnownLogfilePaths
from logtype.exceptions import IgnoredFile, LogFileEmpty, LogTypeError

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


def make_logs(tmp_path, files: dict[str, str | bytes]):
    """Create tmp_path/logs containing files (name -> content)."""
    logs = tmp_path / 'logs'
    logs.mkdir()
    for name, content in files.items():
        if isinstance(content, bytes):
            (logs / name).write_bytes(content)
        else:
            (logs / name).write_text(content)
    return logs


def run_logtype(monkeypatch, tmp_path, logs_dir, *extra_args: str) -> list[Logline]:
    """Run the logtype CLI on logs_dir and return the lines it would print."""
    printed: list[Logline] = []
    monkeypatch.setattr(cli, 'format_logline', printed.append)
    monkeypatch.setattr(sys, 'argv', [
        'logtype', '--path', str(logs_dir),
        '--ignorelist-file', str(tmp_path / 'ignore_list.txt'),
        '--types-file', str(tmp_path / 'logtypes.json'),
        *extra_args])
    cli.main()
    return printed


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
    with pytest.raises(LogFileEmpty):
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


# --- ignore list and types file

def test_ignore_list_skips_blank_lines_and_comments(tmp_path):
    ignore_file = tmp_path / 'ignore_list.txt'
    ignore_file.write_text('# compressed logs\n\\.gz\\Z  \n\n   \n')
    ignores = IgnoreList(str(ignore_file))
    assert [pattern.pattern for pattern in ignores.patterns] == ['\\.gz\\Z']
    assert ignores.is_ignored('/var/log/syslog.1.gz')
    assert not ignores.is_ignored('/var/log/syslog')


def test_known_logfile_paths_contains_listed_paths(tmp_path):
    types_file = tmp_path / 'logtypes.json'
    types_file.write_text('{"logfile_path": "/var/log/suricata/eve.json", "type": "json"}\n')
    known = KnownLogfilePaths(str(types_file))
    assert '/var/log/suricata/eve.json' in known
    assert '/var/log/syslog' not in known


def test_check_not_skipped_raises_for_ignored_paths(tmp_path):
    ignores_file = tmp_path / 'ignore_list.txt'
    ignores_file.write_text('\\.gz\\Z\n')
    analyzer = Analyzer(types_file='', ignores_file=str(ignores_file))
    with pytest.raises(IgnoredFile):
        analyzer.check_not_skipped('/var/log/syslog.1.gz')
    analyzer.check_not_skipped('/var/log/syslog')


# --- logtype CLI

def test_logtype_prints_syslog_lines(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'syslog': SYSLOG})
    printed = run_logtype(monkeypatch, tmp_path, logs)
    assert [line.lineno for line in printed] == [1, 2]


def test_logtype_skips_undetectable_file(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'syslog': SYSLOG, 'binary': bytes(range(256))})
    printed = run_logtype(monkeypatch, tmp_path, logs)
    assert len(printed) == 2  # only the syslog lines, and the run did not abort


def test_logtype_skips_ignored_files(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'syslog': SYSLOG, 'syslog.1.gz': SYSLOG})
    (tmp_path / 'ignore_list.txt').write_text('\\.gz\\Z\n')
    printed = run_logtype(monkeypatch, tmp_path, logs)
    assert {line.filename for line in printed} == {str(logs / 'syslog')}


def test_logtype_force_timestamp_detects_audit(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'audit.log': AUDIT})
    printed = run_logtype(monkeypatch, tmp_path, logs, '--force-timestamp')
    assert len(printed) == 1
