import json
import sys
from datetime import datetime

import pytest

import logreach.__cli__ as cli
from logreach.schemas.logline import Logline

SYSLOG = ('Sep  1 14:08:07 videoserver systemd[1]: Started Session 16 of user superuser.\n'
          'Sep  1 14:09:00 videoserver systemd[1]: Started Session 17 of user superuser.\n')
AUDIT = 'type=DAEMON_START msg=audit(1788266693.261:9117): op=start ver=3.0.9 res=success\n'
EVE_JSON = '{"timestamp": "2026-09-01T14:09:21.639533+0000", "event_type": "alert"}\n'


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


def run_logreach(monkeypatch, tmp_path, path, *extra_args: str) -> tuple[list[Logline], int]:
    """Run the logreach CLI on path (file or directory) and return the lines it
    would print and its exit code."""
    printed: list[Logline] = []
    monkeypatch.setattr(cli, 'format_logline', printed.append)
    monkeypatch.setattr(sys, 'argv', [
        'logreach', str(path),
        '--ignorelist-file', str(tmp_path / 'ignore_list.txt'),
        '--types-file', str(tmp_path / 'logtypes.json'),
        *extra_args])
    try:
        cli.main()
    except SystemExit as e:
        return printed, e.code
    return printed, 0


# --- directories

def test_logreach_prints_syslog_lines(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'syslog': SYSLOG})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs)
    assert [line.lineno for line in printed] == [1, 2]
    assert exit_code == 0


def test_logreach_reports_undetectable_file_at_the_end(monkeypatch, tmp_path, capsys):
    logs = make_logs(tmp_path, {'syslog': SYSLOG, 'binary': bytes(range(256))})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs)
    assert len(printed) == 2  # the syslog file is still printed completely
    assert exit_code == 1
    assert f'Unable to determine logtype for: {logs / "binary"}' in capsys.readouterr().err


def test_logreach_reports_lines_without_timestamp_at_the_end(monkeypatch, tmp_path, capsys):
    logs = make_logs(tmp_path, {'syslog': SYSLOG + '[info] no timestamp here\n'})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs)
    assert len(printed) == 2
    assert exit_code == 1
    assert f'{logs / "syslog"}:3: no timestamp: [info] no timestamp here' in capsys.readouterr().err


def test_logreach_skips_ignored_files(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'syslog': SYSLOG, 'syslog.old': SYSLOG})  # .old is no default extension
    (tmp_path / 'ignore_list.txt').write_text('\\.old\\Z\n')
    printed, _ = run_logreach(monkeypatch, tmp_path, logs)
    assert {line.filename for line in printed} == {str(logs / 'syslog')}


def test_logreach_skips_default_ignored_extensions(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'syslog': SYSLOG, 'syslog.1.gz': SYSLOG, 'app.conf': SYSLOG})
    printed, _ = run_logreach(monkeypatch, tmp_path, logs)
    assert {line.filename for line in printed} == {str(logs / 'syslog')}


@pytest.mark.parametrize('extensions, read', [
    pytest.param('', {'syslog', 'syslog.1.gz', 'app.conf'}, id='none'),
    pytest.param('.conf', {'syslog', 'syslog.1.gz'}, id='custom'),
    pytest.param(' .conf , gz ', {'syslog'}, id='spaces-and-no-dot'),
])
def test_logreach_ignored_extension_option(monkeypatch, tmp_path, extensions, read):
    logs = make_logs(tmp_path, {'syslog': SYSLOG, 'syslog.1.gz': SYSLOG, 'app.conf': SYSLOG})
    printed, _ = run_logreach(monkeypatch, tmp_path, logs, '--ignored-extension', extensions)
    assert {line.filename for line in printed} == {str(logs / name) for name in read}


def test_logreach_require_timestamp_detects_audit(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'audit.log': AUDIT})
    printed, _ = run_logreach(monkeypatch, tmp_path, logs, '--require-timestamp')
    assert len(printed) == 1


def test_logreach_require_timestamp_stops_at_first_line_without_timestamp(monkeypatch, tmp_path, capsys):
    lines = SYSLOG.splitlines(keepends=True)
    logs = make_logs(tmp_path, {'syslog': lines[0] + 'no timestamp\n' + lines[1]})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs, '--require-timestamp')
    assert [line.lineno for line in printed] == [1]
    assert exit_code == 1
    assert f'{logs / "syslog"}: Timestamp not found in line 2' in capsys.readouterr().err


def test_logreach_lists_only_max_problems_and_counts_the_rest(monkeypatch, tmp_path, capsys):
    logs = make_logs(tmp_path, {f'notes{i}.txt': 'no timestamp\n' for i in range(3)})
    _, exit_code = run_logreach(monkeypatch, tmp_path, logs, '--max-problems', '1')
    err = capsys.readouterr().err
    assert exit_code == 1
    assert err.count('Unable to determine logtype') == 1
    assert '... and 2 more (see --max-problems)' in err
    assert '0 lines without timestamp, 3 undetermined files' in err


def test_logreach_fail_fast_stops_at_first_undetermined_file(monkeypatch, tmp_path, capsys):
    logs = make_logs(tmp_path, {f'notes{i}.txt': 'no timestamp\n' for i in range(3)})
    _, exit_code = run_logreach(monkeypatch, tmp_path, logs, '--fail-fast')
    assert exit_code == 1
    assert capsys.readouterr().err.count('Unable to determine logtype') == 1


def test_logreach_fail_fast_stops_within_a_file(monkeypatch, tmp_path, capsys):
    lines = SYSLOG.splitlines(keepends=True)
    logs = make_logs(tmp_path, {'syslog': lines[0] + 'no timestamp\n' + lines[1]})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs, '--fail-fast')
    assert [line.lineno for line in printed] == [1]  # line 3 is never printed
    assert exit_code == 1
    assert ':2: no timestamp: no timestamp' in capsys.readouterr().err


def test_logreach_check_shows_types_instead_of_lines(monkeypatch, tmp_path, capsys):
    logs = make_logs(tmp_path, {'syslog': SYSLOG, 'eve.json': EVE_JSON})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs, '--check')
    assert printed == []
    assert exit_code == 0
    assert sorted(capsys.readouterr().out.splitlines()) == [
        f'{logs / "eve.json"}: json (timestamp)',
        f'{logs / "syslog"}: syslog',
    ]


# --- single files

def test_logreach_reads_single_file_even_if_ignored(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'syslog.1.gz': SYSLOG})  # .gz is a default ignored extension
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs / 'syslog.1.gz')
    assert [line.lineno for line in printed] == [1, 2]
    assert exit_code == 0


def test_logreach_reports_problems_of_single_file(monkeypatch, tmp_path, capsys):
    logs = make_logs(tmp_path, {'syslog': SYSLOG + 'no timestamp\n'})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs / 'syslog')
    assert len(printed) == 2
    assert exit_code == 1
    assert f'{logs / "syslog"}:3: no timestamp: no timestamp' in capsys.readouterr().err


@pytest.mark.parametrize('extra_args', [(), ('--type', 'syslog')])
def test_logreach_skips_empty_file_silently(monkeypatch, tmp_path, capsys, extra_args):
    logs = make_logs(tmp_path, {'empty.log': ''})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs / 'empty.log', '--check', *extra_args)
    assert printed == []
    assert exit_code == 0
    assert capsys.readouterr().out == ''


def test_logreach_missing_path_is_a_usage_error(monkeypatch, tmp_path, capsys):
    _, exit_code = run_logreach(monkeypatch, tmp_path, tmp_path / 'missing')
    assert exit_code == 2
    assert 'missing does not exist' in capsys.readouterr().err


# --- --type and its options

def test_logreach_type_applies_to_every_file_in_directory(monkeypatch, tmp_path):
    # a format detection cannot read, only the given regex can
    web_php = '9/1/26, 1:25:44 PM UTC.519574 web_php[1170].INF [Login successful]\n'
    logs = make_logs(tmp_path, {'web_php.log': web_php, 'web_php.log.1': web_php})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs, '--type', 'syslog',
                                      '--datetimeregex', r'\A(.+?UTC)')
    assert {line.filename for line in printed} == {str(logs / 'web_php.log'), str(logs / 'web_php.log.1')}
    assert exit_code == 0


def test_logreach_type_overrides_types_file(monkeypatch, tmp_path, capsys):
    logs = make_logs(tmp_path, {'syslog': SYSLOG})
    entry = {'logfile_path': str(logs / 'syslog'), 'type': 'audit'}
    (tmp_path / 'logtypes.json').write_text(json.dumps(entry) + '\n')
    run_logreach(monkeypatch, tmp_path, logs, '--type', 'syslog', '--check')
    assert capsys.readouterr().out == f'{logs / "syslog"}: syslog\n'


@pytest.mark.parametrize('option', ['--datetimekey', '--datetimeregex'])
def test_logreach_type_options_require_type(monkeypatch, tmp_path, capsys, option):
    _, exit_code = run_logreach(monkeypatch, tmp_path, tmp_path, option, 'x')
    assert exit_code == 2
    assert '--datetimekey and --datetimeregex require --type' in capsys.readouterr().err


def test_logreach_dayfirst_applies_to_detected_type(monkeypatch, tmp_path):
    logs = make_logs(tmp_path, {'suricata.log': '1/9/2026 -- 13:25:40 - <Info> x\n'})
    printed, _ = run_logreach(monkeypatch, tmp_path, logs, '--dayfirst')
    assert [line.timestamp for line in printed] == [datetime(2026, 9, 1, 13, 25, 40)]


# --- errors while reading a file

def test_logreach_error_in_one_file_does_not_stop_the_run(monkeypatch, tmp_path, capsys):
    logs = make_logs(tmp_path, {'syslog': SYSLOG,
                                'app.json': '{"time": "2026-09-01T13:25:40"}\n{"msg": "no time"}\n'})
    printed, exit_code = run_logreach(monkeypatch, tmp_path, logs)
    assert [line.filename for line in printed].count(str(logs / 'syslog')) == 2
    assert exit_code == 1
    err = capsys.readouterr().err
    assert f'{logs / "app.json"}: Unable to find timestamp-key "time"' in err
    assert '1 files with errors' in err


def test_logreach_unreadable_file_is_reported(monkeypatch, tmp_path, capsys):
    logs = make_logs(tmp_path, {'syslog': SYSLOG})
    (logs / 'syslog').chmod(0)
    try:
        _, exit_code = run_logreach(monkeypatch, tmp_path, logs / 'syslog', '--type', 'syslog')
    finally:
        (logs / 'syslog').chmod(0o644)
    assert exit_code == 1
    assert 'Permission denied' in capsys.readouterr().err


def test_logreach_dayfirst_flag(monkeypatch, tmp_path):
    logfile = tmp_path / 'suricata.log'
    logfile.write_text('1/9/2026 -- 13:25:40 - <Info> x\n')
    printed: list[Logline] = []
    monkeypatch.setattr(cli, 'format_logline', printed.append)
    monkeypatch.setattr(sys, 'argv', ['logreach', str(logfile), '--dayfirst',
                                      '--begin', '2026-09-01', '--end', '2026-09-02'])
    cli.main()
    assert [line.timestamp for line in printed] == [datetime(2026, 9, 1, 13, 25, 40)]


def test_logreach_json_without_datetimekey_is_a_usage_error(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, 'argv', ['logreach', '--type', 'json', str(tmp_path / 'app.json')])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == 2
    assert '--type json requires --datetimekey' in capsys.readouterr().err
