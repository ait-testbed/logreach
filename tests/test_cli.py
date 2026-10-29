from datetime import UTC, datetime

import pytest

from samples import AUDIT, EVE_JSON, SYSLOG

SYSLOG_1408 = 'Sep  1 14:08:07 host app: x\n'


# --- files and directories

def test_prints_syslog_lines(make_logs, run_logreach):
    logs = make_logs({'syslog': SYSLOG})
    printed, exit_code = run_logreach(logs)
    assert [line.lineno for line in printed] == [1, 2]
    assert exit_code == 0


def test_reads_single_file_even_if_ignored(make_logs, run_logreach):
    logs = make_logs({'syslog.1.gz': SYSLOG})  # .gz is a default ignored extension
    printed, exit_code = run_logreach(logs / 'syslog.1.gz')
    assert [line.lineno for line in printed] == [1, 2]
    assert exit_code == 0


def test_skips_ignored_files(make_logs, ignore_list, run_logreach):
    logs = make_logs({'syslog': SYSLOG, 'syslog.old': SYSLOG})  # .old is no default extension
    ignore_list('\\.old\\Z')
    printed, _ = run_logreach(logs)
    assert {line.filename for line in printed} == {str(logs / 'syslog')}


def test_skips_default_ignored_extensions(make_logs, run_logreach):
    logs = make_logs({'syslog': SYSLOG, 'syslog.1.gz': SYSLOG, 'app.conf': SYSLOG})
    printed, _ = run_logreach(logs)
    assert {line.filename for line in printed} == {str(logs / 'syslog')}


@pytest.mark.parametrize('extensions, read', [
    pytest.param('', {'syslog', 'syslog.1.gz', 'app.conf'}, id='none'),
    pytest.param('.conf', {'syslog', 'syslog.1.gz'}, id='custom'),
    pytest.param(' .conf , gz ', {'syslog'}, id='spaces-and-no-dot'),
])
def test_ignored_extension_option(make_logs, run_logreach, extensions, read):
    logs = make_logs({'syslog': SYSLOG, 'syslog.1.gz': SYSLOG, 'app.conf': SYSLOG})
    printed, _ = run_logreach(logs, '--ignored-extension', extensions)
    assert {line.filename for line in printed} == {str(logs / name) for name in read}


@pytest.mark.parametrize('extra_args', [(), ('--type', 'syslog')])
def test_skips_empty_file(make_logs, run_logreach, capsys, extra_args):
    logs = make_logs({'empty.log': ''})
    printed, exit_code = run_logreach(logs / 'empty.log', *extra_args)
    assert printed == []
    assert exit_code == 0
    assert capsys.readouterr().out == ''


def test_skips_ignored_and_empty_files_without_output(make_logs, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG, 'empty.log': '', 'syslog.1.gz': SYSLOG})
    printed, exit_code = run_logreach(logs)
    assert {line.filename for line in printed} == {str(logs / 'syslog')}
    assert exit_code == 0
    assert capsys.readouterr().out == ''


# --- choosing the log type

def test_type_applies_to_every_file_in_directory(make_logs, run_logreach):
    # a format detection cannot read, only the given regex can
    web_php = '9/1/26, 1:25:44 PM UTC.519574 web_php[1170].INF [Login successful]\n'
    logs = make_logs({'web_php.log': web_php, 'web_php.log.1': web_php})
    printed, exit_code = run_logreach(logs, '--type', 'syslog',
                                      '--datetimeregex', r'\A(.+?UTC)')
    assert {line.filename for line in printed} == {str(logs / 'web_php.log'), str(logs / 'web_php.log.1')}
    assert exit_code == 0


def test_type_overrides_types_file(make_logs, types_file, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG})
    types_file({'logfile_path': str(logs / 'syslog'), 'type': 'audit'})
    run_logreach(logs, '--type', 'syslog', '--check')
    assert capsys.readouterr().out == f'{logs / "syslog"}: syslog (UTC)\n'


def test_dayfirst_flag(make_logs, run_logreach):
    logs = make_logs({'suricata.log': '1/9/2026 -- 13:25:40 - <Info> x\n'})
    printed, _ = run_logreach(logs / 'suricata.log', '--dayfirst', '--begin', '2026-09-01',
                              '--end', '2026-09-02')
    assert [line.timestamp for line in printed] == [datetime(2026, 9, 1, 13, 25, 40, tzinfo=UTC)]


def test_dayfirst_applies_to_detected_type(make_logs, run_logreach):
    logs = make_logs({'suricata.log': '1/9/2026 -- 13:25:40 - <Info> x\n'})
    printed, _ = run_logreach(logs, '--dayfirst')
    assert [line.timestamp for line in printed] == [datetime(2026, 9, 1, 13, 25, 40, tzinfo=UTC)]


def test_require_timestamp_detects_audit(make_logs, run_logreach):
    logs = make_logs({'audit.log': AUDIT})
    printed, _ = run_logreach(logs, '--require-timestamp')
    assert len(printed) == 1


# --- timezones

def test_compares_epochs_with_begin_without_timezone(make_logs, run_logreach):
    # audit epochs carry UTC, --begin has no timezone: used to raise TypeError
    logs = make_logs({'audit.log': AUDIT})
    printed, exit_code = run_logreach(logs / 'audit.log', '--begin', '2026-09-01')
    assert len(printed) == 1
    assert exit_code == 0


def test_compares_naive_lines_with_begin_with_timezone(make_logs, run_logreach):
    logs = make_logs({'syslog': SYSLOG_1408})
    printed, _ = run_logreach(logs, '--begin', '2026-09-01T14:00+00:00')
    assert [line.timestamp for line in printed] == [datetime(2026, 9, 1, 14, 8, 7, tzinfo=UTC)]


@pytest.mark.parametrize('extra_args, printed_lines', [
    pytest.param((), 1, id='utc'),
    # 14:08:07 in Vienna (UTC+2 in September) is 12:08:07 UTC, before --begin
    pytest.param(('--timezone', 'Europe/Vienna'), 0, id='vienna'),
])
def test_timezone_option_applies_to_lines_without_timezone(make_logs, run_logreach, extra_args,
                                                           printed_lines):
    logs = make_logs({'syslog': SYSLOG_1408})
    printed, _ = run_logreach(logs, '--begin', '2026-09-01T13:00+00:00', *extra_args)
    assert len(printed) == printed_lines


def test_timezone_option_applies_to_begin_without_timezone(make_logs, run_logreach):
    # the line is in UTC (audit epoch); --begin 14:00 Vienna is 12:00 UTC
    logs = make_logs({'audit.log': 'type=X msg=audit(1788267600.0:1): x\n'})  # 13:00 UTC
    printed, _ = run_logreach(logs, '--begin', '2026-09-01 14:00',
                              '--timezone', 'Europe/Vienna')
    assert len(printed) == 1


def test_types_file_timezone_overrides_timezone_option(make_logs, types_file, run_logreach):
    logs = make_logs({'syslog': SYSLOG_1408})
    types_file({'logfile_path': str(logs / 'syslog'), 'type': 'syslog', 'timezone': 'Europe/Vienna'})
    printed, _ = run_logreach(logs, '--timezone', 'UTC')
    assert printed[0].timestamp.utcoffset().total_seconds() == 2 * 3600


# --- problems and exit codes

def test_reports_undetectable_file_at_the_end(make_logs, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG, 'binary': bytes(range(256))})
    printed, exit_code = run_logreach(logs)
    assert len(printed) == 2  # the syslog file is still printed completely
    assert exit_code == 1
    assert f'Unable to determine logtype for: {logs / "binary"}' in capsys.readouterr().err


def test_reports_lines_without_timestamp_at_the_end(make_logs, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG + '[info] no timestamp here\n'})
    printed, exit_code = run_logreach(logs)
    assert len(printed) == 2
    assert exit_code == 1
    assert f'{logs / "syslog"}:3: no timestamp: [info] no timestamp here' in capsys.readouterr().err


def test_reports_problems_of_single_file(make_logs, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG + 'no timestamp\n'})
    printed, exit_code = run_logreach(logs / 'syslog')
    assert len(printed) == 2
    assert exit_code == 1
    assert f'{logs / "syslog"}:3: no timestamp: no timestamp' in capsys.readouterr().err


def test_error_in_one_file_does_not_stop_the_run(make_logs, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG,
                      'app.json': '{"time": "2026-09-01T13:25:40"}\n{"msg": "no time"}\n'})
    printed, exit_code = run_logreach(logs)
    assert [line.filename for line in printed].count(str(logs / 'syslog')) == 2
    assert exit_code == 1
    err = capsys.readouterr().err
    assert f'{logs / "app.json"}: Unable to find timestamp-key "time"' in err
    assert '1 files with errors' in err


def test_unreadable_file_is_reported(make_logs, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG})
    (logs / 'syslog').chmod(0)
    try:
        _, exit_code = run_logreach(logs / 'syslog', '--type', 'syslog')
    finally:
        (logs / 'syslog').chmod(0o644)
    assert exit_code == 1
    assert 'Permission denied' in capsys.readouterr().err


def test_unknown_timezone_in_types_file_is_reported(make_logs, types_file, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG_1408})
    types_file({'logfile_path': str(logs / 'syslog'), 'type': 'syslog', 'timezone': 'Mars/Olympus'})
    printed, exit_code = run_logreach(logs)
    assert printed == []
    assert exit_code == 1
    assert 'Unknown timezone in' in capsys.readouterr().err


def test_require_timestamp_stops_at_first_line_without_timestamp(make_logs, run_logreach, capsys):
    lines = SYSLOG.splitlines(keepends=True)
    logs = make_logs({'syslog': lines[0] + 'no timestamp\n' + lines[1]})
    printed, exit_code = run_logreach(logs, '--require-timestamp')
    assert [line.lineno for line in printed] == [1]
    assert exit_code == 1
    assert f'{logs / "syslog"}: Timestamp not found in line 2' in capsys.readouterr().err


def test_lists_only_max_problems_and_counts_the_rest(make_logs, run_logreach, capsys):
    logs = make_logs({f'notes{i}.txt': 'no timestamp\n' for i in range(3)})
    _, exit_code = run_logreach(logs, '--max-problems', '1')
    err = capsys.readouterr().err
    assert exit_code == 1
    assert err.count('Unable to determine logtype') == 1
    assert '... and 2 more (see --max-problems)' in err
    assert '0 lines without timestamp, 3 undetermined files' in err


def test_fail_fast_stops_at_first_undetermined_file(make_logs, run_logreach, capsys):
    logs = make_logs({f'notes{i}.txt': 'no timestamp\n' for i in range(3)})
    _, exit_code = run_logreach(logs, '--fail-fast')
    assert exit_code == 1
    assert capsys.readouterr().err.count('Unable to determine logtype') == 1


def test_fail_fast_stops_within_a_file(make_logs, run_logreach, capsys):
    lines = SYSLOG.splitlines(keepends=True)
    logs = make_logs({'syslog': lines[0] + 'no timestamp\n' + lines[1]})
    printed, exit_code = run_logreach(logs, '--fail-fast')
    assert [line.lineno for line in printed] == [1]  # line 3 is never printed
    assert exit_code == 1
    assert ':2: no timestamp: no timestamp' in capsys.readouterr().err


# --- --check

def test_check_shows_types_instead_of_lines(make_logs, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG, 'eve.json': EVE_JSON})
    printed, exit_code = run_logreach(logs, '--check')
    assert printed == []
    assert exit_code == 0
    assert sorted(capsys.readouterr().out.splitlines()) == [
        f'{logs / "eve.json"}: json (timestamp, UTC)',
        f'{logs / "syslog"}: syslog (UTC)',
    ]


def test_check_shows_timezone_of_each_file(make_logs, types_file, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG_1408, 'local.log': SYSLOG_1408})
    types_file({'logfile_path': str(logs / 'local.log'), 'type': 'syslog', 'timezone': 'Europe/Vienna'})
    run_logreach(logs, '--check', '--timezone', 'America/New_York')
    assert sorted(capsys.readouterr().out.splitlines()) == [
        f'{logs / "local.log"}: syslog (Europe/Vienna)',
        f'{logs / "syslog"}: syslog (America/New_York)',
    ]


def test_check_shows_why_files_are_skipped(make_logs, ignore_list, run_logreach, capsys):
    logs = make_logs({'syslog': SYSLOG, 'empty.log': '', 'syslog.1.gz': SYSLOG, 'README': 'x\n'})
    ignores = ignore_list('README\\Z')
    printed, exit_code = run_logreach(logs, '--check')
    assert printed == []
    assert exit_code == 0  # skipped files are no problems
    assert sorted(capsys.readouterr().out.splitlines()) == sorted([
        f'{logs / "README"}: skipped (ignored: {ignores} pattern README\\Z)',
        f'{logs / "empty.log"}: skipped (empty)',
        f'{logs / "syslog"}: syslog (UTC)',
        f'{logs / "syslog.1.gz"}: skipped (ignored: extension .gz)',
    ])


# --- usage errors

def test_missing_path_is_a_usage_error(run_logreach, tmp_path, capsys):
    _, exit_code = run_logreach(tmp_path / 'missing')
    assert exit_code == 2
    assert 'missing does not exist' in capsys.readouterr().err


@pytest.mark.parametrize('option', ['--datetimekey', '--datetimeregex'])
def test_type_options_require_type(run_logreach, tmp_path, capsys, option):
    _, exit_code = run_logreach(tmp_path, option, 'x')
    assert exit_code == 2
    assert '--datetimekey and --datetimeregex require --type' in capsys.readouterr().err


def test_json_without_datetimekey_is_a_usage_error(run_logreach, tmp_path, capsys):
    _, exit_code = run_logreach(tmp_path / 'app.json', '--type', 'json')
    assert exit_code == 2
    assert '--type json requires --datetimekey' in capsys.readouterr().err


def test_unknown_timezone_is_a_usage_error(run_logreach, tmp_path, capsys):
    _, exit_code = run_logreach(tmp_path, '--timezone', 'Mars/Olympus')
    assert exit_code == 2
    assert 'unknown timezone: Mars/Olympus' in capsys.readouterr().err
