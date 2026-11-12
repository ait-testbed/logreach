from datetime import UTC, datetime
from pathlib import Path

import pytest

from logreach import FileEvent, FileStatus, Logline, Logreach
from samples import EVE_JSON, SYSLOG

TRACE = 'Sep  1 14:08:07 host app: crash\n  at Foo\n'  # line 2 has no timestamp


def linenos(items):
    """Line numbers of the lines that read() yielded."""
    return [item.lineno for item in items if isinstance(item, Logline)]


def statuses(items):
    """(file name, status) of the FileEvents that read() yielded."""
    return sorted((Path(item.path).name, item.status) for item in items if isinstance(item, FileEvent))


def test_yields_event_then_lines_in_order(make_logs):
    logs = make_logs({'syslog': TRACE})
    reader = Logreach()
    event, first, second = reader.read(logs / 'syslog')
    assert (event.status, event.message) == (FileStatus.READ, 'syslog (UTC)')
    assert (first.lineno, second.lineno) == (1, 2)
    assert (second.timestamp, second.reason) == (None, 'no timestamp')
    assert reader.problems.unparsed_lines == 1


def test_line_without_timestamp_is_in_time_window_of_line_before(make_logs):
    logs = make_logs({'syslog': 'Sep  1 13:00:00 host app: early\n  at Foo\n' + TRACE})
    assert linenos(Logreach(begin=datetime(2026, 9, 1, 14)).read(logs)) == [3, 4]


def test_grep_applies_to_lines_without_timestamp(make_logs):
    logs = make_logs({'syslog': TRACE})
    assert linenos(Logreach(grep=['foo'], ignore_case=True).read(logs)) == [2]


def test_yields_skipped_and_undetermined_files(make_logs):
    logs = make_logs({'empty.log': '', 'notes.txt': 'no timestamp\n'})
    reader = Logreach()
    assert statuses(reader.read(logs)) == [('empty.log', FileStatus.SKIPPED),
                                           ('notes.txt', FileStatus.UNDETERMINED)]
    assert reader.problems.undetermined_files == 1


def test_check_yields_only_events(make_logs):
    logs = make_logs({'syslog': SYSLOG, 'eve.json': EVE_JSON})
    assert sorted(event.message for event in Logreach().check(logs)) == ['json (timestamp, UTC)',
                                                                         'syslog (UTC)']


def test_require_timestamp_stops_the_file_and_reports_it(make_logs):
    logs = make_logs({'syslog': TRACE})
    reader = Logreach(require_timestamp=True)
    items = list(reader.read(logs / 'syslog'))
    assert linenos(items) == [1]
    assert items[-1].status == FileStatus.FAILED
    assert reader.problems.failed_files == 1


def test_fail_fast_ignores_problems_of_earlier_reads(make_logs):
    logs = make_logs({'syslog': SYSLOG, 'syslog.1': SYSLOG})
    notes = logs.parent / 'notes.txt'
    notes.write_text('no timestamp\n')
    reader = Logreach(fail_fast=True)
    list(reader.read(notes))  # undetermined: a problem
    assert len(linenos(reader.read(logs))) == 4  # both files, not only the first


def test_naive_begin_is_in_timezone():
    assert Logreach(begin=datetime(2026, 9, 1, 14)).begin == datetime(2026, 9, 1, 14, tzinfo=UTC)


def test_creates_no_files_by_default(tmp_path, monkeypatch, make_logs):
    logs = make_logs({'syslog': SYSLOG})
    monkeypatch.chdir(tmp_path)
    list(Logreach().read(logs))
    assert [path.name for path in tmp_path.iterdir()] == ['logs']


@pytest.mark.parametrize('kwargs, error', [
    ({'logtype': 'json'}, ValueError),
    ({'datetime_key': 'ts'}, ValueError),
    ({'logtype': 'syslog', 'datetime_regex': 'a('}, ValueError),
    ({'grep': ['a(']}, ValueError),
    ({'begin': '2026-09-01'}, TypeError),
])
def test_invalid_options(kwargs, error):
    with pytest.raises(error):
        Logreach(**kwargs)
