# Python API

Everything the `logreach` command does from Python code.

## Read lines

```python
from datetime import datetime
from zoneinfo import ZoneInfo

from logreach import FileEvent, Logreach

reader = Logreach(begin=datetime(2026, 9, 1, 14), end=datetime(2026, 9, 1, 15),
                  timezone=ZoneInfo('Europe/Vienna'))

for item in reader.read('/var/log'):  # a file or a directory
    if isinstance(item, FileEvent):
        continue  # a new file starts, see below
    if item.timestamp is None:
        print('no timestamp:', item.reason, item.raw)
    else:
        print(item.timestamp, item.filename, item.lineno, item.raw)
```

`read()` yields, file by file, a `FileEvent` and then the file's lines in order, as they are read.
Each line is a `Logline` with `timestamp`, `raw`, `lineno`, `filename` and `reason`.

Lines without timestamp are yielded too (`timestamp` is `None`, `reason` says why). They belong to the
line with timestamp before them, e.g. a stack trace, and are in the time window if that line is.

## File events

```python
from logreach import FileEvent, FileStatus

for item in reader.read('/var/log'):
    if isinstance(item, FileEvent) and item.status != FileStatus.READ:
        print(item.path, item.status.value, item.message)
```

| `status`       | `message`                                |
|----------------|------------------------------------------|
| `READ`         | how it is read, e.g. `syslog (UTC)`; its lines follow |
| `SKIPPED`      | why: ignored or empty                    |
| `UNDETERMINED` | no log type fits                         |
| `FAILED`       | the error that stopped reading the file  |

`reader.check(path)` yields only the events, e.g. to see the detected type of each file.

## Problems

Problems never stop a run; they are collected in `reader.problems`:

```python
reader.problems.messages            # e.g. '/var/log/app.log:3: no timestamp: ...'
reader.problems.unparsed_lines      # counts
reader.problems.undetermined_files
reader.problems.failed_files
```

Each `read()` (and `check()`) starts with empty problems.

## Options

All are keyword arguments of `Logreach(...)`:

| Option | Meaning |
|---|---|
| `begin`, `end` | `datetime`s of the time window; without timezone they are in `timezone` |
| `timezone` | timezone of timestamps without one (default UTC) |
| `grep`, `ignore_case` | only lines matching one of these regexes |
| `logtype` | `'syslog'`, `'audit'`, `'access'` or `'json'` instead of detecting the type |
| `datetime_key` | timestamp key, required for `logtype='json'` |
| `datetime_regex` | regex whose first group is the timestamp, for the other types |
| `dayfirst` | read 1/9/2026 as 1 September |
| `require_timestamp` | a line without timestamp stops its file (`FAILED`) |
| `fail_fast` | stop at the first problem |
| `types_file`, `ignores_file` | the [configuration files](configuration.md); default `None`: none are read or created |
| `ignored_extensions` | e.g. `['.gz']`: files in directories with these endings are skipped |

Invalid options raise `ValueError` (or `TypeError` for `begin`/`end` that are no `datetime`).

## Examples

Errors of the last hour, from a JSON log:

```python
from datetime import UTC, datetime, timedelta

reader = Logreach(logtype='json', datetime_key='ts', grep=['error'], ignore_case=True,
                  begin=datetime.now(UTC) - timedelta(hours=1))
errors = [line for line in reader.read('app.json') if not isinstance(line, FileEvent)]
```

Detected type of every file, with the types file of the command:

```python
for event in Logreach(types_file='logtypes.json').check('/var/log'):
    print(event.path, event.status.value, event.message)
```

`read()` is a generator: iterate over it instead of `list()` to keep memory low on large logs.
