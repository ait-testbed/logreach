# Usage

```bash
logreach PATH [--type ...] [--begin ...] [--end ...] [--check] ...
```

`PATH` is a logfile or a directory, which is walked recursively. With `uv`, prefix the commands
with `uv run`. `logreach --help` lists all options.

## Examples

```bash
# all lines of one logfile, type detected automatically
logreach /var/log/syslog

# only the lines between two timestamps
logreach /var/log/syslog --begin '2026-09-01 14:00' --end '2026-09-01 15:00'

# every logfile below a directory
logreach gather/logs --begin '2026-09-01 14:00' --end '2026-09-01 15:00'

# only show the detected type of each file and the problems found
logreach gather/logs --check

# set the type instead of detecting it
logreach audit.log --type audit
logreach app.json --type json --datetimekey time
logreach web_php.log --type syslog --datetimeregex '\A(.+?UTC)'

# read dates like 1/9/2026 as 1 September
logreach suricata.log --dayfirst
```

## How the type is chosen

For each file, the first source that applies wins:

1. `--type` (with `--datetimekey`, `--datetimeregex` as needed), applied to every file
2. the file's entry in [`logtypes.json`](configuration.md)
3. detection: json, audit, access and syslog are tried in this order; the first under which a line
   has a timestamp wins

Timestamps without a year (e.g. `Sep  1 13:25:26`) take the year of `--begin`, else `--end`.

## Problems and exit codes

Logreach does not stop at a problem. It lists them on stderr at the end of the run:

* files where no type fits
* lines without a timestamp
* errors while reading a file, e.g. a JSON line without the timestamp key

`--max-problems` limits how many are listed, `--fail-fast` stops at the first one, and
`--require-timestamp` treats a line without a timestamp as an error.

| Exit code | Meaning |
|---|---|
| 0 | no problems |
| 1 | problems found |
| 2 | usage error, e.g. `PATH` does not exist or `--type json` without `--datetimekey` |
