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

# only the lines in the window that match any of the regexes (--ignore-case for any case)
logreach gather/logs --begin '2026-09-01 14:00' --grep 'password' --grep 'sudo:.*'

# only show the detected type of each file and the problems found
logreach gather/logs --check

# also ask for the type of each file that is not detected, and save the answers
logreach gather/logs --check --interactive

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

## Timezones

Timestamps without a timezone (classic syslog like `Sep  1 13:25:26`, and `--begin`/`--end` like
`2026-09-01 14:00`) are taken as UTC. Timestamps that have one, like audit epochs or
`2026-09-01T14:09:21+02:00`, keep it, so files in different timezones are compared correctly.

```bash
# logs and --begin / --end without timezone are Vienna time
logreach gather/logs --begin '2026-09-01 14:00' --timezone Europe/Vienna
```

A single file or host that logs in another timezone gets a `"timezone"` in
[`logtypes.json`](configuration.md), which overrides `--timezone` for that file.

`--check` shows the timezone each file is read in, so a wrong assumption shows up early:

```text
gather/logs/inetfw/kern.log: syslog (UTC)
gather/logs/winhost/app.log: syslog (Europe/Vienna)
gather/logs/inetfw/suricata/eve.json: json (timestamp, UTC)
```

The timezone only matters for timestamps without one; `eve.json` stamps like
`2026-09-01T13:25:36+0000` keep their own.

## Checking a directory: `--check`

`--check` reads every file and reports the same problems, but prints one line per file instead of
the log lines: the detected type and timezone, or why the file was skipped.

```text
gather/logs/inetfw/kern.log: syslog (UTC)
gather/logs/inetfw/suricata/eve.json: json (timestamp, UTC)
gather/logs/inetfw/wtmp: skipped (ignored: ignore_list.txt pattern /wtmp\Z)
gather/logs/inetfw/syslog.1.gz: skipped (ignored: extension .gz)
gather/logs/docker/empty.log: skipped (empty)
```

Skipped files are no problems. Without `--check` they are skipped without output.

## Teaching logreach new files: `--check --interactive`

Run this first on a new directory. For every file whose type is not detected, `--interactive`
(`-i`) shows its first lines and asks what to do with it:

* `skip` leaves it undetermined, so it is reported as a problem 
* `ignore` adds the file's path to [`ignore_list.txt`](configuration.md).
* `edit` asks for the log type and what it needs:
    * `syslog`, `audit`, `access`: Enter keeps the type's default regex; a custom regex needs a
      group `(...)` around the timestamp.
    * `json`: pick the key of the timestamp from the keys of the first line.
    * If the timestamps have no timezone, you are asked for one; 

Before saving, logreach shows the first parsed timestamps. If the answer reads no timestamp, or
you answer `n`, it asks again whether to edit, ignore or skip the file. Saved answers go into
[`logtypes.json`](configuration.md) with the path exactly as shown. To change an answer, edit or delete its line in
`logtypes.json`; `dayfirst` can be added this way if necessary.

`--interactive` only works together with `--check` and in a terminal; (Ctrl-D) skips the remaining questions.

## Problems and exit codes

Logreach does not stop at a problem. It lists them on stderr at the end of the run:

* files where no type fits
* lines without a timestamp, including JSON lines that are not valid JSON (e.g. cut off mid-write)
* errors while reading a file, e.g. a JSON line without the timestamp key

`--max-problems` limits how many are listed, `--fail-fast` stops at the first one, and
`--require-timestamp` treats a line without a timestamp as an error.

| Exit code | Meaning |
|---|---|
| 0 | no problems |
| 1 | problems found |
| 2 | usage error, e.g. `PATH` does not exist or `--type json` without `--datetimekey` |
