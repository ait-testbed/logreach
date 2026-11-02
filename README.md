# Logreach

Reach into collected log dumps: `logreach` detects the type of each logfile (syslog, audit,
access or JSON) and prints the lines within a time window.

> [!IMPORTANT]
> Logreach is an early proof of concept and under development.

## Installation

Requires Python >= 3.14.

```bash
git clone https://github.com/ait-testbed/logreach.git
cd logreach
uv sync
```

With `uv`, prefix the commands below with `uv run`.

## Usage

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

# stop at the first problem instead of listing all problems at the end
logreach gather/logs --check --fail-fast

# set the type instead of detecting it
logreach audit.log --type audit
logreach app.json --type json --datetimekey time
logreach web_php.log --type syslog --datetimeregex '\A(.+?UTC)'

# read dates like 1/9/2026 as 1 September
logreach suricata.log --dayfirst

# timestamps without timezone (in the logs and in --begin/--end) are Vienna time, not UTC
logreach gather/logs --begin '2026-09-01 14:00' --timezone Europe/Vienna
```

Files where no type fits and lines without a timestamp are listed on stderr at the end of the
run (exit code 1). See `logreach --help` for all options and the
[documentation](https://ait-testbed.github.io/logreach/) for details.

### Configuration files

Both are read from the current directory and created empty if missing:

- `ignore_list.txt`: one regex per line; matching paths are skipped when reading a directory.
- `logtypes.json`: one JSON object per line that sets the type of a file instead of detecting it:

  ```json
  {"logfile_path": "gather/logs/zm/web_php.log", "type": "syslog", "datetimeregex": "\\A(.+?UTC)"}
  {"logfile_path": "gather/logs/suricata/suricata.log", "type": "syslog", "dayfirst": true}
  ```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security
see [SECURITY.md](SECURITY.md).

## License

[EUPL-1.2](LICENSE.md)
