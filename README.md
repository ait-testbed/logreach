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
uv run logreach --help
```

## Usage

```bash
# all lines of one logfile, type detected automatically
uv run logreach /var/log/syslog

# only the lines between two timestamps
uv run logreach /var/log/syslog --begin '2026-09-01 14:00' --end '2026-09-01 15:00'

# every logfile below a directory
uv run logreach gather/logs --begin '2026-09-01 14:00' --end '2026-09-01 15:00'

# only show the detected type of each file and the problems found
uv run logreach gather/logs --check

# also ask for the type of each file that is not detected, and save the answers in logtypes.json
uv run logreach gather/logs --check --interactive
```

Files where no type fits and lines without a timestamp are listed on stderr at the end of the
run (exit code 1). See `logreach --help` for all options and the
[documentation](https://ait-testbed.github.io/logreach/) for more examples.

### Configuration files

Both are read from the current directory and created empty if missing:

- `ignore_list.txt`: one regex per line; matching paths are skipped when reading a directory.
- `logtypes.json`: one JSON object per line that sets the type of a file instead of detecting it
  (`--check --interactive` writes it for you):

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
