# Configuration

Logreach reads two files from the current directory and creates them empty if they are missing.
`--ignorelist-file` and `--types-file` choose other paths; `''` turns a file off.

## `ignore_list.txt`: files to skip

One regular expression per line, matched against the full path. Blank lines and lines starting
with `#` are skipped. The list only applies when `PATH` is a directory; a file named directly is
always read.

```text
# not logfiles
README\Z
wtmp\Z
# multi-line formats
apt/history\.log\Z
suricata/stats\.log\Z
```

Files with the extensions in `--ignored-extension` are skipped as well (default
`.gz,.xz,.conf,.journal,.journal~`; `''` for none).

## `logtypes.json`: set the type of a file

[JSON Lines](https://jsonlines.org/): one object per line. A file listed here is read with this
config instead of being detected. `logfile_path` must match the path exactly as logreach builds
it from `PATH`.

```json
{"logfile_path": "gather/logs/zm/web_php.log", "type": "syslog", "datetimeregex": "\\A(.+?UTC)"}
{"logfile_path": "gather/logs/nclog/audit.log", "type": "json", "datetimekey": "time"}
{"logfile_path": "gather/logs/suricata/suricata.log", "type": "syslog", "dayfirst": true}
{"logfile_path": "gather/logs/winhost/app.log", "type": "syslog", "timezone": "Europe/Vienna"}
```

| Key | Required | Meaning |
|---|---|---|
| `logfile_path` | yes | path of the logfile |
| `type` | yes | `syslog`, `audit`, `access` or `json` |
| `datetimeregex` | no | regex whose first group is the timestamp (not for `json`) |
| `datetimekey` | for `json` | key that holds the timestamp |
| `dayfirst` | no | `true` reads dates like `1/9/2026` as 1 September |
| `timezone` | no | timezone of timestamps without one in this file, e.g. `Europe/Vienna`; overrides `--timezone` |

`--type` on the command line takes precedence over this file.
