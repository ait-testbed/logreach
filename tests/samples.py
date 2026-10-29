"""Sample log lines shared by the tests."""

SYSLOG = ('Sep  1 14:08:07 videoserver systemd[1]: Started Session 16 of user superuser.\n'
          'Sep  1 14:09:00 videoserver systemd[1]: Started Session 17 of user superuser.\n')
AUDIT = 'type=DAEMON_START msg=audit(1788266693.261:9117): op=start ver=3.0.9 res=success\n'
ACCESS = '127.0.0.1 - - [01/Sep/2026:14:08:07 +0000] "GET / HTTP/1.1" 200 512\n'
# spaces after the separators: the loose syslog regex used to claim this line
JSON_TIME = '{"time": "2026-09-01T14:09:21+00:00", "msg": "session started"}\n'
EVE_JSON = '{"timestamp": "2026-09-01T14:09:21.639533+0000", "event_type": "alert"}\n'
