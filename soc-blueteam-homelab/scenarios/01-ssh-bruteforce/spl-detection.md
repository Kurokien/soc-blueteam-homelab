# SPL Detection — SSH Brute-Force (Linux Victim)

Index: `linuxlogs` | Sourcetype: `linux_secure` | Source: `/var/log/auth.log`

---

## 1. Raw event confirmation

```spl
index="linuxlogs" "Failed password"
```

Sample raw event:

```
2026-07-15T09:11:17.213802+00:00 Linux-victim sshd[11374]: Failed password for khoa from 192.168.54.40 port 56142 ssh2
```

## 2. Detection query — brute-force burst correlation

Extracts the target user and source IP from the raw event, bins events into 1-minute windows, and flags any window with more than 5 failed attempts (a threshold chosen to separate normal typo-level failures from automated brute-forcing).

```spl
index="linuxlogs" "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| bin _time span=1m
| stats count as failed_attempts by src_ip, user, _time
| where failed_attempts > 5
| sort - failed_attempts
```

**Result (24h window, 1,143 total `Failed password` events):**

| src_ip | user | _time (1-min bin) | failed_attempts |
|---|---|---|---|
| 192.168.54.40 | khoa | 2026-07-15 08:50:00 | 286 |
| 192.168.54.40 | khoa | 2026-07-15 09:10:00 | 234 |
| 192.168.54.40 | khoa | 2026-07-15 08:38:00 | 191 |
| 192.168.54.40 | khoa | 2026-07-15 08:49:00 | 168 |
| 192.168.54.40 | khoa | 2026-07-15 08:51:00 | 91 |

## 3. Breach verification query

Critical follow-up step: confirm no successful login occurred from the same source during the attack window, rather than assuming failure based on absence of contrary evidence.

```spl
index="linuxlogs" "Accepted password"
```

**Result:** `0 events` — confirms no successful SSH login from `192.168.54.40` occurred.

## 4. Alert configuration

| Setting | Value |
|---|---|
| Alert type | Real-time |
| Trigger condition | Per-Result |
| Severity | Medium |
| Action | Add to Triggered Alerts |

> **Lesson learned:** Real-time + Per-Result generates one alert per matching row, which produced dozens of Triggered Alerts entries within a single one-minute burst. For the RDP scenario this was corrected to a Scheduled alert with `Number of Results > 0` — see [`../02-rdp-bruteforce/spl-detection.md`](../02-rdp-bruteforce/spl-detection.md).

## 5. Dashboard panels

Panels built on top of the queries above (see `screenshots/01-dashboard.png`):
1. Top attacking source IPs (Column Chart)
2. Failed attempts over time (Line Chart)
3. Targeted usernames (Pie Chart)
4. Raw failed-login events table
