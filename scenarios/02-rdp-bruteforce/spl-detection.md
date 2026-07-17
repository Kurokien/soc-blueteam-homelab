# SPL Detection — RDP Brute-Force (Windows Victim)

Index: `wineventlog` | Source: Windows Security Event Log (`WinEventLog://Security`)

---

## 1. Raw event confirmation

```spl
index=wineventlog EventCode=4625
| table _time, host, Account_Name, Source_Network_Address, Logon_Type
```

`EventCode=4625` = "An account failed to log on".

## 2. A field pitfall: multivalue `Account_Name`

Windows Event 4625 XML contains both `SubjectUserName` (almost always `-` for a failed remote logon) and `TargetUserName` (the account actually being tested). Splunk's default field extraction merges both into a single multivalue field `Account_Name`, which silently doubles `stats count` results if not handled:

```spl
index=wineventlog EventCode=4625
| stats count by Account_Name        " ⚠ double-counts: one row for "-", one row for "khoa"
```

**Fix — extract the correct value with `mvindex`:**

```spl
index=wineventlog EventCode=4625
| eval target_user=mvindex(Account_Name, -1)
```

## 3. Detection query — brute-force burst correlation

```spl
index=wineventlog EventCode=4625
| eval target_user=mvindex(Account_Name, -1)
| bin _time span=1m
| stats count as failed_attempts by Source_Network_Address, target_user, _time
| where failed_attempts > 5
| sort - failed_attempts
```

**Result — 5 distinct attack bursts identified:**

| src_ip | target_user | _time (1-min bin) | failed_attempts |
|---|---|---|---|
| 192.168.54.40 | khoa | 2026-07-16 08:52:00 | 13 |
| 192.168.54.40 | khoa | 2026-07-16 09:06:00 | 10 |
| 192.168.54.40 | khoa | 2026-07-16 09:40:00 | 10 |
| 192.168.54.40 | khoa | 2026-07-16 09:17:00 | 7 |
| 192.168.54.40 | khoa | 2026-07-16 11:14:00 | 7 |

Lower per-burst counts compared to the SSH scenario (7–13 vs. up to 286) reflect RDP's heavier handshake, the forced `-t 1` throttle, and the account lockout cutting each burst short.

## 4. Breach verification query

```spl
index=wineventlog EventCode=4624 Logon_Type=10 Source_Network_Address="192.168.54.40"
```

`Logon_Type=10` = RemoteInteractive (RDP). **Result:** `0 events` — confirms no successful RDP login from the attacker IP.

## 5. Auto-containment evidence — Account Lockout

```spl
index=wineventlog EventCode=4740
| table _time, host, Target_Account, Caller_Computer_Name
```

`EventCode=4740` = "A user account was locked out". Four lockout events were recorded, each timed to coincide with the end of an attack burst, with `Caller_Computer_Name=kali` — direct evidence that Windows' default lockout policy auto-contained the attack before any manual response.

## 6. Alert configuration

| Setting | Value |
|---|---|
| Alert type | Scheduled |
| Schedule | Cron `*/5 * * * *` (every 5 minutes) |
| Time range | Last 5 minutes |
| Trigger condition | Number of Results is greater than **0** |
| Trigger | Once |
| Actions | Add to Triggered Alerts, Send Email |

> **Lesson learned:** the threshold for "how many failures count as abnormal" belongs in the SPL (`where failed_attempts > 5`); the Alert's trigger condition should simply ask "did anything match at all" (`> 0`). Also, `Time range` **must** match the cron interval — leaving it at "All time" causes the alert to re-match old historical data every run and fire indefinitely.

## 7. Dashboard panels

Panels built on top of the queries above (see `screenshots/01-dashboard.png`):
1. Successful RDP logins from attacker IP (Single Value — should read 0)
2. Failed RDP logon attempts over time (Line Chart)
3. Top attacking IPs (Column Chart)
4. Targeted accounts (Pie Chart)
5. Raw failed RDP logon events (table)
6. Account lockout events (table) — unique to this scenario
