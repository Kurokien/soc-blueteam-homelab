# Lessons Learned

Consolidated technical and process lessons from building and operating this SOC home lab, expanded from the summary in the main [README](README.md). Organized by category rather than by scenario, since several lessons apply across both.

---

## Splunk / SPL Detection Engineering

**Separate "how much" from "did it happen."** Detection thresholds (e.g. "more than 5 failed logins per minute") belong inside the SPL query itself (`where count > N`). The Alert's trigger condition should only ask whether the query returned anything at all (`Number of Results > 0`). Mixing the two — e.g. setting the Alert's own trigger condition to `> 5` — created a bug in the RDP scenario where the alert would almost never fire, because it required 6+ *already-aggregated* rows within a single 5-minute run, not 6+ raw events.

**Scheduled Alert `Time Range` must match the cron interval.** Leaving `Time Range = All time` on a `*/5 * * * *` schedule causes Splunk to re-scan the entire historical index every 5 minutes. Since old brute-force data still exists in the index, this produced an alert that would trigger forever, long after the actual attack ended. Fixed by setting `Time Range = Last 5 minutes` to match the schedule.

**Real-time + Per-Result triggering causes alert fatigue.** The first alert (SSH scenario) was configured as `Alert type: Real-time` with `Trigger alert when: Per-Result`, meaning every single matching log line fired its own alert — dozens of Triggered Alerts entries within about 60 seconds during one burst. The RDP scenario alert was redesigned as `Scheduled` + `Trigger: Once`, producing one alert per detection window instead.

**Windows Event Log fields can be multivalue and silently double your counts.** Event ID 4625 bundles `SubjectUserName` (usually `-`) and `TargetUserName` into a single Splunk field (`Account_Name`). A naive `stats count by Account_Name` produced two rows per event — one for `-`, one for the real username — inflating every count by 2x. Caught by manually inspecting `| table Account_Name` before trusting the aggregation, and fixed with `mvindex(Account_Name, -1)`.

**Always run a breach-verification query, don't infer absence of compromise.** For both scenarios, the presence of failed-login alerts alone doesn't prove the account wasn't eventually compromised. A second, explicit query (`"Accepted password"` for SSH; `EventCode=4624 Logon_Type=10` for RDP) was run against the same source IP and time window to confirm zero successful logins. This became a standard step for every scenario going forward.

---

## Infrastructure & Networking

**Time synchronization across every VM is a prerequisite, not an afterthought.** Early in the RDP scenario, Windows Security logs appeared to be missing from Splunk entirely — the real cause was that the Splunk server's clock wasn't NTP-synced, making correctly-forwarded logs fall outside the search time range. Fixed by enabling `chrony` (Ubuntu) and `w32tm` (Windows), and standardizing all four VMs to the same timezone (`Asia/Ho_Chi_Minh`).

**VirtualBox Host-only Adapter is preferable to Internal Network for a solo lab.** Host-only allows the physical host machine to reach the VMs directly (e.g. browsing to the Splunk Web UI on port 8000 without port-forwarding), which Internal Network does not support. The tradeoff (slightly less isolation) is acceptable for a personal, non-production lab.

**Universal Forwarder log visibility depends on OS-level permissions, not just `inputs.conf`.** Sysmon logs forwarded correctly by default, but Windows Security Event Log initially did not — because reading the Security channel requires the forwarder process to run as `Local System` or be a member of the `Event Log Readers` group, unlike Sysmon's more permissive log.

---

## Attack Execution

**RDP brute-forcing is fundamentally different from SSH brute-forcing.** SSH tolerated 16 parallel Hydra tasks at ~250 tries/minute; RDP required throttling to a single task (`-t 1`) due to the heavier TLS/CredSSP handshake per attempt, and NLA specifically caused Hydra connection resets that had nothing to do with password correctness.

**Windows' default Account Lockout Policy is a real, working control — and it fought back mid-test.** After only ~10 failed RDP attempts, the target account locked automatically (Event ID 4740), which is exactly what the control is designed to do. This meant every attack burst self-terminated within about a minute, producing naturally segmented data (5 bursts) rather than one continuous flood — and turned into a detection-worthy event in its own right rather than just an operational nuisance.

**Lab-only configuration changes (disabling NLA, disabling account lockout) must be tracked and reverted.** Because NLA was intentionally disabled to get Hydra working, the runbook for the RDP scenario explicitly includes a "restore lab state" step — a habit worth carrying into any future scenario that requires temporarily weakening a control for testing purposes.

---

## Documentation & Process

**Every incident report follows the same NIST SP 800-61 structure** (Executive Summary → Preparation → Detection & Analysis → Containment → Eradication & Recovery → Lessons Learned → Appendix), regardless of scenario. Keeping this consistent makes reports easier to compare across scenarios and mirrors how a real SOC team would standardize documentation.

**Screenshots alone are not evidence — they need to answer a specific question.** Early dashboard drafts included panels with unclear titles or redundant groupings (e.g. charting a single-IP attack by IP, which added no information). Each panel was revised to answer one specific analytical question (who attacked, when, who was targeted, did they succeed).
