# T1059.001 — Command and Scripting Interpreter: PowerShell

**Log source:** Sysmon Event ID 1 (Process Creation) via `sourcetype="XmlWinEventLog"`, `index="wineventlog"`
**Test suite:** Atomic Red Team — 22 tests executed against T1059.001
**Date executed:** 2026-07-22

---

## 1. Final Detection Rule (SPL)

```spl
index="wineventlog" sourcetype="XmlWinEventLog" EventCode=1
| where NOT match(Image, "(?i)SplunkUniversalForwarder|splunk-powershell\.exe")
| where NOT match(CommandLine, "(?i)Invoke-AtomicTest|Out-ATHPowerShell|AtomicRedTeam")
| search Image=*powershell.exe OR Image=*cmd.exe
| eval T1059_001 = case(
       match(CommandLine, "(?i)-e(nc(odedcommand)?)?\s"), "Encoded Command",
       match(CommandLine, "(?i)-nop(rofile)?\s"), "No Profile",
       match(CommandLine, "(?i)\s-c(ommand)?\s"), "Command Switch (short form)",
       match(CommandLine, "[A-Za-z0-9+/]{40,}={0,2}"), "Base64 Blob",
       match(CommandLine, "(?i)--user|--password|--bhdump|--cachefilename|--outputdirectory"), "AD Recon Parameter",
       match(CommandLine, "(?i)invoke-webrequest|downloadstring|downloadfile|net\.webclient|invoke-restmethod"), "Download Cradle",
       match(CommandLine, "(?i)test-connection|new-pssession"), "Remote Connection",
       match(CommandLine, "(?i)-stream") AND match(CommandLine, "(?i)invoke-expression"), "Hidden Command (ADS)",
       1=1, "None"
)
| where T1059_001!="None"
| table _time, ParentImage, Image, User, CommandLine, T1059_001, EventCode, event_id
```

### Design notes

- **`EventCode=1`** — giới hạn về đúng Process Creation; các EventCode khác (11, 22...) không có field `CommandLine` đầy đủ, gây match trên giá trị null nếu không lọc trước.
- **Loại trừ Splunk Universal Forwarder / Atomic Red Team framework tự thân** — tránh false positive từ chính công cụ testing (`Invoke-AtomicTest`, `Out-ATHPowerShellCommandLineParameter`).
- **`-e(nc(odedcommand)?)?\s`** — bắt mọi biến thể viết tắt hợp lệ của `-EncodedCommand` mà PowerShell parameter binding chấp nhận (`-e`, `-enc`, `-encodedcommand`), vì attacker thường dùng dạng ngắn nhất để né rule chỉ match chuỗi đầy đủ.
- **`-stream` AND `invoke-expression`** — dùng kết hợp 2 điều kiện thay vì match riêng lẻ, giảm false positive vì `-Stream` một mình còn có mục đích hợp pháp khác (VD: Zone.Identifier metadata).
- **`Remote Connection`** — nhánh có khả năng false positive cao nhất nếu áp dụng production lâu dài, vì `Test-Connection` là cmdlet phổ biến trong tác vụ IT thông thường; nên gắn severity thấp hơn các nhánh khác.

---

## 2. Detection Matrix — 22 Atomic Tests

| Test # | Tên test | Kết quả thực thi | Sinh Sysmon EID 1? | Rule bắt được? | Nhánh match | Tier |
|---|---|---|---|---|---|---|
| 1 | Mimikatz | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 2 | Run BloodHound from disk | Module not found | ❌ | — | — | N/A — chưa thực thi |
| 3 | BloodHound Download Cradle | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 4 | Mimikatz — Cradlecraft PsSendKeys | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 5 | Invoke-AppPathBypass | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 6 | MsXml COM object | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 7 | PowerShell XML requests | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 8 | mshta.exe download | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 10 | Fileless Script Execution | Access denied | ❌ | — | — | N/A — chưa thực thi |
| **11** | NTFS Alternate Data Stream | ✅ Exit 0 | ✅ | ✅ | `Hidden Command (ADS)` | **Detected** |
| **12** | PowerShell Session Creation and Use | ✅ (Test-Connection chạy) | ✅ | ✅ | `Remote Connection` | **Detected** |
| **13** | `-C` command switch variation | ✅ Exit 0 | ✅ | ⚠️ | `No Profile` *(sai lý do — xem ghi chú)* | **Detected (attribution sai)** |
| **14** | `-C` + encoded argument | ✅ Exit 0 | ✅ | ✅ | `No Profile` + `Base64 Blob` | **Detected** |
| **15** | `-EncodedCommand` variation (`-E`) | ✅ Exit 0 | ✅ | ✅ | `Encoded Command` + `No Profile` + `Base64 Blob` | **Detected** |
| **16** | `-EncodedArguments` variation | ✅ Exit 0 | ✅ | ✅ | `Encoded Command` + `No Profile` + `Base64 Blob` | **Detected** |
| **17** | PowerShell Command Execution (benign) | ✅ Exit 0, **không có ProcessId** | ❌ | — | — | **Missing** |
| 18 | Invoke Known Malicious Cmdlets | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 19 | PowerUp Invoke-AllChecks | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 20 | Abuse Nslookup with DNS Records | Access denied | ❌ | — | — | N/A — chưa thực thi |
| 21 | SOAPHound — Dump BloodHound Data | CommandNotFound (thiếu binary) | ❌ | — | — | N/A — chưa thực thi |
| 22 | SOAPHound — Build Cache | CommandNotFound (thiếu binary) | ❌ | — | — | N/A — chưa thực thi |

### Tổng hợp

- **Detected:** 5 test (12, 13, 14, 15, 16)
- **Missing:** 1 test (17)
- **Not Executed — bị chặn bởi Windows Defender** (xác nhận qua `Get-MpThreatDetection`, không liên quan đến quyền admin — xem mục 3.5): tests 8, 18, 20, và các test liên quan BloodHound/SharpHound (2, 3)
- **Not Executed — thiếu binary/module phụ trợ trong lab** (Mimikatz, PowerUp, SOAPHound chưa đặt đúng path): tests 1, 4-7, 10, 19, 21, 22

> **Lưu ý quan trọng:** "Not Executed" **không phải** một khối đồng nhất. Có 2 nguyên nhân khác nhau đứng sau nhãn này: (1) **Windows Defender activelly chặn** — đây là một detection layer thật đang hoạt động, không phải gap; (2) **thiếu điều kiện môi trường lab** (binary/module chưa cài đặt) — đây mới đúng là gap về test coverage. Cả hai đều khác bản chất với **"Missing"** — trường hợp payload chạy trót lọt nhưng detection engineering (rule/log source) không bắt được. Ba loại này cần được phân biệt rõ khi báo cáo, tránh đánh giá sai hiệu quả của rule Splunk.

---

## 3. Root Cause Analysis

### Test 17 — Missing: Sysmon EID 1 không đủ để cover mọi hình thức thực thi PowerShell

**Root cause:** Test 17 thực thi scriptblock (`Write-Host "Hello, from PowerShell!"`) trực tiếp trong PowerShell session đang mở sẵn (session dùng để chạy `Invoke-AtomicTest`), không spawn process `powershell.exe` con mới. Vì Sysmon Event ID 1 chỉ log tại thời điểm `CreateProcess`, không có process mới nào được tạo → không có event nào sinh ra ở tầng process creation, bất kể nội dung script vô hại hay độc hại.

**Remediation:** Bật **PowerShell Script Block Logging** (Event ID 4104) qua GPO:
```
Computer Configuration > Administrative Templates > Windows Components
> Windows PowerShell > Turn on PowerShell Script Block Logging
```
Log này hoạt động ở tầng engine của PowerShell, độc lập với việc có spawn process con hay không, nên bắt được toàn bộ nội dung scriptblock thực thi kể cả trường hợp inline.

### Test 11 — Detected nhờ behavior-pairing, không dựa trên flag

**Điểm đáng chú ý:** Command của test này hoàn toàn plaintext — không obfuscate, không base64, không flag đáng ngờ nào. Tín hiệu duy nhất là **cặp hành vi**: ghi dữ liệu vào NTFS Alternate Data Stream (`-Stream`) rồi thực thi động (`Invoke-Expression`). Đây là kỹ thuật defense evasion (giấu payload trong luồng dữ liệu ẩn mà Explorer/`dir` không hiển thị) kết hợp dynamic execution. Rule chỉ match được nhờ kết hợp 2 điều kiện `AND`; nếu chỉ match riêng lẻ `-Stream` sẽ gây false positive vì tham số này còn dùng cho mục đích hợp pháp khác.

### Test 13 — False attribution: bị bắt vì lý do sai

Command: `powershell.exe -NoProfile -C Write-Host <guid>`. Rule hiện tại gắn nhãn `"No Profile"` vì match được `-NoProfile`, nhưng thứ đáng chú ý thực sự ở test này là switch `-C` (dạng viết tắt của `-Command`) — chưa có nhánh riêng nào bắt trực tiếp pattern này trước khi bổ sung `Command Switch (short form)`. Nếu attacker chỉ dùng `-C` mà không kèm `-NoProfile`, rule bản gốc (trước khi vá) sẽ **miss hoàn toàn**.

### 3.5 — Windows Defender là một detection layer thật, xác nhận qua `Get-MpThreatDetection`

Ban đầu, các test báo lỗi `Access is denied` tại `$process.Start()` được giả định là do thiếu quyền hệ thống. Thực tế đã kiểm chứng lại: **user chạy PowerShell với quyền Administrator, lỗi vẫn xảy ra** — loại trừ khả năng đây là vấn đề ACL/permission.

Chạy `Get-MpThreatDetection` trên máy victim cho thấy Windows Defender đã chủ động can thiệp qua 2 cơ chế:

| Cơ chế | `DetectionSourceTypeID` | Ví dụ trong lab |
|---|---|---|
| **File scan** — cách ly file ngay khi ghi xuống disk, trước khi PowerShell kịp thực thi | `3` | `SharpHound.ps1`, `uacme.zip`, `RedInjection.exe`, `Get-Keystrokes.ps1` bị `CleaningActionID: 3` (Quarantine) hoặc `2` (Remove) |
| **Behavior monitoring** — chặn ngay tại thời điểm process con chuẩn bị được tạo, dựa trên pattern trong CommandLine | `2` | `mshta.exe javascript:...GetObject('script:https://...mshta.sct')` (test 8, 20); danh sách cmdlet `Invoke-Mimikatz`, `Invoke-Shellcode`, `Invoke-TokenManipulation`... (test 18) |

**Kết luận:** một phần đáng kể trong số 16 test "Not Executed" thực chất **đã bị phát hiện và chặn** — chỉ là bị chặn bởi Windows Defender (endpoint layer) thay vì bởi rule Splunk (SIEM layer). Đây là bằng chứng thực tế cho mô hình **defense-in-depth**: AV/EDR xử lý threat gần payload nhất (trước khi kịp tạo process), trong khi SIEM đóng vai trò correlation/visibility bổ sung cho những gì lọt qua được endpoint layer. Splunk không phải là lớp phòng thủ duy nhất, và một kỹ thuật "không thấy trong Splunk" không đồng nghĩa với "không được phát hiện" — cần đối chiếu chéo với endpoint protection logs trước khi kết luận đó là detection gap.

### Tests 21-22 (SOAPHound) — Không thể detect bằng flag-based rule

Dù không thực thi thành công trong lab này (do thiếu binary), phân tích cấu trúc lệnh cho thấy: `SOAPHound.exe` là công cụ AD reconnaissance chạy qua ADWS, có command line hoàn toàn plaintext (không obfuscate). Rule flag-based (`-enc`, `-nop`, base64) sẽ **luôn miss** loại này. Cần detection riêng dựa trên:
1. Tên binary đã biết (dễ bypass qua rename)
2. Argument pattern đặc trưng của công cụ (`--bhdump`, `--cachefilename`) — bền hơn vì gắn với logic tool
3. Credential cleartext trong CLI (`--password`) — tín hiệu độc lập, áp dụng rộng cho T1552

---

## 4. Key Lessons Learned

1. **Flag-based detection không đủ cho toàn bộ kỹ thuật T1059.001.** Nhiều test (11, 12, SOAPHound) hoàn toàn plaintext, không có flag né tránh nào — detection phải mở rộng sang layer behavior-pairing (VD: `-Stream` + `Invoke-Expression`) và argument-pattern matching cho các tool cụ thể.
2. **Sysmon Event ID 1 có blind spot cố hữu:** chỉ bắt được khi có process mới được tạo. Thực thi inline trong session có sẵn (test 17) hoàn toàn vô hình trước log source này — cần Script Block Logging (4104) làm lớp bổ sung.
3. **Phân biệt rõ giữa artifact của testing framework và artifact của kỹ thuật tấn công thật.** Các hàm nội bộ của Atomic Red Team (`Out-ATHPowerShellCommandLineParameter`) không nên bị coi là chỉ báo tấn công thật, và nên được loại trừ khỏi baseline khi tune rule cho môi trường production.
4. **"Access is denied" không đồng nghĩa với thiếu quyền admin.** Kiểm chứng bằng cách chạy PowerShell as Administrator vẫn gặp lỗi tương tự, sau đó xác nhận qua `Get-MpThreatDetection` rằng nguyên nhân thực sự là Windows Defender chủ động chặn payload (file scan hoặc behavior monitoring) — độc lập hoàn toàn với ACL/permission. Đây là bài học về việc **không vội gán nguyên nhân theo triệu chứng bề mặt** mà cần xác minh bằng log cụ thể trước khi kết luận.
5. **"Not executed" không phải một khối đồng nhất.** Cần tách rõ giữa: (a) bị Windows Defender chặn — một detection layer thật đang hoạt động, không phải gap; và (b) thiếu điều kiện môi trường lab (binary/module chưa cài) — gap về test coverage, khác bản chất với (c) "Missing" — payload chạy lọt nhưng Splunk không bắt được. Gộp chung cả ba vào một nhãn sẽ đánh giá sai hiệu quả thực sự của rule detection.
5. **`case()` chỉ trả về nhánh match đầu tiên theo thứ tự khai báo** — cần cẩn trọng thứ tự nhánh để tránh gắn nhãn "đúng nhưng sai lý do" (như test 13), và cân nhắc dùng eval cộng dồn (concatenate) khi cần thấy đầy đủ mọi tín hiệu trùng khớp trên cùng một dòng.

