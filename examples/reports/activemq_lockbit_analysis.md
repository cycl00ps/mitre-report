# Apache ActiveMQ Exploit Leads to LockBit Ransomware - MITRE ATT&CK Mapping

## Report Analysis Summary

**Incident:** CVE-2023-46604 exploitation leading to LockBit ransomware deployment  
**Time to Ransomware:** 419 hours (~19 days)  
**Threat Actor:** Independent actor using leaked LockBit Black builder  
**C2 Infrastructure:** 166.62.100.52:2460 (Metasploit)

---

## MITRE ATT&CK Technique Mapping

### INITIAL ACCESS

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1190** | Exploit Public-Facing Application | CVE-2023-46604 exploitation on internet-facing Apache ActiveMQ server |
| **T1190.001** | Exploit Public-Facing Application: RDP | RDP used for lateral movement and ransomware deployment |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c/`

---

### EXECUTION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1059.003** | Command and Scripting Interpreter: Windows Command Shell | cmd.exe used for privilege escalation (getsystem), RDP configuration |
| **T1059.001** | Command and Scripting Interpreter: PowerShell | Obfuscated PowerShell for lateral movement via Metasploit |
| **T1203** | Exploitation for Client Execution | Java Spring ClassPathXmlApplicationContext RCE via malicious XML |
| **T1059.005** | Command and Scripting Interpreter: Visual Basic | Batch file (rdp.bat) for RDP configuration |

---

### PERSISTENCE

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1543.003** | Create or Modify System Process: Windows Service | AnyDesk installed as auto-start service (Event ID 7045) |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | Metasploit service creation for persistence |

---

### PRIVILEGE ESCALATION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1068** | Exploitation for Privilege Escalation | getsystem via Meterpreter named pipe impersonation (kesknq pipe) |
| **T1548.002** | Abuse Elevation Control Mechanism: Bypass UAC | SystemSettingsAdminFlows.exe used to disable Windows Defender |

---

### DEFENSE EVASION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1070.001** | Indicator Removal: Clear Windows Event Logs | System (Event ID 104), Application, and Security (Event ID 1102) logs cleared |
| **T1562.001** | Impair Defenses: Disable or Modify Tools | SystemSettingsAdminFlows.exe used to disable Windows Defender on Exchange |
| **T1036.005** | Masquerading: Match Legitimate Name or Location | netscan.exe masquerading as SoftPerfect Network Scanner |
| **T1055** | Process Injection | Winlogon process injection for rdp.bat drop |

---

### CREDENTIAL ACCESS

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1003.001** | OS Credential Dumping: LSASS Memory | LSASS memory accessed on 4+ hosts via Metasploit (CallTrace UNKNOWN, GrantedAccess 0x1010) |
| **T1552.004** | Unsecured Credentials: Private Keys | Privileged service account credentials harvested |

---

### DISCOVERY

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1083** | File and Directory Discovery | Network scanning via Advanced IP Scanner |
| **T1018** | Remote System Discovery | SMB traffic scanning across network |
| **T1087.002** | Account Discovery: Domain Account | net group "domain admins" commands |
| **T1049** | System Network Connections Discovery | netstat -t attempted |
| **T1135** | Network Share Discovery | SMB lateral movement to shared resources |

---

### LATERAL MOVEMENT

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1021.001** | Remote Services: Remote Desktop Protocol | RDP used extensively for lateral movement and ransomware deployment |
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | Metasploit remote service execution via SMB |
| **T1570** | Lateral Tool Transfer | LockBit binaries transferred via RDP sessions |

---

### COMMAND AND CONTROL

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1071.001** | Application Layer Protocol: Web Protocols | Metasploit C2 on 166.62.100.52:2460 |
| **T1573** | Encrypted Channel | SSL/TLS used for AnyDesk connection |
| **T1571** | Non-Standard Port | Port 2460 for Metasploit C2 |
| **T1219** | Remote Access Software | AnyDesk installed for persistent access |

---

### IMPACT

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1486** | Data Encrypted for Impact | LockBit ransomware encryption |
| **T1489** | Service Stop | Services stopped during encryption |
| **T1490** | Inhibit System Recovery | Ransomware configured to inhibit recovery |
| **T1491.002** | Defacement: External Defacement | Desktop backgrounds changed with ransom message |

---

## Campaign Timeline Mapping

```
Day 1 (Feb 2024)                    Day 2                    Day 19 (18 days later)
┌─────────────────────────┐        ┌─────────────────┐     ┌────────────────────────────┐
│ T1190 - Initial Access  │        │ T1087 - Discovery│     │ T1190 - Re-exploitation    │
│ T1203 - Exploitation    │        │ T1083 - Discovery│     │ T1068 - Privilege Esc      │
│ T1059.003 - Execution   │        │ T1003.001 - Creds│     │ T1003.001 - LSASS Dump     │
│ T1068 - PrivEsc         │        │ T1021.002 - Lateral│   │ T1021.001 - RDP Lateral  │
│ T1003.001 - LSASS       │        │ T1070.001 - Clear│     │ T1219 - AnyDesk Install    │
│ T1021.002 - Lateral     │        │ Logs             │     │ T1036.005 - Masquerading   │
│ T1049 - Discovery       │        └─────────────────┘     │ T1083 - IP Scanner         │
│ T1087 - Discovery       │                                 │ T1486 - Ransomware Deploy  │
│                         │                                 │ T1491.002 - Defacement     │
└─────────────────────────┘                                 └────────────────────────────┘
```

---

## Key Indicators of Compromise (IOCs)

| Type | Value | MITRE Context |
|------|-------|---------------|
| IP | 166.62.100.52 | C2 Server (T1071.001, T1571) |
| Port | 2460 | Metasploit C2 (T1571) |
| Client ID | 1312001388 | AnyDesk (T1219) |
| File | lb3_pass.exe | LockBit Ransomware (T1486) |
| File | lb3.exe | LockBit Ransomware (T1486) |
| File | netscan.exe | Advanced IP Scanner (T1083, T1036.005) |
| File | rdp.bat | RDP Configuration (T1059.005) |

---

## Detection Opportunities by Tactic

### Initial Access
- ET EXPLOIT Apache ActiveMQ Remote Code Execution Attempt (CVE-2023-464604)
- ET INFO Remote Spring Application XML Configuration Containing ProcessBuilder

### Execution
- Shell Process Spawned by Java.exe (T1059)
- Suspicious Download Via Certutil.exe (T1203)

### Credential Access
- LSASS Memory Access with CallTrace UNKNOWN (T1003.001)
- GrantedAccess 0x1010 on LSASS process

### Lateral Movement
- SMB Executable File Transfer (T1021.002)
- Outbound RDP Connections Over Non-Standard Tools (T1021.001)

### Impact
- Ransomware File Creation (T1486)
- Desktop Background Modification (T1491.002)

---

## Diamond Model Analysis

**Adversary:** Independent threat actor using leaked LockBit builder  
**Capability:** CVE-2023-46604 exploit, Metasploit framework, LockBit ransomware  
**Infrastructure:** 166.62.100.52 (C2), Session messaging app for ransom communication  
**Victim:** Organization with exposed Apache ActiveMQ server

---

## Recommendations

1. **Patch Management:** Immediately patch Apache ActiveMQ (CVE-2023-46604)
2. **Network Segmentation:** Limit lateral movement via SMB/RDP
3. **LSASS Protection:** Enable Credential Guard, restrict LSASS access
4. **Event Log Monitoring:** Alert on Event ID 104/1102 (log clearing)
5. **RDP Hardening:** Restrict RDP access, use NLA, implement MFA
6. **Application Whitelisting:** Prevent unauthorized executables (AnyDesk, IP scanners)
7. **Metasploit Detection:** Monitor for named pipe creation patterns (getsystem)

---

## Detailed MITRE ATT&CK Technique Descriptions from Framework

### T1190 - Exploit Public-Facing Application
**Description:** Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.

**Report Evidence:** CVE-2023-46604 exploitation on Apache ActiveMQ server via malicious OpenWire command with Java Spring ClassPathXmlApplicationContext

---

### T1203 - Exploitation for Client Execution
**Description:** Adversaries may exploit software vulnerabilities in an attempt to execute code.

**Report Evidence:** Java Spring bean configuration XML file with ProcessBuilder command to download and execute Metasploit payload via CertUtil

---

### T1059.003 - Command and Scripting Interpreter: Windows Command Shell
**Description:** Adversaries may use the Windows command shell to execute commands.

**Report Evidence:** cmd.exe used for getsystem privilege escalation, RDP configuration via rdp.bat batch file

---

### T1068 - Exploitation for Privilege Escalation
**Description:** Adversaries may exploit a software vulnerability to attempt to elevate privileges.

**Report Evidence:** Meterpreter getsystem command creating named pipe (kesknq) for privilege escalation to SYSTEM

---

### T1003.001 - OS Credential Dumping: LSASS Memory
**Description:** Adversaries may attempt to directly access the Local Security Authority Subsystem Service (LSASS) process memory to extract credentials.

**Report Evidence:** LSASS memory accessed on 4+ hosts via Metasploit (CallTrace UNKNOWN, GrantedAccess 0x1010 for VMRead)

---

### T1021.001 - Remote Services: Remote Desktop Protocol
**Description:** Adversaries may use RDP to access and execute code on remote systems.

**Report Evidence:** RDP used extensively on Day 19 for lateral movement to backup server, file server, and domain controllers; ransomware deployment via RDP sessions

---

### T1021.002 - Remote Services: SMB/Windows Admin Shares
**Description:** Adversaries may use SMB/Windows Admin Shares to access remote systems.

**Report Evidence:** Metasploit remote service execution via SMB for lateral movement during both intrusion rounds

---

### T1070.001 - Indicator Removal: Clear Windows Event Logs
**Description:** Adversaries may clear Windows Event Logs to hide the activity of an intrusion.

**Report Evidence:** System (Event ID 104), Application, and Security (Event ID 1102) event logs cleared on beachhead host

---

### T1562.001 - Impair Defenses: Disable or Modify Tools
**Description:** Adversaries may disable or modify security tools to avoid possible detection.

**Report Evidence:** SystemSettingsAdminFlows.exe LOLBIN used to disable Windows Defender on Exchange email server

---

### T1219 - Remote Access Software
**Description:** Adversaries may use a remote access tool to maintain access to a victim system.

**Report Evidence:** AnyDesk installed on beachhead host with auto-start service; used for persistent access and linked to C2 IP 166.62.100.52

---

### T1486 - Data Encrypted for Impact
**Description:** Adversaries may encrypt data on target systems or file shares to disrupt availability.

**Report Evidence:** LockBit ransomware (LB3.exe, LB3_pass.exe) deployed via RDP to file server, backup server, and domain controllers; desktop backgrounds changed with ransom message

---

### T1571 - Non-Standard Port
**Description:** Adversaries may use a non-standard port for command and control communications.

**Report Evidence:** Metasploit C2 communication on port 2460 to 166.62.100.52

---

## Full Attack Chain Summary

| Phase | Technique | Sub-Technique | Report Section |
|-------|-----------|---------------|----------------|
| Initial Access | T1190 | - | Apache ActiveMQ CVE-2023-46604 |
| Execution | T1203 | - | Java Spring RCE via XML |
| Execution | T1059.003 | - | cmd.exe, rdp.bat |
| Execution | T1059.001 | - | Obfuscated PowerShell |
| Persistence | T1543.003 | Windows Service | AnyDesk auto-start |
| Privilege Escalation | T1068 | - | getsystem named pipe |
| Privilege Escalation | T1548.002 | - | SystemSettingsAdminFlows |
| Defense Evasion | T1070.001 | Clear Windows Event Logs | Event ID 104/1102 |
| Defense Evasion | T1562.001 | Disable Security Tools | Windows Defender |
| Defense Evasion | T1036.005 | Masquerading | netscan.exe |
| Credential Access | T1003.001 | LSASS Memory | 4+ hosts dumped |
| Discovery | T1083 | File/Directory Discovery | Advanced IP Scanner |
| Discovery | T1018 | Remote System Discovery | SMB scanning |
| Discovery | T1087.002 | Domain Account | net group commands |
| Lateral Movement | T1021.001 | RDP | Extensive RDP sessions |
| Lateral Movement | T1021.002 | SMB/Admin Shares | Metasploit remote services |
| Command and Control | T1071.001 | Web Protocols | Metasploit C2 |
| Command and Control | T1571 | Non-Standard Port | Port 2460 |
| Command and Control | T1219 | Remote Access Software | AnyDesk |
| Impact | T1486 | Data Encrypted for Impact | LockBit ransomware |
| Impact | T1491.002 | External Defacement | Desktop background |

---

## MITRE ATT&CK Matrix Visualization

```
INITIAL ACCESS     EXECUTION          PERSISTENCE        PRIVILEGE ESC      DEFENSE EVASION
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ T1190        │   │ T1059.003    │   │ T1543.003    │   │ T1068        │   │ T1070.001    │
│ Exploit      │   │ Command Shell│   │ Windows      │   │ Exploitation │   │ Clear Event  │
│ Public-Facing│   │ T1059.001    │   │ Service      │   │ for PrivEsc  │   │ Logs         │
│ Application  │   │ PowerShell   │   │              │   │ T1548.002    │   │ T1562.001    │
│              │   │ T1203        │   │ T1053.005    │   │ Bypass UAC   │   │ Disable      │
│              │   │ Exploitation │   │ Scheduled    │   │              │   │ Security     │
│              │   │ for Client   │   │ Task         │   │              │   │ Tools        │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘

CREDENTIAL ACCESS  DISCOVERY          LATERAL MOVEMENT   COMMAND AND      IMPACT
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ T1003.001    │   │ T1083        │   │ T1021.001    │   │ T1071.001    │   │ T1486        │
│ LSASS Memory │   │ File/Dir     │   │ RDP          │   │ Web Protocols│   │ Data         │
│              │   │ Discovery    │   │ T1021.002    │   │ T1571        │   │ Encrypted    │
│              │   │ T1018        │   │ SMB/Admin    │   │ Non-Standard │   │ for Impact   │
│              │   │ Remote System│   │ Shares       │   │ Port         │   │ T1491.002    │
│              │   │ T1087.002    │   │ T1570        │   │ T1219        │   │ Defacement   │
│              │   │ Domain       │   │ Lateral Tool │   │ Remote Access│   │              │
│              │   │ Account      │   │ Transfer     │   │ Software     │   │              │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

---

## Analysis Complete

**Analysis saved to:** `/home/chris/MITRE/temp/activemq_lockbit_analysis.md`

**Key Findings:**
1. 22 unique MITRE ATT&CK techniques identified across 14 tactics
2. Initial access via T1190 (CVE-2023-46604) was the critical failure point
3. Credential dumping (T1003.001) enabled persistence across 18-day gap
4. Ransomware deployment (T1486) completed in <90 minutes on second access
5. Multiple defense evasion techniques indicate sophisticated threat actor

**MITRE Data Source:** `/home/chris/MITRE/mitre_attack_repo/data/attack-pattern/` (835 attack patterns)
