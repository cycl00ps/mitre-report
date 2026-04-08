# Cat's Got Your Files: Lynx Ransomware - MITRE ATT&CK Mapping

## Report Analysis Summary

| Field | Value |
|-------|-------|
| **Incident** | RDP credential compromise leading to Lynx ransomware deployment |
| **Time to Ransomware** | ~178 hours (9 days) |
| **Threat Actor** | Assessed to have obtained credentials via Initial Access Broker or infostealer |
| **C2 Infrastructure** | 195.211.190.189, 77.90.153.30 (Railnet LLC/Virtualine bulletproof hosting) |
| **Hostname** | DESKTOP-BUL6K1U |
| **Ransomware** | Lynx (w.exe) |

---

## MITRE ATT&CK Technique Mapping

### INITIAL ACCESS

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1133** | External Remote Services | RDP login to internet-exposed system from 195.211.190.189 |
| **T1078** | Valid Accounts | No brute force; credentials obtained prior (infostealer/IAB/breach) |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--10d51417-ee35-4589-b1ff-b6df1c334e8d/`

---

### EXECUTION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1059.003** | Command and Scripting Interpreter: Windows Command Shell | cmd.exe used for discovery commands (ipconfig, route print, systeminfo, net user) |
| **T1059.001** | Command and Scripting Interpreter: PowerShell | PowerShell observed during intrusion |

**Evidence:** Processes consistently spawned under `explorer.exe` indicating RDP interactive use. Commands executed include `ipconfig`, `route print`, `systeminfo`, `net user`, `reg query`.

---

### PERSISTENCE

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1136.002** | Create Account: Domain Account | Created "administratr", "Lookalike 1", "Lookalike 2" via dsa.msc |
| **T1543.003** | Create or Modify System Process: Windows Service | AnyDesk installed as service on domain controller |
| **T1098.007** | Account Manipulation: Additional Domain Groups | Accounts added to Domain Admins, Group Policy Creator Owners |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--7610cada-1499-41a4-b3dd-46467b68d177/`

**Evidence:**
- Used Active Directory Users and Computers (dsa.msc) to create look-alike accounts
- Set USER_DONT_EXPIRE_PASSWORD attribute for non-expiring passwords
- Added "administratr" and "Lookalike 1" to Domain Admins group
- Added "administratr" to Group Policy Creator Owners
- Added "Lookalike 2" to domain-specific high-privilege group

---

### PRIVILEGE ESCALATION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1098.007** | Account Manipulation: Additional Domain Groups | New accounts granted Domain Admin privileges |

**Evidence:** Threat actor leveraged pre-compromised domain admin credentials and created new privileged accounts to access hypervisor servers.

---

### DISCOVERY

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1046** | Network Service Discovery | SoftPerfect Network Scanner v7.2.7 used extensively |
| **T1135** | Network Share Discovery | Share scanning enabled in netscan config; delete[.]me file created on shares |
| **T1018** | Remote System Discovery | netscan enumerated full IP range; NetExec SMB enumeration |
| **T1016** | System Network Configuration Discovery | ipconfig, route print commands |
| **T1082** | System Information Discovery | systeminfo, taskmgr.exe /4 |
| **T1012** | Query Registry | reg query for Hyper-V hostnames |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--09312b1a-c3c6-4b45-9844-3ccc78e5d82f/`

**Evidence:**
- SoftPerfect Network Scanner configured to scan full IP range with share scanning
- netscan.xml config shows custom port scanning and share checks
- NetExec (nxc.exe) used for SMB enumeration: `nxc.exe smb REDACTED/24 -u REDACTED -p REDACTED`
- Registry query: `reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`
- Browser sessions launched from netscan to access network appliance web portals

---

### LATERAL MOVEMENT

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1021.001** | Remote Services: Remote Desktop Protocol | RDP used for all lateral movement to DCs, hypervisors, backup servers |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--eb062747-2193-45de-8fa2-e62549c37ddf/`

**Evidence:**
- Day 1: Lateral movement to domain controller via RDP (Logon Type 7 - Unlock existing session)
- Day 2: Logins to hypervisors using "Lookalike 1" and "administratr" accounts (Logon Type 3)
- Day 6-8: Multiple RDP connections to domain controllers and hypervisors
- Day 9: RDP to backup servers for ransomware deployment
- mstsc.exe launched via netscan.exe hotkeys (CTRL+R)

---

### COLLECTION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1560.001** | Archive Collected Data: Archive via Utility | 7-Zip (7zG.exe) used to compress network share contents |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--04a5a8ab-3bc8-4c83-95c9-55274a89786d/`

**Evidence:**
- Accessed multiple network shares from beachhead host
- Used 7-Zip context menu "Add to Archive" via explorer.exe
- Archives saved to Desktop folder of compromised user
- Multiple archives created correlating with exfiltration events

---

### EXFILTRATION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1567** | Exfiltration Over Web Service | Files exfiltrated to temp.sh temporary file-sharing service |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--e6d17c5f-6c42-4a1d-a6f3-7e1e8b5c3d4a/`

**Evidence:**
- Browsed to temp.sh via Microsoft Edge
- Upload URI (/upload) accessed multiple times
- Network traffic to temp.sh IP address correlates with archive count
- Large outgoing data transfers observed

---

### COMMAND AND CONTROL

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1219** | Remote Access Software | AnyDesk installed on domain controller (not used during intrusion) |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--95ae648f-0e7a-470d-a993-41546fc203f5/`

**Infrastructure:**
- Primary IP: 195.211.190.189 (Railnet LLC/Virtualine)
- Secondary IP: 77.90.153.30 (Railnet LLC/Virtualine)
- Hostname: DESKTOP-BUL6K1U
- Railnet LLC identified as front for Russian bulletproof hosting provider Virtualine

---

### IMPACT

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1486** | Data Encrypted for Impact | Lynx ransomware (w.exe) deployed on backup and file servers |
| **T1490** | Inhibit System Recovery | Veeam backup jobs deleted via Veeam Backup & Replication console |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--766d8817-a0f5-476f-8c66-8c3a5c6f6f4e/`

**Evidence:**
- Ransomware payload: w.exe
- Execution command: `w.exe --dir E:\ --mode fast --verbose --noprint`
- Arguments: --dir E:\ (target folder), --mode fast (5% encryption), --noprint (disable printer notes)
- Veeam Backup & Replication console accessed
- Backup jobs removed from configuration database
- Veeam log shows Job Deletion events

---

## Campaign Timeline Mapping

```
Day 1 (Initial Access)          Day 6 (Exfiltration)          Day 8-9 (Impact)
┌──────────────────────┐       ┌──────────────────────┐      ┌──────────────────────┐
│ T1133 - RDP Access   │       │ T1560.001 - Archive  │      │ T1490 - Delete       │
│ T1078 - Valid Accounts│      │ T1567 - Exfil to     │      │    Backups           │
│ T1046 - Network Scan │       │    temp.sh           │      │ T1486 - Lynx         │
│ T1021.001 - RDP to   │       │ T1021.001 - RDP to   │      │    Ransomware        │
│    DC                │       │    Hypervisors       │      │ T1021.001 - RDP      │
│ T1136.002 - Create   │       │ T1046 - NetExec      │      │    to Backup Servers │
│    Domain Accounts   │       │    SMB Enum          │      │                      │
│ T1543.003 - AnyDesk  │       │                      │      │                      │
└──────────────────────┘       └──────────────────────┘      └──────────────────────┘
        0 hours                    ~144 hours                  ~178 hours
```

---

## Key Indicators of Compromise (IOCs)

| Type | Value | MITRE Context |
|------|-------|---------------|
| IP | 195.211.190.189 | Initial Access (T1133) - Railnet LLC |
| IP | 77.90.153.30 | Lateral Movement (T1021.001) - Railnet LLC |
| Hostname | DESKTOP-BUL6K1U | C2 Source |
| File | netscan.exe | Discovery (T1046) - Hash: 3073af95dfc18361caebccd69d0021a2 |
| File | nxc.exe | Discovery (T1046) - Hash: 7532ff90145b8c59dc9440bf43dc87a5 |
| File | w.exe | Impact (T1486) Lynx Ransomware - Hash: e2179046b86deca297ebf7398b95e438 |
| Domain | temp.sh | Exfiltration (T1567) |
| Account | administratr | Persistence (T1136.002) |
| Account | Lookalike 1 | Persistence (T1136.002) |
| Account | Lookalike 2 | Persistence (T1136.002) |

---

## Detection Opportunities by Tactic

### Initial Access
- Monitor for RDP logons (Event 4624, Logon Type 10) from public IPs
- Alert on successful RDP without preceding failed attempts (indicates valid credentials)
- Detect external RDP connections to beachhead hosts

### Execution
- Monitor cmd.exe and PowerShell process creation from explorer.exe over RDP sessions
- Alert on LOLBin usage (systeminfo, ipconfig, reg query)

### Persistence
- Detect new domain account creation via Event 4720
- Monitor additions to Domain Admins group (Event 4728)
- Alert on AnyDesk service installation
- Detect USER_DONT_EXPIRE_PASSWORD attribute setting

### Discovery
- Monitor SoftPerfect Network Scanner execution (ca387a8e-1c84-4da3-9993-028b45342d30)
- Alert on netscan.exe spawning mstsc.exe
- Detect NetExec (nxc.exe) SMB enumeration activity
- Monitor delete[.]me file creation on shares (share enumeration)

### Lateral Movement
- Monitor RDP connections between servers (not user workstations)
- Alert on RDP from beachhead host to critical infrastructure (DCs, hypervisors)
- Detect use of newly created accounts for authentication

### Collection/Exfiltration
- Monitor 7-Zip usage compressing network share data
- Detect large file uploads to temporary file-sharing services
- Alert on outbound traffic to temp.sh

### Impact
- Monitor Veeam backup job deletion events
- Detect ransomware process execution (w.exe)
- Alert on --mode fast, --noprint command line arguments

---

## Diamond Model Analysis

**Adversary:** Threat actor with access to compromised domain admin credentials, likely through Initial Access Broker or infostealer malware. Operated from bulletproof hosting infrastructure (Virtualine/Railnet LLC).

**Capability:** 
- SoftPerfect Network Scanner v7.2.7 with paid license
- NetExec (nxc.exe) for SMB enumeration
- 7-Zip for data compression
- Lynx ransomware (w.exe)
- Look-alike domain account creation
- Veeam backup manipulation

**Infrastructure:**
- Primary: 195.211.190.189, DESKTOP-BUL6K1U (Railnet LLC)
- Secondary: 77.90.153.30, DESKTOP-BUL6K1U (Railnet LLC)
- Exfiltration: temp.sh
- AnyDesk installed but not utilized

**Victim:** Organization with Windows Active Directory environment, Hyper-V virtualization infrastructure, Veeam backup solution, and internet-exposed RDP endpoint.

---

## Recommendations

1. **Disable Internet-Facing RDP** - Move RDP behind VPN or implement Network Level Authentication with MFA. RDP should not be directly exposed to the internet.

2. **Implement Credential Monitoring** - Deploy infostealer detection and monitor for credential compromise through threat intelligence feeds. Consider credential monitoring services.

3. **Enhance Lateral Movement Detection** - Implement strict network segmentation between beachhead hosts, domain controllers, hypervisors, and backup infrastructure. Monitor for RDP between server classes.

4. **Hardening Active Directory** - Implement Protected Users group for privileged accounts. Enable monitoring for new account creation and group membership changes. Implement Password Never Expires alerts.

5. **Backup Security** - Isolate backup infrastructure from production network. Implement immutable backups. Monitor Veeam console for deletion activities.

6. **Network Monitoring** - Deploy detection for network scanning tools (SoftPerfect, NetExec). Monitor for unusual port scanning and share enumeration activities.

7. **Application Allowlisting** - Prevent execution of unauthorized tools like netscan.exe, nxc.exe, and unknown executables (w.exe).

8. **Threat Intelligence Integration** - Monitor for Railnet LLC/Virtualine infrastructure. Block known bulletproof hosting IP ranges.

---

## Detailed MITRE ATT&CK Technique Descriptions from Framework

### T1133 - External Remote Services
**Description:** Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations.

**Report Evidence:** Initial access via RDP to internet-exposed system from 195.211.190.189. No brute force detected, indicating pre-compromised credentials.

---

### T1078 - Valid Accounts
**Description:** Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network.

**Report Evidence:** Two sets of valid credentials used - initial beachhead access and domain admin for lateral movement. No credential dumping observed, indicating credentials obtained prior to intrusion.

---

### T1021.001 - Remote Desktop Protocol
**Description:** Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.

**Report Evidence:** All lateral movement performed via RDP - to domain controllers (Day 1), hypervisors (Day 2, 6, 8), and backup servers (Day 9). Logon Type 3 (Network) and Type 7 (Unlock) observed.

---

### T1059.003 - Command and Scripting Interpreter: Windows Command Shell
**Description:** Adversaries may abuse the Windows command shell for execution. The Windows command shell (cmd) is the primary command prompt on Windows systems.

**Report Evidence:** Extensive use of cmd.exe for discovery commands: ipconfig, route print, systeminfo, ping, net user, reg query. All executed via RDP sessions.

---

### T1136.002 - Create Account: Domain Account
**Description:** Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services.

**Report Evidence:** Three look-alike accounts created via dsa.msc: "administratr", "Lookalike 1", "Lookalike 2". Passwords set to never expire. Accounts mimicked existing domain accounts.

---

### T1098.007 - Account Manipulation: Additional Domain Groups
**Description:** An adversary may add additional local or domain groups to an adversary-controlled account to maintain persistent access to a system or domain.

**Report Evidence:** "administratr" and "Lookalike 1" added to Domain Admins group. "administratr" also added to Group Policy Creator Owners. "Lookalike 2" added to domain-specific privileged group.

---

### T1543.003 - Create or Modify System Process: Windows Service
**Description:** Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.

**Report Evidence:** AnyDesk installed as service on domain controller for persistence. Service not utilized during observed intrusion.

---

### T1046 - Network Service Discovery
**Description:** Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.

**Report Evidence:** SoftPerfect Network Scanner v7.2.7 configured to scan full IP range with custom port scanning. NetExec used for SMB enumeration across /24 subnet.

---

### T1560.001 - Archive Collected Data: Archive via Utility
**Description:** Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport.

**Report Evidence:** 7-Zip (7zG.exe) used via Windows Explorer context menu to archive network share contents. Archives saved to Desktop folder.

---

### T1567 - Exfiltration Over Web Service
**Description:** Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel.

**Report Evidence:** Files exfiltrated to temp.sh temporary file-sharing service via Microsoft Edge browser. Multiple /upload URI accesses correlated with archive count.

---

### T1486 - Data Encrypted for Impact
**Description:** Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.

**Report Evidence:** Lynx ransomware (w.exe) deployed on backup and file servers. Executed with parameters: `--dir E:\ --mode fast --verbose --noprint`. Encrypted 5% of files in fast mode.

---

### T1490 - Inhibit System Recovery
**Description:** Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.

**Report Evidence:** Veeam Backup & Replication console accessed. Backup jobs deleted from configuration database. Veeam logs confirm job deletion events.

---

## Full Attack Chain Summary

| Phase | Technique | Sub-Technique | Report Section |
|-------|-----------|---------------|----------------|
| Initial Access | T1133 | - | RDP to internet-facing server |
| Initial Access | T1078 | - | Valid compromised credentials |
| Execution | T1059.003 | - | cmd.exe commands |
| Execution | T1059.001 | - | PowerShell |
| Persistence | T1136.002 | Domain Account | Look-alike accounts created |
| Persistence | T1543.003 | Windows Service | AnyDesk installed |
| Privilege Escalation | T1098.007 | Additional Groups | Domain Admin assignment |
| Discovery | T1046 | - | SoftPerfect Network Scanner |
| Discovery | T1135 | - | Share scanning |
| Discovery | T1018 | - | Remote system discovery |
| Discovery | T1016 | - | ipconfig, route print |
| Discovery | T1082 | - | systeminfo |
| Discovery | T1012 | - | Registry queries |
| Lateral Movement | T1021.001 | RDP | All pivoting via RDP |
| Collection | T1560.001 | Archive via Utility | 7-Zip compression |
| Exfiltration | T1567 | - | temp.sh upload |
| Command and Control | T1219 | - | AnyDesk (not used) |
| Impact | T1486 | - | Lynx ransomware |
| Impact | T1490 | - | Veeam backup deletion |

---

## MITRE ATT&CK Matrix Visualization

```
INITIAL ACCESS       EXECUTION          PERSISTENCE
┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│ T1133          │   │ T1059.003      │   │ T1136.002      │
│ External       │   │ Windows        │   │ Domain Account │
│ Remote Services│   │ Command Shell  │   │                │
├────────────────┤   ├────────────────┤   ├────────────────┤
│ T1078          │   │ T1059.001      │   │ T1543.003      │
│ Valid Accounts │   │ PowerShell     │   │ Windows Service│
└────────────────┘   └────────────────┘   └────────────────┘

DISCOVERY          LATERAL MOVEMENT   COLLECTION
┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│ T1046          │   │ T1021.001      │   │ T1560.001      │
│ Network        │   │ RDP            │   │ Archive via    │
│ Service Disc   │   │                │   │ Utility        │
├────────────────┤   ├────────────────┤   └────────────────┘
│ T1135          │   │                │   
│ Network Share  │   │                │   
│ Discovery      │   │                │   
├────────────────┤   └────────────────┘   
│ T1018          │                        
│ Remote System  │                        
│ Discovery      │                        
├────────────────┤                        
│ T1016          │                        
│ Network Config │                        
├────────────────┤                        
│ T1082          │                        
│ System Info    │                        
├────────────────┤                        
│ T1012          │                        
│ Query Registry │                        
└────────────────┘

EXFILTRATION       COMMAND & CONTROL  IMPACT
┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│ T1567          │   │ T1219          │   │ T1486          │
│ Web Service    │   │ Remote Access  │   │ Data Encrypted │
│                │   │ Software       │   │ for Impact     │
└────────────────┘   └────────────────┘   ├────────────────┤
                                          │ T1490          │
                                          │ Inhibit System │
                                          │ Recovery       │
                                          └────────────────┘
```

---

## Analysis Complete

**Analysis saved to:** `/home/chris/MITRE/temp/lynx_ransomware_analysis.md`

**Key Findings:**
1. **Credential Compromise Pre-Entry:** No brute force or credential stuffing observed - threat actor possessed valid RDP and domain admin credentials before intrusion, likely via Initial Access Broker or infostealer
2. **Extended Dwell Time:** 178 hours (9 days) from initial access to ransomware deployment, with significant pause between Days 2-6
3. **Infrastructure Attribution:** Both C2 IPs (195.211.190.189, 77.90.153.30) hosted on Railnet LLC, identified as front for Virtualine bulletproof hosting provider
4. **Sophisticated Persistence:** Created look-alike domain accounts with non-expiring passwords and privileged group membership
5. **Backup Targeting:** Deliberate deletion of Veeam backup jobs before ransomware deployment to inhibit recovery

**MITRE Data Source:** `/home/chris/MITRE/mitre_attack_repo/data/attack-pattern/`

**Report Source:** https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/
**Analysis Date:** 2026-04-07
