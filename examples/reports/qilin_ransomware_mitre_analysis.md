# Qilin Ransomware - MITRE ATT&CK Mapping

## Report Analysis Summary

| Field | Value |
|-------|-------|
| **Incident** | Qilin ransomware operations targeting Japan with sophisticated EDR killer malware |
| **Time to Ransomware** | Average 6 days after initial compromise |
| **Threat Actor** | Qilin ransomware group (post-Soviet nexus) |
| **C2 Infrastructure** | Not explicitly disclosed; uses stolen credentials for access |
| **Target Region** | Japan (134 ransomware incidents in 2025, 22 attributed to Qilin) |
| **Primary Sectors** | Manufacturing (28%), Automotive (8%), Trading (7%), IT (6%), Education (5%) |

---

## MITRE ATT&CK Technique Mapping

### INITIAL ACCESS

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1078** | Valid Accounts | Qilin primarily relies on stolen credentials obtained from platforms like Telegram, Breach Forums to gain initial access |
| **T1133** | External Remote Services | Uses compromised credentials to access remote services for initial network entry |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--6151cbea-819b-455a-9fa6-99a1cc58797d/`

---

### DEFENSE EVASION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1562** | Impair Defenses | EDR killer disables over 300 different EDR drivers across multiple vendors |
| **T1562.001** | Disable or Modify Tools | Terminates EDR processes including Windows Defender; unregisters EDR monitoring callbacks |
| **T1205** | Traffic Signaling | SEH/VEH-based obfuscation to evade detection |
| **T1027** | Obfuscated Files or Information | Multi-stage encrypted payload delivery; SEH/VEH control flow obfuscation |
| **T1620** | Reflective Code Loading | In-memory PE loading via VEH-triggered execution; shell32.dll overwriting technique |
| **T1564** | Hide Artifacts | Geo-fencing to avoid post-Soviet countries; memory mapping techniques to hide RWX regions |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d/`

---

### EXECUTION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1055** | Process Injection | VEH-based code execution; DLL side-loading via msimg32.dll |
| **T1055.011** | Process Injection: Additional Process | PE loader injects into legitimate application process space |
| **T1659** | Content Injection | IAT hooking to redirect ExitProcess to Stage 3 execution |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298/`

---

### PERSISTENCE

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1547** | Boot or Logon Autostart Execution | DLL side-loading via legitimate application imports |
| **T1543.003** | Create or Modify System Process: Windows Service | Loads helper drivers (rwdrv.sys, hlpdrv.sys) for EDR termination |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d/`

---

### PRIVILEGE ESCALATION

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1068** | Exploitation for Privilege Escalation | BYOVD (Bring Your Own Vulnerable Driver) using ThrottleStop.sys (rwdrv.sys) |
| **T1548** | Abuse Elevation Control Mechanism | EDR killer requires administrative privileges to load kernel drivers |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d/`

---

### CREDENTIAL ACCESS

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1552** | Unsecured Credentials | Credentials obtained from breach forums, Telegram for initial access |

---

### DISCOVERY

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1082** | System Information Discovery | Windows version detection via PEB-based lookup |
| **T1087** | Account Discovery | Network reconnaissance for lateral movement preparation |

---

### IMPACT

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T1486** | Data Encrypted for Impact | Qilin ransomware encryption after EDR disablement |
| **T1489** | Service Stop | EDR process termination (Windows Defender, etc.) |
| **T1490** | Inhibit System Recovery | Shadow copy deletion preparation before encryption |

**MITRE Data Location:** `/data/attack-pattern/attack-pattern--20fb2507-d71c-455d-9b6d-6104461cf26b/`

---

## Campaign Timeline Mapping

```
Day 1 (Initial Access)              Day 2-5 (Post-Compromise)         Day 6 (Impact)
┌─────────────────────────┐        ┌─────────────────────────┐        ┌─────────────────────────┐
│ T1078 - Valid Accounts  │        │ T1562 - Impair Defenses │        │ T1486 - Data Encrypted  │
│ Stolen credentials from │        │ EDR killer deployment   │        │ for Impact            │
│ breach forums/Telegram  │        │ - msimg32.dll side-load │        │ Ransomware execution  │
│                         │        │ - SEH/VEH obfuscation   │        │                       │
│                         │        │ - BYOVD driver loading  │        │                       │
└─────────────────────────┘        └─────────────────────────┘        └─────────────────────────┘
         |                                      |                              |
         v                                      v                              v
   T1133 - External                        T1055 -                          T1489 - Service
   Remote Services                        Process Injection                 Stop
```

---

## Key Indicators of Compromise (IOCs)

| Type | Value | MITRE Context |
|------|-------|---------------|
| File | msimg32.dll | T1055 - DLL side-loading loader |
| MD5 | 89ee7235906f7d12737679860264feaf | T1055 - Malicious loader |
| SHA256 | 7787da25451f5538766240f4a8a2846d0a589c59391e15f188aa077e8b888497 | T1055 - Malicious loader |
| File | rwdrv.sys | T1068 - BYOVD (ThrottleStop.sys renamed) |
| SHA256 | 16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0 | T1068 - Physical memory access driver |
| File | hlpdrv.sys | T1562.001 - EDR process termination driver |
| SHA256 | bd1f381e5a3db22e88776b7873d4d2835e9a1ec620571d2b1da0c58f81c84a56 | T1562.001 - Process unprotect/terminate |
| File | EDRKiller.exe | T1562 - EDR killer payload |
| SHA256 | 12fcde06ddadf1b48a61b12596e6286316fd33e850687fe4153dfd9383f0a4a0 | T1562 - EDR disabling component |
| Timestamp | 0x684d33f0 (June 14, 2025) | EDRKiller.exe compilation time |

---

## Detection Opportunities by Tactic

### Initial Access
- Monitor for login attempts using credentials from known breach sources
- Alert on authentication from unusual geographic locations
- Detect RDP/VPN access outside normal business hours

### Defense Evasion
- Monitor for DLL side-loading via suspicious module loads (msimg32.dll from non-system paths)
- Alert on SEH/VEH handler registration patterns
- Detect physical memory access via driver IOCTL calls
- Monitor for driver loading from non-standard locations

### Execution
- Detect hardware breakpoint registration on system APIs (NtOpenSection, NtMapViewOfSection)
- Alert on VEH registration followed by DLL loading
- Monitor for IAT hooking patterns (ExitProcess redirection)

### Impact
- Detect mass file encryption patterns
- Monitor for shadow copy deletion commands
- Alert on EDR service termination

---

## Diamond Model Analysis

**Adversary:** Qilin ransomware group - post-Soviet nexus threat actor with sophisticated operational security, evidenced by geo-fencing to avoid targeting former Soviet states. Operators demonstrate mature tradecraft with documented attack playbooks.

**Capability:** Multi-stage EDR killer malware with SEH/VEH obfuscation, BYOVD techniques using signed vulnerable drivers (ThrottleStop.sys), kernel callback manipulation, and ability to disable 300+ EDR solutions. Ransomware deployment with double extortion capabilities.

**Infrastructure:** Stolen credentials distributed via Telegram and breach forums. No dedicated C2 infrastructure explicitly identified; relies on legitimate remote access methods.

**Victim:** Japan-based organizations, primarily manufacturing (28%), automotive (8%), trading (7%), IT (6%), education (5%). SMEs represent 57% of victims. Healthcare/social assistance is a priority vertical due to operational disruption impact.

---

## Recommendations

1. **Credential Hygiene** - Implement MFA across all remote access services; monitor breach forums for exposed credentials; rotate credentials proactively

2. **EDR Resilience** - Deploy EDR solutions with kernel-level protection; implement driver signing enforcement; monitor for vulnerable driver usage (ThrottleStop.sys)

3. **Memory Protection** - Enable Control Flow Guard (CFG); deploy memory integrity solutions; monitor for VEH/SEH abuse patterns

4. **Network Segmentation** - Isolate critical manufacturing/operational technology networks; limit lateral movement pathways

5. **Detection Tuning** - Implement Sigma correlation rules for suspicious command patterns (e.g., net user executed 3+ times in 15 minutes); monitor for off-hours administrative activity

6. **Backup Strategy** - Maintain offline/immutable backups; test restoration procedures; implement rapid recovery capabilities

---

## Detailed MITRE ATT&CK Technique Descriptions from Framework

### T1078 - Valid Accounts
**Description:** Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Valid Accounts can allow adversaries to conceal unauthorized activity and appear to be legitimate users.

**Report Evidence:** Qilin primarily relies on stolen credentials obtained from platforms such as Telegram, Breach Forums, and other online platforms to gain initial access to victim environments.

---

### T1562 - Impair Defenses
**Description:** Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection defenses, such as SIEMs or audit policies.

**Report Evidence:** Qilin deploys sophisticated EDR killer malware capable of disabling over 300 different EDR drivers across multiple vendors. The malware unregisters kernel callbacks for process/thread creation and image loading events.

---

### T1055 - Process Injection
**Description:** Adversaries may inject code into processes in order to evade process-based defenses as well as possibly evade memory scanning. Process injection is a method of executing arbitrary code in the address space of a separate live process.

**Report Evidence:** The malicious msimg32.dll is side-loaded via legitimate application imports. VEH-based execution triggers code injection through hardware breakpoint manipulation on NtOpenSection and NtMapViewOfSection APIs.

---

### T1068 - Exploitation for Privilege Escalation
**Description:** Adversaries may exploit a software vulnerability to attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.

**Report Evidence:** Qilin uses BYOVD technique loading ThrottleStop.sys (renamed to rwdrv.sys) which exposes physical memory access primitives. This allows the malware to read/write kernel memory and manipulate EDR callback structures.

---

### T1486 - Data Encrypted for Impact
**Description:** Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system, network, and organizational resources. This behavior is part of the Impact goal of ransomware.

**Report Evidence:** Qilin ransomware execution occurs approximately 6 days after initial compromise, following EDR disablement and post-compromise reconnaissance activities.

---

### T1620 - Reflective Code Loading
**Description:** Adversaries may load code into memory without writing files to disk. This technique allows adversaries to avoid detection by file-based security controls.

**Report Evidence:** Stage 3 decompresses and loads a PE image entirely in memory. The loader overwrites shell32.dll in memory and uses VEH to trigger execution without disk artifacts.

---

## Full Attack Chain Summary

| Phase | Technique | Sub-Technique | Report Section |
|-------|-----------|---------------|----------------|
| Initial Access | T1078 | Valid Accounts | Stolen credentials from breach forums |
| Initial Access | T1133 | External Remote Services | Remote access via compromised credentials |
| Defense Evasion | T1562 | Impair Defenses | EDR killer deployment |
| Defense Evasion | T1562.001 | Disable or Modify Tools | EDR process termination |
| Defense Evasion | T1027 | Obfuscated Files or Information | SEH/VEH control flow obfuscation |
| Defense Evasion | T1620 | Reflective Code Loading | In-memory PE loading |
| Execution | T1055 | Process Injection | DLL side-loading via msimg32.dll |
| Execution | T1055.011 | Process Injection: Additional Process | VEH-triggered execution |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | BYOVD with ThrottleStop.sys |
| Persistence | T1547 | Boot or Logon Autostart Execution | DLL side-loading persistence |
| Impact | T1486 | Data Encrypted for Impact | Qilin ransomware encryption |
| Impact | T1489 | Service Stop | EDR process termination |

---

## MITRE ATT&CK Matrix Visualization

```
INITIAL ACCESS         EXECUTION            PERSISTENCE
┌────────────────┐    ┌────────────────┐   ┌────────────────┐
│ T1078          │    │ T1055          │   │ T1547          │
│ Valid Accounts │    │ Process        │   │ Boot or Logon  │
│                │    │ Injection      │   │ Autostart      │
└────────────────┘    └────────────────┘   └────────────────┘

PRIVILEGE ESCALATION   DEFENSE EVASION      IMPACT
┌────────────────┐    ┌────────────────┐   ┌────────────────┐
│ T1068          │    │ T1562          │   │ T1486          │
│ Exploitation   │    │ Impair         │   │ Data Encrypted │
│ for Priv Esc   │    │ Defenses       │   │ for Impact     │
│                │    │                │   │                │
│                │    │ T1027          │   │ T1489          │
│                │    │ Obfuscated     │   │ Service Stop   │
│                │    │ Files          │   │                │
└────────────────┘    └────────────────┘   └────────────────┘
```

---

## Analysis Complete

**Analysis saved to:** `/home/chris/MITRE/temp/qilin_ransomware_mitre_analysis.md`

**Key Findings:**
1. Qilin ransomware group demonstrates sophisticated EDR evasion capabilities with multi-stage PE loader using SEH/VEH obfuscation
2. BYOVD technique leverages legitimate signed driver (ThrottleStop.sys) for kernel-level memory access and EDR callback manipulation
3. Average 6-day dwell time between initial compromise and ransomware deployment provides detection window
4. Geo-fencing indicates post-Soviet nexus; targets Japan's manufacturing sector disproportionately
5. Credential theft via breach forums is primary initial access vector

**MITRE Data Source:** `/home/chris/MITRE/mitre_attack_repo/data/attack-pattern/`

**References:**
- https://blog.talosintelligence.com/qilin-edr-killer/
- https://blog.talosintelligence.com/an-overview-of-ransomware-threats-in-japan-in-2025-and-early-detection-insights-from-qilin-cases/
- https://github.com/Cisco-Talos/IOCs/blob/main/2026/04/overview-of-ransomware-threats-in-japan.txt

---

**Report Generated:** 2026-04-07
**Analyst:** Automated MITRE ATT&CK Mapping Tool
**Confidence Level:** High (based on detailed technical analysis from Cisco Talos)
