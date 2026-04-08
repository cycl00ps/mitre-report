# Report to MITRE ATT&CK Mapping - Analysis Methodology

## Overview

This document describes the methodology for analyzing DFIR (Digital Forensics and Incident Response) reports and mapping the observed threat actor activities to MITRE ATT&CK framework techniques.

## Prerequisites

1. **MITRE ATT&CK Repository** - Local clone of MITRE ATT&CK data:
   ```
   ATTACK/data/attack-pattern/
   ```

2. **Report URL** - The report to analyze (e.g., from thedfirreport.com)

3. **Temp Directory** - Working directory for analysis output:
   ```
   temp/
   ```

## Step-by-Step Methodology

### Step 1: Fetch and Parse the DFIR Report

1. Use web fetch to retrieve the full report content
2. Extract key sections:
   - **Initial Access** - How the threat actor gained entry
   - **Execution** - Commands, scripts, payloads run
   - **Persistence** - Mechanisms to maintain access
   - **Privilege Escalation** - Methods to gain higher privileges
   - **Defense Evasion** - Techniques to avoid detection
   - **Credential Access** - How credentials were obtained
   - **Discovery** - Reconnaissance activities
   - **Lateral Movement** - How they moved through the network
   - **Command and Control** - C2 infrastructure and protocols
   - **Impact** - Final objectives (ransomware, data theft, etc.)

3. Extract specific evidence:
   - CVE numbers (e.g., CVE-2023-46604)
   - Tool names (e.g., Metasploit, AnyDesk, LockBit)
   - Commands executed (e.g., `getsystem`, `net group`)
   - File names and hashes
   - Network indicators (IPs, ports, domains)
   - Event IDs (e.g., Sysmon 1, 11, 4688)

### Step 2: Map Activities to MITRE ATT&CK Techniques

For each activity identified, follow this process:

1. **Identify the Tactic** - Which phase of the attack does this represent?
   - Initial Access, Execution, Persistence, Privilege Escalation,
     Defense Evasion, Credential Access, Discovery, Lateral Movement,
     Command and Control, Impact

2. **Find the Technique** - Search the MITRE data for matching techniques:
   ```bash
   grep -r "Technique Name" ATTACK/data/attack-pattern/
   ```

3. **Verify the Match** - Read the technique description to confirm it matches the observed activity

4. **Record Evidence** - Document the specific evidence from the report that supports this mapping

### Step 3: Extract MITRE Framework Data

For each mapped technique, retrieve the official MITRE data:

```bash
# Find the technique directory
grep -rl "T1190$" ATTACK/data/attack-pattern/*/attack-pattern--*.md

# Read the technique description
cat ATTACK/data/attack-pattern/<uuid>/<uuid>.md
```

### Step 4: Document the Analysis

Create a markdown report following the **Output Format** section below.

## Output Format

The analysis output must follow this exact structure:

```markdown
# <Report Title> - MITRE ATT&CK Mapping

## Report Analysis Summary

| Field | Value |
|-------|-------|
| **Incident** | Brief description |
| **Time to Ransomware** | If applicable |
| **Threat Actor** | Assessment |
| **C2 Infrastructure** | IPs, domains, ports |

---

## MITRE ATT&CK Technique Mapping

### <TACTIC NAME>

| Technique ID | Technique Name | Evidence from Report |
|--------------|----------------|---------------------|
| **T####** | Technique Name | Specific evidence |

**MITRE Data Location:** `ATTACK/data/attack-pattern/<uuid>/`

---

[Repeat for each tactic]

---

## Campaign Timeline Mapping

```
Day 1                    Day X                    Day Y
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ T#### - Action  │     │ T#### - Action  │     │ T#### - Action  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

---

## Key Indicators of Compromise (IOCs)

| Type | Value | MITRE Context |
|------|-------|---------------|
| IP | x.x.x.x | C2 (T####) |
| File | name.exe | Malware (T####) |

---

## Detection Opportunities by Tactic

### <Tactic>
- Detection rule 1
- Detection rule 2

---

## Diamond Model Analysis

**Adversary:** Description  
**Capability:** Tools/techniques used  
**Infrastructure:** C2 details  
**Victim:** Target description

---

## Recommendations

1. **Recommendation 1** - Description
2. **Recommendation 2** - Description

---

## Detailed MITRE ATT&CK Technique Descriptions from Framework

### T#### - Technique Name
**Description:** Official MITRE description

**Report Evidence:** How this was observed in the report

---

[Repeat for key techniques]

---

## Full Attack Chain Summary

| Phase | Technique | Sub-Technique | Report Section |
|-------|-----------|---------------|----------------|
| Initial Access | T1190 | - | CVE-2023-46604 |

---

## MITRE ATT&CK Matrix Visualization

```
INITIAL ACCESS     EXECUTION          PERSISTENCE
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ T####        │   │ T####        │   │ T####        │
│ Name         │   │ Name         │   │ Name         │
└──────────────┘   └──────────────┘   └──────────────┘
```

---

## Analysis Complete

**Analysis saved to:** `<path>`

**Key Findings:**
1. Finding 1
2. Finding 2
3. Finding 3

**MITRE Data Source:** `<path to mitre repo>`
```

## Common Technique Mappings

| Activity | Technique ID | Technique Name |
|----------|--------------|----------------|
| Exploit internet-facing server | T1190 | Exploit Public-Facing Application |
| Run commands via cmd.exe | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| Run PowerShell scripts | T1059.001 | Command and Scripting Interpreter: PowerShell |
| Dump LSASS memory | T1003.001 | OS Credential Dumping: LSASS Memory |
| RDP lateral movement | T1021.001 | Remote Services: Remote Desktop Protocol |
| SMB lateral movement | T1021.002 | Remote Services: SMB/Windows Admin Shares |
| Clear event logs | T1070.001 | Indicator Removal: Clear Windows Event Logs |
| Disable antivirus | T1562.001 | Impair Defenses: Disable or Modify Tools |
| Install remote access tool | T1219 | Remote Access Software |
| Ransomware encryption | T1486 | Data Encrypted for Impact |
| Use non-standard C2 port | T1571 | Non-Standard Port |
| Process injection | T1055 | Process Injection |
| Create persistence service | T1543.003 | Create or Modify System Process: Windows Service |
| Exploit for privilege escalation | T1068 | Exploitation for Privilege Escalation |
| Network scanning | T1083 | File and Directory Discovery |
| Account discovery | T1087.002 | Account Discovery: Domain Account |
| Lateral file transfer | T1570 | Lateral Tool Transfer |

## Tips and Best Practices

1. **Be Specific** - Always cite the exact evidence from the report (file names, commands, event IDs)

2. **Verify Techniques** - Don't assume; read the MITRE technique description to confirm the match

3. **Include Sub-techniques** - When applicable, use the full technique ID (e.g., T1059.003 instead of just T1059)

4. **Document Uncertainty** - If a mapping is an assessment rather than confirmed, note it as "assessed" or "likely"

5. **Cross-reference** - Use the report's own MITRE ATT&CK matrix if provided, but verify against the framework data

6. **Include Timeline** - Map techniques to the attack timeline to show progression

7. **Add Detection Guidance** - Include specific detection opportunities based on the techniques observed

## Example Commands for Analysis

```bash
# Search for a specific technique
grep -r "T1190" ATTACK/data/attack-pattern/

# List all attack patterns
ls ATTACK/data/attack-pattern/

# Read a specific technique
cat ATTACK/data/attack-pattern/<uuid>/<uuid>.md

# Create output file
cat > temp/<report-name>_analysis.md << 'EOF'
```

## File Locations

| Item | Path |
|------|------|
| MITRE ATT&CK Data | `ATTACK/data/` |
| Attack Patterns | `ATTACK/data/attack-pattern/` |
| Temp/Output Directory | `temp/` |
| This Methodology | `ATTACK_REPORT_METHOD.md` |

---

**Last Updated:** 2026-04-07  
**Author:** Analysis Team  
**Version:** 1.1
