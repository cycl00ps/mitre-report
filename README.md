# MITRE ATT&CK Report Analyzer

A methodology and tooling for analyzing DFIR (Digital Forensics and Incident Response) reports and mapping observed threat actor activities to the MITRE ATT&CK framework.

> **Prerequisite:** This project assumes you already have opencode installed and running with web fetch capabilities enabled.

## Overview

This project provides:
- A systematic methodology for mapping DFIR reports to MITRE ATT&CK techniques
- Scripts to sync and maintain local MITRE ATT&CK data
- Example analyses demonstrating the methodology in practice

## Project Structure

```
mitre-report/
├── ATTACK/                                       # MITRE ATT&CK data synchronization
│   ├── sync_mitre.py                             # Python script to fetch MITRE data
│   ├── update.sh                                 # Bash wrapper for sync script
│   ├── requirements.txt                          # Python dependencies
│   └── data/                                     # Local MITRE ATT&CK data (generated on first run)
├── examples/                                     # Example analyses
│   ├── EXAMPLE-PROMPT.md                         # Example prompts to trigger analysis
│   └── reports/                                  # Source report storage
│       ├── activemq_lockbit_analysis.md
│       ├── lunar_spider_analysis.md
│       ├── lynx_ransomware_analysis.md
│       └── qilin_ransomware_mitre_analysis.md
├── ATTACK_REPORT_METHOD.md                       # Detailed analysis methodology
└── LICENSE
```

## Getting Started

### Step 1: Initialize MITRE ATT&CK Data

```bash
cd ATTACK
./update.sh
```

This creates a Python virtual environment, installs dependencies, and fetches the latest MITRE ATT&CK CTI data.

### Step 2: Verify Setup

```bash
ls ATTACK/data/attack-pattern/
```

You should see directories for each attack pattern (e.g., `attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c/`).

### Step 3: Analyze Your First Report

1. Identify a DFIR report URL (e.g. from thedfirreport.com)
2. Start opencode with web fetch enabled from inside the root project folder
3. Use one of the example prompts to trigger an analysis`
   -  Review examples in `examples/` for reference

#### Example Query

```
Using the instructions in ATTACK_REPORT_METHOD.md, produce a report for:
- https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/
```


## Usage

### How analysis works

1. **Fetchs the report** using opencode's web fetch capability
2. **Extract key activities** from each attack phase:
   - Initial Access, Execution, Persistence, Privilege Escalation
   - Defense Evasion, Credential Access, Discovery
   - Lateral Movement, Command and Control, Impact
3. **Map to MITRE techniques** using the local data in `ATTACK/data/`
4. **Document evidence** with specific IOCs, commands, and event IDs
5. **Generate output** following the template in `ATTACK_REPORT_METHOD.md`


### Quick Reference: Common Technique Mappings

| Activity | Technique ID | Technique Name |
|----------|--------------|----------------|
| Exploit public-facing app | T1190 | Exploit Public-Facing Application |
| Command shell execution | T1059.003 | Windows Command Shell |
| PowerShell execution | T1059.001 | PowerShell |
| LSASS dumping | T1003.001 | OS Credential Dumping: LSASS Memory |
| RDP lateral movement | T1021.001 | Remote Desktop Protocol |
| SMB lateral movement | T1021.002 | SMB/Windows Admin Shares |
| Clear event logs | T1070.001 | Clear Windows Event Logs |
| Disable antivirus | T1562.001 | Disable or Modify Tools |
| Ransomware encryption | T1486 | Data Encrypted for Impact |
| Remote access software | T1219 | Remote Access Software |

*See `ATTACK_REPORT_METHOD.md` for the complete technique mapping table.*

## Output Examples

See the `examples/reports` directory for completed analyses:
- **activemq_lockbit_analysis.md** - Apache ActiveMQ CVE-2023-46604 exploitation
- **lunar_spider_analysis.md** - Lunar Spider threat actor campaign
- **lynx_ransomware_analysis.md** - Lynx ransomware attack chain
- **qilin_ransomware_mitre_analysis.md** - Qilin ransomware EDR analysis

## Methodology Reference

The complete step-by-step methodology is documented in [`ATTACK_REPORT_METHOD.md`](ATTACK_REPORT_METHOD.md), including:
- Report parsing guidelines
- Technique mapping process
- Output format templates
- Detection opportunities
- Diamond Model analysis
- Best practices and tips

## Maintenance

### Updating MITRE ATT&CK Data

```bash
cd ATTACK
./update.sh
```

Fetches the latest MITRE CTI data and regenerates the local data files.

## License

See [LICENSE](LICENSE) file for details.

## Contributing

When adding new analyses:
1. Follow the output format in `ATTACK_REPORT_METHOD.md`
2. Include specific evidence from source reports (commands, hashes, event IDs)
3. Verify technique mappings against MITRE framework data
4. Document uncertainty where mappings are assessed rather than confirmed
5. Include sub-techniques when applicable (e.g., T1059.003 not just T1059)
