# ThreatLens-Kali

ThreatLens-Kali is a modular threat detection and incident triage toolkit built for Kali Linux.

It ingests logs and suspicious text artifacts, extracts indicators of compromise (IOCs), applies YAML-based detection rules, maps findings to MITRE ATT&CK, scores severity, and generates analyst-friendly Markdown and HTML reports.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-orange)

---

## Why This Project

This project is designed as a blue-team portfolio repo to demonstrate:

- Detection engineering
- Log analysis
- IOC extraction
- MITRE ATT&CK mapping
- Incident triage
- Security reporting automation

---

## Features

- Parse authentication, web, and generic text logs
- Extract IPs, domains, hashes, URLs, and email artifacts
- Run YAML-based detection rules
- Assign severity scores (low, medium, high, critical)
- Map detections to MITRE ATT&CK techniques
- Generate Markdown and HTML investigation reports
- Modular architecture for easy extension

---

## Project Structure

```
ThreatLens-Kali/
├── threatlens.py              # Main entry point
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
├── src/
│   ├── parsers.py            # Log and text parsers
│   ├── ioc_extractor.py      # IOC extraction (IPs, domains, hashes, URLs)
│   ├── detection_engine.py   # YAML rule engine
│   ├── mitre_mapper.py       # MITRE ATT&CK technique mapping
│   └── reporting.py          # Markdown and HTML report generation
├── config/
│   └── rules/
│       └── sample_rules.yml  # Sample detection rules
├── sample_logs/
│   ├── auth.log              # Sample authentication log
│   └── http_access.log       # Sample HTTP access log
├── reports/                   # Generated investigation reports
├── docs/
│   └── case-study.md         # Project case study
└── tests/
    └── test_smoke.py         # Basic smoke tests
```

---

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Kali Linux (recommended) or any Linux distribution

### Installation

```bash
# Clone the repository
git clone https://github.com/gauravmalhotra3300-hub/threatlens-kali.git
cd threatlens-kali

# Install dependencies
pip3 install -r requirements.txt
```

### Usage

```bash
# Analyze a single log file
python3 threatlens.py --input sample_logs/auth.log --output reports/

# Analyze with verbose output
python3 threatlens.py --input sample_logs/auth.log --output reports/ --verbose

# Analyze with custom rules file
python3 threatlens.py --input sample_logs/auth.log --output reports/ --rules config/rules/sample_rules.yml
```

---

## Detection Rules

Detection rules are defined in YAML format. Here is an example:

```yaml
rules:
  - name: Suspicious PowerShell Encoded Command
    match: "powershell -enc"
    severity: high
    mitre: T1059.001
    description: "Detects encoded PowerShell execution attempts"

  - name: Repeated Failed Authentication
    match: "failed password"
    severity: medium
    mitre: T1110
    description: "Detects multiple failed authentication attempts"

  - name: Suspicious Curl or Wget Download
    match: "curl http" OR "wget http"
    severity: medium
    mitre: T1105
    description: "Detects suspicious file downloads"
```

---

## Severity Scoring

| Score | Level    | Description                                    |
|-------|----------|------------------------------------------------|
| 1     | Low      | Informational findings with minimal risk       |
| 2     | Medium   | Suspicious activity requiring investigation    |
| 3     | High     | Likely malicious activity requiring response   |
| 4     | Critical | Confirmed malicious activity, immediate action |

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name                  | Rule Example                    |
|--------------|----------------------------------|----------------------------------|
| T1059.001    | Command and Scripting Interpreter: PowerShell | Suspicious PowerShell Encoded Command |
| T1110        | Brute Force                     | Repeated Failed Authentication    |
| T1105        | Ingress Tool Transfer           | Suspicious Curl/Wget Download     |
| T1078        | Valid Accounts                  | Unusual Login Time/Location       |
| T1190        | Exploit Public-Facing Application | Suspicious HTTP Requests          |

---

## Sample Output

```
[INFO] ThreatLens-Kali starting analysis...
[INFO] Loaded 1 log file(s)
[INFO] Extracted 15 IOCs: 4 IPs, 3 domains, 2 URLs, 1 hash
[INFO] Running detection rules...
[ALERT] HIGH - Suspicious PowerShell Encoded Command (T1059.001)
[ALERT] MEDIUM - Repeated Failed Authentication (T1110)
[INFO] Mapping detections to MITRE ATT&CK...
[INFO] Generating report: reports/report_20260421_120000.md
[INFO] Analysis complete. 2 detection(s) found.
```

---

## Roadmap

- [x] Core log parsing and IOC extraction
- [x] YAML-based detection rule engine
- [x] MITRE ATT&CK mapping
- [x] Markdown report generation
- [ ] HTML styled report generation
- [ ] Sigma rule format support
- [ ] Batch directory scanning
- [ ] JSON and CSV export
- [ ] Risk scoring improvements
- [ ] Unit test coverage
- [ ] Sample investigation packs

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Author

**Gaurav Malhotra**  
Cybersecurity Professional | Detection Engineering | Incident Response  

- GitHub: [@gauravmalhotra3300-hub](https://github.com/gauravmalhotra3300-hub)
- LinkedIn: [Gaurav Malhotra](https://linkedin.com/in/gauravmalhotra)

---

## Related Projects

- [PhishGuard](https://github.com/gauravmalhotra3300-hub/phishguard) - Phishing detection toolkit
- [PenTest-Scripts](https://github.com/gauravmalhotra3300-hub/pentest-scripts) - Penetration testing scripts collection

---

*Built with Kali Linux and Python. Designed for blue-team security operations.*
