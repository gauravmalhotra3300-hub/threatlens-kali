# ThreatLens-Kali

ThreatLens-Kali is a modular threat detection and incident triage toolkit built for Kali Linux.

It ingests logs and suspicious text artifacts, extracts indicators of compromise (IOCs), applies YAML-based detection rules, maps findings to MITRE ATT&CK, scores severity, and generates analyst-friendly Markdown and HTML reports.

![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-orange)

## Why This Project

This project is designed as a blue-team portfolio repo to demonstrate:
* Detection engineering
* Log analysis
* IOC extraction
* MITRE ATT&CK mapping
* Incident triage
* Security reporting automation

## Features

* Parse authentication, web, and generic text logs
* Extract IPs, domains, hashes, URLs, and email artifacts
* Run YAML-based detection rules
* Assign severity scores (low, medium, high, critical)
* Map detections to MITRE ATT&CK techniques
* Generate Markdown and HTML investigation reports
* Modular architecture for easy extension

## Project Structure

```
ThreatLens-Kali/
├── threatlens.py           # Main entry point
├── requirements.txt        # Python dependencies
├── README.md              # Project documentation
├── src/
│   ├── parsers.py         # Log and text parsers
│   ├── ioc_extractor.py   # IOC extraction (IPs, domains, hashes, URLs)
│   ├── detection_engine.py # YAML rule engine
│   ├── mitre_mapper.py    # MITRE ATT&CK technique mapping
│   └── reporting.py       # Markdown and HTML report generation
├── config/
│   └── rules/
│       └── sample_rules.yml # Sample detection rules
├── sample_logs/
│   └── auth.log           # Sample authentication log
├── docs/
│   └── case-study.md      # Project case study
└── reports/               # Generated investigation reports (created on first run)
```

## Quick Start

### Prerequisites
* Python 3.8 or higher
* Kali Linux (recommended) or any Linux distribution

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

# Generate HTML report in addition to Markdown
python3 threatlens.py --input sample_logs/auth.log --output reports/ --html
```

## Detection Rules

Detection rules are defined in YAML format. Example:

```yaml
rules:
  - name: "Suspicious PowerShell Encoded Command"
    match: "powershell -enc"
    severity: high
    mitre: T1059.001
    description: "Detects encoded PowerShell execution attempts"
  - name: "Repeated Failed Authentication"
    match: "failed password"
    severity: medium
    mitre: T1110
    description: "Detects multiple failed authentication attempts"
  - name: "Suspicious Curl or Wget Download"
    match: "curl http"
    severity: medium
    mitre: T1105
    description: "Detects suspicious file downloads"
```

## Severity Scoring

| Score | Level    | Description |
|-------|----------|-------------|
| 1     | Low      | Informational findings with minimal risk |
| 2     | Medium   | Suspicious activity requiring investigation |
| 3     | High     | Likely malicious activity requiring response |
| 4     | Critical | Confirmed malicious activity, immediate action |

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Rule Example |
|--------------|----------------|--------------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Suspicious PowerShell Encoded Command |
| T1110 | Brute Force | Repeated Failed Authentication |
| T1105 | Ingress Tool Transfer | Suspicious Curl/Wget Download |
| T1078 | Valid Accounts | Unusual Login Time/Location |
| T1190 | Exploit Public-Facing Application | Suspicious HTTP Requests |

## Sample Output

```
[INFO] ThreatLens-Kali starting analysis...
[INFO] Loading input file: sample_logs/auth.log
[INFO] Extracting indicators of compromise (IOCs)...
[INFO] Extracted 8 IOCs: 3 IPs, 0 domains, 0 URLs, 0 hashes
[INFO] Running detection rules...
[ALERT] HIGH - Keyword match: failed password
[ALERT] MEDIUM - Keyword match: invalid user
[ALERT] HIGH - Keyword match: unauthorized
[INFO] Mapping detections to MITRE ATT&CK...
[INFO] Generating reports...
[INFO] Markdown report generated: reports/report_20260421_120000.md

==================================================
[INFO] Analysis complete.
[INFO] Total IOCs found: 8
[INFO] Total detections: 3
==================================================
```

## Roadmap

- [x] Core log parsing and IOC extraction
- [x] YAML-based detection rule engine
- [x] MITRE ATT&CK mapping
- [x] Markdown report generation
- [x] HTML report generation
- [ ] Sigma rule format support
- [ ] Batch directory scanning
- [ ] JSON and CSV export
- [ ] Risk scoring improvements
- [ ] Unit test coverage
- [ ] Sample investigation packs

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

**Gaurav Malhotra**  
Cybersecurity Professional | Detection Engineering | Incident Response

* GitHub: [@gauravmalhotra3300-hub](https://github.com/gauravmalhotra3300-hub)
* LinkedIn: [Gaurav Malhotra](https://linkedin.com/in/gauravmalhotra)

## Related Projects

* [Phishing Detector](https://github.com/gauravmalhotra3300-hub/phishing-detector) - Automated Python tool for URL and email phishing analysis
* [SentinelShield](https://github.com/gauravmalhotra3300-hub/SentinelShield) - Advanced Intrusion Detection & Web Protection System
* [Payload Encoder & Obfuscation Framework](https://github.com/gauravmalhotra3300-hub/payload-encoder-obfuscation-framework) - Payload encoding and obfuscation techniques for evasion testing

Built with Kali Linux and Python. Designed for blue-team security operations.
