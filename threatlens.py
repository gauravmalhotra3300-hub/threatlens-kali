#!/usr/bin/env python3
"""
ThreatLens-Kali
Modular threat detection and incident triage toolkit for Kali Linux.

Author: Gaurav Malhotra
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from src.parsers import load_text
from src.ioc_extractor import extract_iocs
from src.detection_engine import run_rules
from src.mitre_mapper import map_to_mitre
from src.reporting import write_markdown_report, write_html_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="ThreatLens-Kali - Threat Detection and Incident Triage Toolkit"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Input log or text file path"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output directory for generated reports"
    )
    parser.add_argument(
        "--rules", "-r",
        default="config/rules/sample_rules.yml",
        help="Path to YAML detection rules file (default: config/rules/sample_rules.yml)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--html", "-H",
        action="store_true",
        help="Generate HTML report in addition to Markdown"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print("[INFO] ThreatLens-Kali starting analysis...")

    # Validate input file
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {args.input}")
        sys.exit(1)

    # Load the input data
    print(f"[INFO] Loading input file: {args.input}")
    data = load_text(args.input)

    if not data.strip():
        print("[ERROR] Input file is empty")
        sys.exit(1)

    # Extract IOCs
    print("[INFO] Extracting indicators of compromise (IOCs)...")
    iocs = extract_iocs(data)

    ioc_count = sum(len(v) for v in iocs.values())
    print(f"[INFO] Extracted {ioc_count} IOCs: "
          f"{len(iocs.get('ips', []))} IPs, "
          f"{len(iocs.get('domains', []))} domains, "
          f"{len(iocs.get('urls', []))} URLs, "
          f"{len(iocs.get('hashes', []))} hashes")

    if args.verbose:
        for category, values in iocs.items():
            if values:
                print(f"[DEBUG] {category.upper()}: {', '.join(values[:5])}")

    # Run detection rules
    print("[INFO] Running detection rules...")
    detections = run_rules(data, iocs, args.rules)

    for det in detections:
        severity = det.get('severity', 'info').upper()
        rule_name = det.get('rule', 'Unknown')
        mitre = det.get('mitre', '')
        mitre_str = f" ({mitre})" if mitre else ""
        print(f"[ALERT] {severity} - {rule_name}{mitre_str}")

    if args.verbose and not detections:
        print("[DEBUG] No detections triggered")

    # Map detections to MITRE ATT&CK
    print("[INFO] Mapping detections to MITRE ATT&CK...")
    mapped_detections = map_to_mitre(detections)

    # Generate reports
    print("[INFO] Generating reports...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Markdown report
    md_report = write_markdown_report(
        args.output,
        args.input,
        iocs,
        mapped_detections,
        timestamp
    )
    print(f"[INFO] Markdown report generated: {md_report}")

    # HTML report (optional)
    if args.html:
        html_report = write_html_report(
            args.output,
            args.input,
            iocs,
            mapped_detections,
            timestamp
        )
        print(f"[INFO] HTML report generated: {html_report}")

    # Summary
    print("\n" + "=" * 50)
    print("[INFO] Analysis complete.")
    print(f"[INFO] Total IOCs found: {ioc_count}")
    print(f"[INFO] Total detections: {len(mapped_detections)}")
    
    high_count = sum(1 for d in mapped_detections if d.get('severity') in ['high', 'critical'])
    if high_count > 0:
        print(f"[WARNING] {high_count} high/critical severity detection(s) require immediate attention!")
    print("=" * 50)

    return 0 if not high_count else 1


if __name__ == "__main__":
    sys.exit(main())
