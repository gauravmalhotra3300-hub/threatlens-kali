"""
src/detection_engine.py
YAML-based detection rule engine for ThreatLens-Kali.
"""

import re
import yaml
from pathlib import Path


DEFAULT_KEYWORDS = [
    ("failed password", "medium"),
    ("unauthorized", "high"),
    ("powershell -enc", "high"),
    ("curl http", "medium"),
    ("wget http", "medium"),
    ("admin login failed", "high"),
    ("invalid user", "medium"),
    ("authentication failure", "medium"),
    ("suspicious activity", "high"),
    ("malware", "critical"),
]


def load_rules(rules_path):
    """Load detection rules from YAML file.
    
    Args:
        rules_path: Path to the YAML rules file
        
    Returns:
        list: List of rule dictionaries
    """
    try:
        with open(rules_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("rules", [])
    except FileNotFoundError:
        return []
    except Exception:
        return []


def run_rules(text, iocs, rules_path="config/rules/sample_rules.yml"):
    """Run detection rules against input text and IOCs.
    
    Args:
        text: Input text to scan
        iocs: Dictionary of extracted IOCs
        rules_path: Path to YAML rules file
        
    Returns:
        list: List of detection results
    """
    detections = []
    text_lower = text.lower()
    
    # Load custom rules
    rules = load_rules(rules_path)
    
    for rule in rules:
        name = rule.get("name", "Unknown Rule")
        match = rule.get("match", "")
        severity = rule.get("severity", "medium")
        mitre = rule.get("mitre", "")
        description = rule.get("description", "")
        
        # Simple keyword matching
        if match.lower() in text_lower:
            detections.append({
                "rule": name,
                "severity": severity,
                "mitre": mitre,
                "description": description,
                "matched_text": match
            })
    
    # Built-in keyword detections
    for keyword, severity in DEFAULT_KEYWORDS:
        if keyword in text_lower:
            detections.append({
                "rule": f"Keyword match: {keyword}",
                "severity": severity,
                "mitre": "",
                "description": f"Detected suspicious keyword: {keyword}",
                "matched_text": keyword
            })
    
    # IOC-based detections
    if len(iocs.get("ips", [])) > 5:
        detections.append({
            "rule": "Multiple IP indicators found",
            "severity": "high",
            "mitre": "T1071",
            "description": "Large number of unique IPs detected",
            "matched_text": f"{len(iocs['ips'])} IPs"
        })
    
    if len(iocs.get("urls", [])) > 3:
        detections.append({
            "rule": "Multiple URL indicators found",
            "severity": "medium",
            "mitre": "T1105",
            "description": "Large number of unique URLs detected",
            "matched_text": f"{len(iocs['urls'])} URLs"
        })
    
    if iocs.get("hashes", []):
        detections.append({
            "rule": "Hash indicators found",
            "severity": "medium",
            "mitre": "T1550",
            "description": "File hashes detected in logs",
            "matched_text": f"{len(iocs['hashes'])} hashes"
        })
    
    return detections
