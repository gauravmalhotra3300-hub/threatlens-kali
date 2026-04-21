"""
src/mitre_mapper.py
MITRE ATT&CK technique mapping for ThreatLens-Kali.
"""

MITRE_ATTACK_TECHNIQUES = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution"
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access"
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control"
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control"
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Persistence"
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access"
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "Lateral Movement"
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access"
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement"
    },
}


def map_to_mitre(detections):
    """Map detection results to MITRE ATT&CK techniques.
    
    Args:
        detections: List of detection results
        
    Returns:
        list: List of detections with MITRE mapping added
    """
    mapped = []
    
    for det in detections:
        mitre_id = det.get("mitre", "")
        
        if mitre_id and mitre_id in MITRE_ATTACK_TECHNIQUES:
            technique = MITRE_ATTACK_TECHNIQUES[mitre_id]
            det["mitre_name"] = technique["name"]
            det["mitre_tactic"] = technique["tactic"]
        else:
            det["mitre_name"] = "Unknown or custom technique"
            det["mitre_tactic"] = ""
        
        mapped.append(det)
    
    return mapped


def get_technique_info(mitre_id):
    """Get MITRE ATT&CK technique information.
    
    Args:
        mitre_id: MITRE technique ID (e.g., T1059.001)
        
    Returns:
        dict: Technique information or empty dict if not found
    """
    return MITRE_ATTACK_TECHNIQUES.get(mitre_id, {})


def get_all_techniques():
    """Get all available MITRE ATT&CK technique mappings.
    
    Returns:
        dict: All technique mappings
    """
    return MITRE_ATTACK_TECHNIQUES.copy()
