"""
src/ioc_extractor.py
Indicator of Compromise (IOC) extraction for ThreatLens-Kali.
"""

import re


def extract_iocs(text):
    """Extract indicators of compromise from text.
    
    Args:
        text: Input text to scan for IOCs
        
    Returns:
        dict: Dictionary containing lists of extracted IOCs
    """
    # Extract IPv4 addresses
    ips = re.findall(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        text
    )
    
    # Extract domain names
    domains = re.findall(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        text
    )
    
    # Extract URLs
    urls = re.findall(
        r'https?://[^\s<>"]+',
        text
    )
    
    # Extract MD5, SHA1, SHA256 hashes
    hashes = re.findall(
        r'\b[a-fA-F0-9]{32,64}\b',
        text
    )
    
    # Extract email addresses
    emails = re.findall(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        text
    )
    
    return {
        "ips": sorted(set(ips)),
        "domains": sorted(set(domains)),
        "urls": sorted(set(urls)),
        "hashes": sorted(set(hashes)),
        "emails": sorted(set(emails))
    }
