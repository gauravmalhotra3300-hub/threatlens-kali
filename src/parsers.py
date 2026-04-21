"""
src/parsers.py
Log and text file parsers for ThreatLens-Kali.
"""

from pathlib import Path


def load_text(path):
    """Load text content from a file.
    
    Args:
        path: Path to the input file
        
    Returns:
        str: File content as string
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def load_lines(path):
    """Load file content as a list of lines.
    
    Args:
        path: Path to the input file
        
    Returns:
        list: List of non-empty lines
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]
