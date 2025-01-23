import json
import re
from datetime import datetime
import hashlib
from colorama import Fore, Style
from typing import Dict, Optional, List, Any

FIELD_COLOR_MAPPING = {
    "cvss": Fore.RED,
    "cvss_v3": Fore.RED,
    "epss": Fore.YELLOW,
    "references": Fore.BLUE,
    "published_time": Fore.GREEN,
    "summary": Fore.MAGENTA,
    "cpes": Fore.CYAN,
}

SEVERITY_MAP = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9)
}


def save_to_json(data, filename):
    """Save data to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)


def validate_date(date_str):
    """Validate date string format (YYYY-MM-DD)."""
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False


def get_cvss_severity(score: float) -> str:
    """Get severity level based on CVSS score."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    return "none"


def filter_by_severity(data: Dict[str, Any], severity_levels: List[str]) -> Dict[str, Any]:
    """Filter CVEs by severity levels."""
    if not severity_levels or not data or "cves" not in data:
        return data

    # Define severity ranges like in the original implementation
    severity_ranges = {
        "critical": (9.0, 10.0),
        "high": (7.0, 8.9),
        "medium": (4.0, 6.9),
        "low": (0.1, 3.9),
        "none": (0.0, 0.0)
    }

    # Normalize severity levels
    severity_levels = [s.lower().strip() for s in severity_levels]
    
    filtered_cves = []
    for cve in data["cves"]:
        # Try CVSS v3 first, then fall back to v2
        cvss_score = cve.get("cvss_v3")
        if cvss_score is None:
            cvss_score = cve.get("cvss")
        
        if cvss_score is not None:
            try:
                score = float(cvss_score)
                # Check if score falls within any of the requested severity ranges
                for level in severity_levels:
                    if level in severity_ranges:
                        min_score, max_score = severity_ranges[level]
                        if min_score <= score <= max_score:
                            filtered_cves.append(cve)
                            break
            except (ValueError, TypeError):
                continue

    # Sort by CVSS score in descending order
    filtered_cves.sort(
        key=lambda x: float(x.get("cvss_v3", x.get("cvss", 0)) or 0),
        reverse=True
    )

    return {
        "cves": filtered_cves,
        "total": len(filtered_cves)
    }


def colorize_output(data, fields):
    """Display data with colorized fields."""
    for field in fields:
        if field in data:
            color = FIELD_COLOR_MAPPING.get(field, Fore.WHITE)
            print(f"{color}{field}: {Style.BRIGHT}{data[field]}")


def sort_by_epss_score(data: dict) -> dict:
    """Sort CVEs by EPSS score in descending order."""
    if not data or "cves" not in data:
        return data
    
    def get_epss_score(cve):
        try:
            return float(cve.get("epss", 0))
        except (TypeError, ValueError):
            return 0.0
    
    sorted_cves = sorted(
        data["cves"],
        key=get_epss_score,
        reverse=True
    )
    return {"cves": sorted_cves}


def create_cache_key(prefix, **kwargs):
    """Create a unique cache key based on function arguments."""
    sorted_items = sorted(kwargs.items())
    args_str = ','.join(f'{k}={v}' for k, v in sorted_items)
    key = f"{prefix}:{args_str}"
    return hashlib.md5(key.encode()).hexdigest()

