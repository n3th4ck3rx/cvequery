import json
import re
from datetime import datetime
import hashlib
from colorama import Fore, Style, init as colorama_init
from typing import Dict, Optional, List, Any
from src.constants import SEVERITY_MAP
import click

# Initialize colorama
colorama_init(autoreset=True)

FIELD_COLOR_MAPPING = {
    "id": Fore.WHITE + Style.BRIGHT,
    "summary": Fore.MAGENTA,
    "cvss": Fore.RED,
    "cvss_v2": Fore.RED,
    "cvss_v3": Fore.RED + Style.BRIGHT,
    "epss": Fore.YELLOW,
    "epss_score": Fore.YELLOW + Style.BRIGHT,
    "kev": Fore.RED + Style.BRIGHT,
    "references": Fore.BLUE,
    "published": Fore.GREEN,
    "modified": Fore.GREEN,
    "cpes": Fore.CYAN,
    "cwe": Fore.YELLOW,
    "vectorString": Fore.LIGHTRED_EX,
    "attackVector": Fore.LIGHTRED_EX,
    "complexity": Fore.LIGHTYELLOW_EX,
    "privilegesRequired": Fore.LIGHTYELLOW_EX,
    "userInteraction": Fore.LIGHTYELLOW_EX,
    "scope": Fore.LIGHTWHITE_EX,
    "confidentialityImpact": Fore.LIGHTRED_EX,
    "integrityImpact": Fore.LIGHTRED_EX,
    "availabilityImpact": Fore.LIGHTRED_EX,
    "baseScore": Fore.RED + Style.BRIGHT,
    "baseSeverity": Fore.RED + Style.BRIGHT,
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

    severity_ranges = {
        "critical": (9.0, 10.0),
        "high": (7.0, 8.9),
        "medium": (4.0, 6.9),
        "low": (0.1, 3.9),
        "none": (0.0, 0.0)
    }
    
    normalized_severity_levels = [s.lower().strip() for s in severity_levels]
    
    filtered_cves = []
    for cve in data["cves"]:
        cvss_score_to_check = None
        if "cvss_v3" in cve and isinstance(cve["cvss_v3"], dict) and "baseScore" in cve["cvss_v3"]:
            cvss_score_to_check = cve["cvss_v3"]["baseScore"]
        elif "cvss" in cve and isinstance(cve["cvss"], dict) and "score" in cve["cvss"]:
            cvss_score_to_check = cve["cvss"]["score"]
        elif "cvss_v3" in cve and isinstance(cve["cvss_v3"], (float, int)):
             cvss_score_to_check = cve["cvss_v3"]
        elif "cvss" in cve and isinstance(cve["cvss"], (float, int)):
             cvss_score_to_check = cve["cvss"]

        if cvss_score_to_check is not None:
            try:
                score = float(cvss_score_to_check)
                for level in normalized_severity_levels:
                    if level in severity_ranges:
                        min_score, max_score = severity_ranges[level]
                        if min_score <= score <= max_score:
                            filtered_cves.append(cve)
                            break 
            except (ValueError, TypeError):
                continue 

    def get_sort_score(cve_item):
        if "cvss_v3" in cve_item and isinstance(cve_item["cvss_v3"], dict) and "baseScore" in cve_item["cvss_v3"]:
            return float(cve_item["cvss_v3"]["baseScore"] or 0)
        if "cvss" in cve_item and isinstance(cve_item["cvss"], dict) and "score" in cve_item["cvss"]:
            return float(cve_item["cvss"]["score"] or 0)
        if "cvss_v3" in cve_item and isinstance(cve_item["cvss_v3"], (float, int)):
             return float(cve_item["cvss_v3"] or 0)
        if "cvss" in cve_item and isinstance(cve_item["cvss"], (float, int)):
             return float(cve_item["cvss"] or 0)
        return 0.0

    filtered_cves.sort(key=get_sort_score, reverse=True)

    return {
        "cves": filtered_cves,
        "total": len(filtered_cves)
    }


def colorize_output(data: Dict[str, Any], fields_to_display: List[str]):
    """Display data with colorized fields."""
    for field_name in fields_to_display:
        if field_name in data:
            field_value = data[field_name]
            
            field_name_style = Fore.WHITE + Style.BRIGHT
            field_value_style = Style.BRIGHT

            if field_name in FIELD_COLOR_MAPPING:
                field_name_style = FIELD_COLOR_MAPPING[field_name]
            
            value_str = ""
            if isinstance(field_value, dict):
                value_str = json.dumps(field_value, indent=2)
                complex_obj_color = FIELD_COLOR_MAPPING.get(field_name, Fore.WHITE).split(Style.BRIGHT)[0] if isinstance(FIELD_COLOR_MAPPING.get(field_name), str) else Fore.WHITE
                
                lines = value_str.split('\\n')
                colored_lines = []
                for line in lines:
                    if ":" in line:
                        key, val = line.split(":", 1)
                        colored_lines.append(f"{Fore.LIGHTWHITE_EX}{key}:{Style.RESET_ALL}{field_value_style}{val}")
                    else:
                        colored_lines.append(f"{complex_obj_color}{line}")
                value_str = "\\n".join(colored_lines)

            elif isinstance(field_value, list):
                value_str = json.dumps(field_value, indent=2)
            else:
                value_str = str(field_value)

            print(f"{field_name_style}{field_name}:{Style.RESET_ALL} {field_value_style}{value_str}{Style.RESET_ALL}")


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

