import json
from datetime import datetime
from colorama import Fore, Style

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
    "info": (0.0, 0.0),
    "low": (0.1, 3.9),
    "medium": (4.0, 6.9),
    "high": (7.0, 8.9),
    "critical": (9.0, 10.0),
}


def save_to_json(data, filename):
    """Save output to a JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Output successfully saved to {filename}")
    except IOError as e:
        print(f"Error saving file: {e}")


def validate_date(date_string):
    """Validate date format (YYYY-MM-DD)."""
    try:
        datetime.strptime(date_string, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def filter_by_severity(data, severity_levels):
    """Filter CVEs by severity levels."""
    if not severity_levels:
        return data

    severity_ranges = [SEVERITY_MAP[sev] for sev in severity_levels]
    filtered_cves = []
    for cve in data.get("cves", []):
        cvss_v3 = cve.get("cvss_v3")
        if cvss_v3 is not None:
            if any(low <= cvss_v3 <= high for (low, high) in severity_ranges):
                filtered_cves.append(cve)
    return {"cves": filtered_cves}


def colorize_output(data, fields):
    """Display data with colorized fields."""
    for field in fields:
        if field in data:
            color = FIELD_COLOR_MAPPING.get(field, Fore.WHITE)
            print(f"{color}{field}: {Style.BRIGHT}{data[field]}")

