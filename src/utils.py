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

def save_to_csv(data, filename):
    """Save CVE data to CSV format optimized for cybersecurity analysis."""
    import csv
    
    # Handle both single CVE and multiple CVEs
    if isinstance(data, dict) and 'cves' in data:
        cves = data['cves']
    elif isinstance(data, dict) and 'cve_id' in data:
        cves = [data]
    elif isinstance(data, list):
        cves = data
    else:
        cves = [data]
    
    if not cves:
        return
    
    # Define CSV columns optimized for cybersecurity use cases
    fieldnames = [
        'cve_id', 'severity', 'cvss_v3', 'cvss_v2', 'epss_score', 'epss_percentile',
        'kev_status', 'published_date', 'modified_date', 'summary',
        'attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction',
        'scope', 'confidentiality_impact', 'integrity_impact', 'availability_impact',
        'cwe_id', 'references_count', 'affected_products_count', 'references', 'cpes'
    ]
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for cve in cves:
            # Extract CVSS metrics
            cvss_v3 = cve.get('cvss_v3', 0)
            cvss_v2 = cve.get('cvss_v2', 0)
            
            # Calculate severity
            severity = 'Unknown'
            if isinstance(cvss_v3, (int, float)) and cvss_v3 > 0:
                if cvss_v3 >= 9.0:
                    severity = 'Critical'
                elif cvss_v3 >= 7.0:
                    severity = 'High'
                elif cvss_v3 >= 4.0:
                    severity = 'Medium'
                else:
                    severity = 'Low'
            
            row = {
                'cve_id': cve.get('cve_id', ''),
                'severity': severity,
                'cvss_v3': cvss_v3 if cvss_v3 else '',
                'cvss_v2': cvss_v2 if cvss_v2 else '',
                'epss_score': cve.get('epss', ''),
                'epss_percentile': f"{cve.get('epss', 0) * 100:.2f}%" if cve.get('epss') else '',
                'kev_status': 'Yes' if cve.get('kev') else 'No',
                'published_date': cve.get('published_time', cve.get('published', '')),
                'modified_date': cve.get('modified', ''),
                'summary': cve.get('summary', '').replace('\n', ' ').replace('\r', ' '),
                'attack_vector': cve.get('attack_vector', ''),
                'attack_complexity': cve.get('attack_complexity', ''),
                'privileges_required': cve.get('privileges_required', ''),
                'user_interaction': cve.get('user_interaction', ''),
                'scope': cve.get('scope', ''),
                'confidentiality_impact': cve.get('confidentiality_impact', ''),
                'integrity_impact': cve.get('integrity_impact', ''),
                'availability_impact': cve.get('availability_impact', ''),
                'cwe_id': cve.get('cwe', ''),
                'references_count': len(cve.get('references', [])),
                'affected_products_count': len(cve.get('cpes', [])),
                'references': '; '.join(cve.get('references', [])[:5]) + ('...' if len(cve.get('references', [])) > 5 else ''),
                'cpes': '; '.join(cve.get('cpes', [])[:5]) + ('...' if len(cve.get('cpes', [])) > 5 else '')
            }
            writer.writerow(row)

def save_to_yaml(data, filename):
    """Save CVE data to YAML format for automation and configuration."""
    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML is required for YAML export. Install with: pip install PyYAML")
    
    # Structure data for YAML with cybersecurity focus
    if isinstance(data, dict) and 'cves' in data:
        yaml_data = {
            'cve_report': {
                'metadata': {
                    'total_cves': len(data['cves']),
                    'generated_at': datetime.now().isoformat(),
                    'format_version': '1.0'
                },
                'vulnerabilities': []
            }
        }
        
        for cve in data['cves']:
            vuln = {
                'cve_id': cve.get('cve_id', ''),
                'severity': _get_severity_from_cvss(cve.get('cvss_v3', cve.get('cvss', 0))),
                'scores': {
                    'cvss_v3': cve.get('cvss_v3', 0) if cve.get('cvss_v3') else None,
                    'cvss_v2': cve.get('cvss_v2', 0) if cve.get('cvss_v2') else None,
                    'epss': cve.get('epss', 0) if cve.get('epss') else None
                },
                'timeline': {
                    'published': cve.get('published_time', cve.get('published', '')),
                    'modified': cve.get('modified', '')
                },
                'kev_status': cve.get('kev', False),
                'summary': cve.get('summary', ''),
                'references': cve.get('references', []),
                'affected_products': cve.get('cpes', [])
            }
            # Remove None values
            vuln = {k: v for k, v in vuln.items() if v is not None and v != ''}
            yaml_data['cve_report']['vulnerabilities'].append(vuln)
    else:
        # Single CVE
        cve = data if isinstance(data, dict) else {}
        yaml_data = {
            'vulnerability': {
                'cve_id': cve.get('cve_id', ''),
                'severity': _get_severity_from_cvss(cve.get('cvss_v3', cve.get('cvss', 0))),
                'scores': {
                    'cvss_v3': cve.get('cvss_v3', 0) if cve.get('cvss_v3') else None,
                    'cvss_v2': cve.get('cvss_v2', 0) if cve.get('cvss_v2') else None,
                    'epss': cve.get('epss', 0) if cve.get('epss') else None
                },
                'timeline': {
                    'published': cve.get('published_time', cve.get('published', '')),
                    'modified': cve.get('modified', '')
                },
                'kev_status': cve.get('kev', False),
                'summary': cve.get('summary', ''),
                'references': cve.get('references', []),
                'affected_products': cve.get('cpes', [])
            }
        }
    
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, indent=2)

def save_to_xml(data, filename):
    """Save CVE data to XML format for enterprise systems integration."""
    try:
        import xml.etree.ElementTree as ET
        from xml.dom import minidom
    except ImportError:
        raise ImportError("xml.etree.ElementTree is required for XML export")
    
    # Create root element
    root = ET.Element('cve_report')
    root.set('version', '1.0')
    root.set('generated_at', datetime.now().isoformat())
    
    # Handle multiple CVEs
    if isinstance(data, dict) and 'cves' in data:
        cves = data['cves']
        metadata = ET.SubElement(root, 'metadata')
        ET.SubElement(metadata, 'total_cves').text = str(len(cves))
    elif isinstance(data, dict) and 'cve_id' in data:
        cves = [data]
    else:
        cves = [data] if data else []
    
    vulnerabilities = ET.SubElement(root, 'vulnerabilities')
    
    for cve in cves:
        vuln = ET.SubElement(vulnerabilities, 'vulnerability')
        
        # Basic info
        ET.SubElement(vuln, 'cve_id').text = cve.get('cve_id', '')
        ET.SubElement(vuln, 'severity').text = _get_severity_from_cvss(cve.get('cvss_v3', cve.get('cvss', 0)))
        
        # Scores
        scores = ET.SubElement(vuln, 'scores')
        if cve.get('cvss_v3'):
            ET.SubElement(scores, 'cvss_v3').text = str(cve['cvss_v3'])
        if cve.get('cvss_v2'):
            ET.SubElement(scores, 'cvss_v2').text = str(cve['cvss_v2'])
        if cve.get('epss'):
            ET.SubElement(scores, 'epss').text = str(cve['epss'])
        
        # Timeline
        timeline = ET.SubElement(vuln, 'timeline')
        if cve.get('published_time') or cve.get('published'):
            ET.SubElement(timeline, 'published').text = cve.get('published_time', cve.get('published', ''))
        if cve.get('modified'):
            ET.SubElement(timeline, 'modified').text = cve['modified']
        
        # KEV status
        ET.SubElement(vuln, 'kev_status').text = 'true' if cve.get('kev') else 'false'
        
        # Summary
        if cve.get('summary'):
            ET.SubElement(vuln, 'summary').text = cve['summary']
        
        # References
        if cve.get('references'):
            refs = ET.SubElement(vuln, 'references')
            for ref in cve['references']:
                ET.SubElement(refs, 'reference').text = ref
        
        # Affected products
        if cve.get('cpes'):
            products = ET.SubElement(vuln, 'affected_products')
            for cpe in cve['cpes']:
                ET.SubElement(products, 'product').text = cpe
    
    # Pretty print XML
    rough_string = ET.tostring(root, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(reparsed.toprettyxml(indent='  '))

def save_to_stix(data, filename):
    """Save CVE data to STIX 2.1 format for threat intelligence sharing."""
    try:
        from stix2 import Vulnerability, Bundle, TLP_WHITE
        import uuid
    except ImportError:
        raise ImportError("stix2 is required for STIX export. Install with: pip install stix2")
    
    stix_objects = []
    
    # Handle multiple CVEs
    if isinstance(data, dict) and 'cves' in data:
        cves = data['cves']
    elif isinstance(data, dict) and 'cve_id' in data:
        cves = [data]
    else:
        cves = [data] if data else []
    
    for cve in cves:
        # Prepare external references
        external_refs = []
        
        # Add CVE reference (primary)
        external_refs.append({
            'source_name': 'cve',
            'external_id': cve.get('cve_id', ''),
            'url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.get('cve_id', '')}"
        })
        
        # Add additional references (limit to 5 for STIX compliance)
        if cve.get('references'):
            for ref in cve.get('references', [])[:5]:
                external_refs.append({
                    'source_name': 'reference',
                    'url': ref
                })
        
        # Create enhanced description with metadata
        description = cve.get('summary', '')
        if cve.get('cvss_v3') or cve.get('cvss_v2'):
            cvss_info = []
            if cve.get('cvss_v3'):
                cvss_info.append(f"CVSS v3.0: {cve['cvss_v3']}")
            if cve.get('cvss_v2'):
                cvss_info.append(f"CVSS v2.0: {cve['cvss_v2']}")
            description += f"\n\nSeverity: {' | '.join(cvss_info)}"
        
        if cve.get('epss'):
            description += f"\nEPSS Score: {cve['epss']} ({cve['epss']*100:.2f}% exploitation probability)"
        
        if cve.get('kev'):
            description += "\n\n⚠️ This vulnerability is listed in CISA's Known Exploited Vulnerabilities (KEV) catalog."
        
        # Create STIX Vulnerability object (simplified for compliance)
        vulnerability = Vulnerability(
            name=cve.get('cve_id', ''),
            description=description,
            external_references=external_refs,
            object_marking_refs=[TLP_WHITE]
        )
        
        stix_objects.append(vulnerability)
    
    # Create STIX Bundle
    bundle = Bundle(objects=stix_objects)
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(bundle.serialize(pretty=True))

def _get_severity_from_cvss(cvss_score):
    """Helper function to get severity level from CVSS score."""
    try:
        score = float(cvss_score) if cvss_score else 0
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        elif score > 0:
            return 'Low'
        else:
            return 'None'
    except (ValueError, TypeError):
        return 'Unknown'


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

