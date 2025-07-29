# CVEQuery
![cvequery](/static/cvequery.png)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.5-orange.svg)](https://pypi.org/project/cvequery/)

Powerfull CVE research tool for security researchers and bug bounty hunters. Query Shodan's CVE database with advanced filtering and export capabilities.

## Quick Start

```bash
# Install
pipx install cvequery

# Single CVE lookup
cvequery -c CVE-2021-44228

# Product vulnerability search
cvequery --product-cve nginx --severity critical

# KEV (Known Exploited Vulnerabilities) only
cvequery --is-kev --limit-cves 10
```

## Core Commands

### CVE Lookup
```bash
# Single CVE
cvequery -c CVE-2021-44228

# Multiple CVEs (parallel processing)
cvequery -mc "CVE-2021-44228,CVE-2023-44487"

# Detailed view (no truncation)
cvequery -c CVE-2021-44228 -d
```

### Product Research
```bash
# Find vulnerabilities in specific products
cvequery --product-cve nginx
cvequery --product-cve "windows_10" -lcv 10

# Filter by severity
cvequery --product-cve django --severity critical,high
```

### Advanced Filtering
```bash
# KEV vulnerabilities only
cvequery --is-kev --limit-cves 20

# Date range filtering
cvequery --product-cve log4j --start-date 2021-01-01 --end-date 2021-12-31

# Sort by exploitation probability
cvequery --product-cve nginx --sort-by-epss
```

## Output Formats

### Display Options
```bash
# Compact format (one line per CVE)
cvequery --product-cve apache --format compact

# Summary format (statistical analysis)
cvequery --product-cve apache --format summary

# Custom fields only
cvequery -c CVE-2021-44228 --fields cve_id,cvss,epss,kev

# Exclude specific fields
cvequery -c CVE-2021-44228 --fields-exclude summary,references
```

### Export Formats
```bash
# JSON for automation
cvequery --product-cve nginx --json results.json

# CSV for analysis
cvequery --is-kev --csv kev_report.csv

# STIX for threat intelligence
cvequery -c CVE-2021-44228 --stix intel.json
```

## Installation

```bash
# Recommended
pipx install cvequery

# Alternative
pip install cvequery
```

## Key Features

- **KEV Integration** - Focus on actively exploited vulnerabilities
- **EPSS Scoring** - Exploitation probability assessment  
- **Parallel Processing** - Fast multiple CVE lookups
- **Rich Filtering** - Severity, date range, product-based
- **Export Options** - JSON, CSV, YAML, XML, STIX 2.1
- **Field Customization** - Show/hide specific data fields

## Documentation

- [Installation Guide](docs/installation.md)
- [Usage Guide](docs/usage.md)

## **Contributing**

 Take a look at the [Contributing](CONTRIBUTING.md) Page.

## 📬 Contact

[![X](https://img.shields.io/badge/X-%23000000.svg?style=for-the-badge&logo=X&logoColor=white)](https://x.com/n3th4ck3rx) 

## License

MIT License