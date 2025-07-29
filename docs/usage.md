# Usage Guide

## CVE Lookup

### Single CVE
- `cvequery -c CVE-ID`
- `cvequery -c CVE-ID -d` (detailed)
- `cvequery -c CVE-ID -f field1,field2` (custom fields)

### Multiple CVEs
- `cvequery -mc "CVE-1,CVE-2"` (comma-separated)
- `cvequery -mc file.txt` (from file)

## Product Research

### Basic Search
- `cvequery --product-cve PRODUCT`
- `cvequery --product-cve PRODUCT -d` (detailed)

### With Filters
- `cvequery --product-cve PRODUCT --severity critical,high`
- `cvequery --product-cve PRODUCT --is-kev`
- `cvequery --product-cve PRODUCT --start-date YYYY-MM-DD`

## Filtering Options

### Severity
- `--severity critical,high,medium,low,none`

### KEV Status
- `--is-kev` (Known Exploited Vulnerabilities only)

### Date Range
- `--start-date YYYY-MM-DD`
- `--end-date YYYY-MM-DD`

### Sorting
- `--sort-by-epss` (by exploitation probability)

### Limits
- `--limit-cves N` (max results)
- `--skip-cves N` (skip first N)

## Output Control

### Display Formats
- `--format compact` (one line per CVE)
- `--format summary` (statistical analysis)
- `--only-cve-ids` (IDs only)

### Field Control
- `--fields field1,field2` (show specific fields)
- `--fields-exclude field1,field2` (hide fields)
- `--fields-list` (list available fields)

### Export Formats
- `--json file.json`
- `--csv file.csv`
- `--yaml file.yaml`
- `--xml file.xml`
- `--stix file.json`

## Utility Options

### Information
- `--count` (show count only)
- `--help` (show help)
- `--version` (show version)

### Interactive
- `--interactive` (guided mode)

### Completion
- `--install-completion` (install shell completion)

## Available Fields

- `cve_id`, `summary`, `cvss`, `cvss_v2`, `cvss_v3`, `cvss_version`
- `epss`, `ranking_epss`, `kev`, `propose_action`, `ransomware_campaign`
- `references`, `published_time`, `published`, `modified`, `cpes`