# Examples

## CVE Lookup
```bash
# Single CVE
cvequery -c CVE-2021-44228

# Multiple CVEs
cvequery -mc "CVE-2021-44228,CVE-2023-44487"

# Detailed view
cvequery -c CVE-2021-44228 -d

# Custom fields
cvequery -c CVE-2021-44228 -f cve_id,cvss,epss,kev
```

## Product Research
```bash
# Basic search
cvequery --product-cve apache

# With severity filter
cvequery --product-cve nginx --severity critical,high

# KEV only
cvequery --product-cve nginx --is-kev

# Date range
cvequery --product-cve nginx --start-date 2021-01-01 --end-date 2021-12-31
```

## Filtering
```bash
# KEV vulnerabilities
cvequery --is-kev --limit-cves 10

# Sort by EPSS
cvequery --product-cve django --sort-by-epss -lcv 10

# Multiple filters
cvequery --product-cve nginx --severity high --start-date 2020-01-01
```

## Output Formats
```bash
# Compact format
cvequery --product-cve nginx --format compact

# Summary format
cvequery --product-cve apache --format summary

# CVE IDs only
cvequery --product-cve apache --only-cve-ids

# Exclude fields
cvequery -c CVE-2021-44228 --fields-exclude summary,references
```

## Export
```bash
# JSON export
cvequery --product-cve nginx --json results.json

# CSV export
cvequery --is-kev --csv kev_report.csv

# Multiple formats
cvequery --product-cve apache --json data.json --csv data.csv

# STIX export
cvequery -c CVE-2021-44228 --stix intel.json
```

## Common Workflows
```bash
# Incident response
cvequery -c CVE-2023-44487 -d

# Vulnerability assessment
cvequery --product-cve "windows_10" --severity critical,high --csv report.csv

# Threat hunting
cvequery --is-kev --sort-by-epss --limit-cves 20 --format compact

# Bug bounty research
cvequery --product-cve wordpress --severity critical,high --start-date 2021-01-01
```