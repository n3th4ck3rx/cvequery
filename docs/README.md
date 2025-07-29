# CVEQuery Documentation

Documentation for security researchers and bug bounty hunters.

## Quick Links

- **[Installation Guide](installation.md)** - Setup and requirements
- **[Usage Guide](usage.md)** - Commands and examples

## Getting Started

1. **Install**: `pipx install cvequery`
2. **Test**: `cvequery -c CVE-2021-44228`
3. **Explore**: `cvequery --help`

## Key Concepts

### CVE Lookup
- Single CVE: `-c CVE-ID`
- Multiple CVEs: `-mc "CVE-1,CVE-2"`
- Detailed view: `-d`

### Product Research
- Basic search: `--product-cve PRODUCT`
- With filters: `--product-cve PRODUCT --severity critical`
- KEV only: `--is-kev`

### Output Control
- Format: `--format compact|summary`
- Fields: `--fields field1,field2`
- Export: `--json file.json`

## Common Workflows

### Incident Response
```bash
cvequery -c CVE-2023-44487 -d
```

### Vulnerability Assessment
```bash
cvequery --product-cve nginx --severity critical,high --csv report.csv
```

### Threat Hunting
```bash
cvequery --is-kev --sort-by-epss --limit-cves 10 --format compact
```

## Support

- Use `cvequery --help` for command reference
- Set `CVEQUERY_DEBUG=1` for detailed error information
- Check the usage guide for advanced examples