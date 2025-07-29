# Export Formats

## Supported Formats

### JSON
- **Flag**: `--json filename.json`
- **Use**: API integration, automation
- **Dependencies**: Built-in

### CSV
- **Flag**: `--csv filename.csv`
- **Use**: Spreadsheet analysis, reporting
- **Dependencies**: Built-in

### YAML
- **Flag**: `--yaml filename.yaml`
- **Use**: Configuration files, automation
- **Dependencies**: `pip install PyYAML`

### XML
- **Flag**: `--xml filename.xml`
- **Use**: Enterprise systems, legacy tools
- **Dependencies**: Built-in

### STIX 2.1
- **Flag**: `--stix filename.json`
- **Use**: Threat intelligence platforms
- **Dependencies**: `pip install stix2`

## Usage

```bash
# Single format
cvequery -c CVE-2021-44228 --json output.json

# Multiple formats
cvequery --product-cve apache --json data.json --csv data.csv
```

## Notes

- All formats support the same CVE data structure
- Export files are created in the current directory unless full path specified
- Multiple export formats can be used simultaneously