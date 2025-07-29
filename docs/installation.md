# Installation Guide

## Quick Install (Recommended)

```bash
pipx install cvequery
```

This is the cleanest method as it installs CVEQuery in an isolated environment.

## Alternative Methods

### Using pip
```bash
pip install cvequery
```

### From Source
```bash
git clone https://github.com/user/cvequery.git
cd cvequery
pip install -e .
```

## Requirements

- Python 3.8 or higher
- Internet connection for CVE database queries

## Optional Dependencies

For additional export formats:

```bash
# YAML export support
pip install PyYAML

# STIX 2.1 export support
pip install stix2
```

## Verification

Test your installation:

```bash
cvequery --version
cvequery -c CVE-2021-44228
```

## Shell Completion (Optional)

Enable tab completion for faster usage:

```bash
# Auto-detect and install
cvequery --install-completion

# Manual setup for specific shell
cvequery --setup-completion bash
cvequery --setup-completion zsh
```

## Troubleshooting

### Common Issues

**Command not found**: Ensure Python's script directory is in your PATH, or use `python -m cvequery` instead.

**Permission errors**: Use `pipx` instead of `pip`, or install with `pip install --user cvequery`.

**Network errors**: Check your internet connection and firewall settings.

### Debug Mode

For detailed error information:

```bash
export CVEQUERY_DEBUG=1
cvequery -c CVE-2021-44228
```

## Updating

```bash
# With pipx
pipx upgrade cvequery

# With pip
pip install --upgrade cvequery
```