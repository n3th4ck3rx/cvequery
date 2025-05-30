# Create and activate virtual environment
python -m venv venv

# Activate the virtual environment (Windows)
. .\venv\Scripts\Activate.ps1

# Upgrade pip and install build tools
pip install --upgrade pip setuptools wheel

# Ensure VERSION environment variable is set
if (-not $env:VERSION) {
    Write-Host "ERROR: VERSION environment variable is not set."
    exit 1
}

# Install the package with both indexes
pip install --index-url https://test.pypi.org/simple/ `
    --extra-index-url https://pypi.org/simple `
    cvequery==$env:VERSION

# Verify installation
cvequery --version
