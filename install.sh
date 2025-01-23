#!/bin/bash

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate

# Upgrade pip and install build tools
pip install --upgrade pip setuptools wheel

# Install the package with both indexes
pip install --index-url https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple \
    cvequery==${VERSION}

# Verify installation
cvequery --version 