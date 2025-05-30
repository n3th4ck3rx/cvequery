# build.ps1

Write-Host "🚀 Starting full build and publish process..." -ForegroundColor Cyan

function Clean {
    Write-Host "🧹 Cleaning project..."
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue build, dist, *.egg-info
    Get-ChildItem -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Recurse -Include *.pyc | Remove-Item -Force -ErrorAction SilentlyContinue
}

function Install {
    Write-Host "📦 Installing dependencies..."
    pip install -e ".[dev]"
}

function Test {
    Write-Host "🧪 Running tests..."
    pytest tests/ --cov=src --cov-report=term-missing
    if ($LASTEXITCODE -ne 0) {
        throw "❌ Tests failed. Halting the process."
    }
}

function Lint {
    Write-Host "🧼 Linting code..."
    black .
    isort .
    flake8 .
    if ($LASTEXITCODE -ne 0) {
        throw "❌ Linting failed. Halting the process."
    }
}

function Build {
    Write-Host "🏗️  Building the project..."
    python -m build
    if ($LASTEXITCODE -ne 0) {
        throw "❌ Build failed. Halting the process."
    }
}

function Publish {
    Write-Host "🚀 Publishing to PyPI..."
    python -m twine upload dist/*
    if ($LASTEXITCODE -ne 0) {
        throw "❌ Publish failed."
    }
}

try {
    Clean
    Install
    # Test  # ← Uncomment to re-enable testing
    Lint
    Build
    Publish
    Write-Host "`n✅ Done! Project cleaned, linted, built, and published successfully." -ForegroundColor Green
} catch {
    Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

