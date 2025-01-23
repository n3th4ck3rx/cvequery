import os
from setuptools import setup, find_packages

# Read version directly as a string to avoid execution
with open(os.path.join("src", "__version__.py"), "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith("__version__"):
            __version__ = line.split("=")[1].strip().strip('"').strip("'")
            break

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
    
# Core dependencies with relaxed versions
INSTALL_REQUIRES = [
    "requests",  # Let pip resolve the version
    "click",
    "colorama",
    "urllib3",
    "certifi",
    "typing-extensions",
]

# Development dependencies
DEV_REQUIRES = [
    "pytest",
    "pytest-cov",
    "pytest-mock",
    "responses",
    "black",
    "isort",
    "flake8",
    "mypy",
    "build",
    "twine",
    "wheel",
]

setup(
    name="cvequery",
    version=__version__,
    author="Neo",
    author_email="neo.nzso@proton.me",
    description="Query CVE details using Shodan's public CVE database API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/n3th4ck3rx/cvequery",
    packages=["src"],
    package_dir={"src": "src"},
    install_requires=INSTALL_REQUIRES,
    extras_require={
        'dev': DEV_REQUIRES,
    },
    entry_points={
        "console_scripts": [
            "cvequery=src.main:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
) 
