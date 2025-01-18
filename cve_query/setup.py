from setuptools import setup, find_packages

setup(
    name="cve-query",
    version="0.1.0",
    author="Neo",
    author_email="neo.nzso@proton.me",
    description="Query CVE details using Shodan's public CVE database API.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/n3th4ck3rx/cve-query",
    packages=find_packages(),
    install_requires=["requests", "colorama"],
    entry_points={
        "console_scripts": [
            "cve-query = cve_query.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)

