# 🔍 cvequery - CVE Search and Analysis Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.2-orange.svg)](https://test.pypi.org/project/cvequery/)

A powerful command-line tool to search and analyze CVE (Common Vulnerabilities and Exposures) data using Shodan's public CVE database API.

## ✨ Features

- 🔍 Search CVEs by product name or CPE
- 📊 Filter results by severity, date range, and KEV status
- 📈 Sort results by EPSS score
- 📥 Export results to JSON format
- 🖌️ Colorized output for better readability
- ⏳ Auto-update functionality

## 📦 Installation

### If you want to install the tool easily, I recommend using `pipx`:

```bash
pipx install cvequery
```

### 2. Manual Installation (From Source)

If you prefer to manually install the tool from the source, you can clone the repository and set up the environment locally.

#### Steps to Install Manually:

1. Clone the Repository:

   First, clone the `cvequery` repository from GitHub to your local machine:
   ```bash
   git clone https://github.com/n3th4ck3rx/cvequery.git
   cd cvequery
   ```

2. Set Up a Virtual Environment (Optional but recommended):

   It's best practice to use a virtual environment to avoid conflicts with other Python packages.

   ```bash
   # Create a virtual environment (you can name it anything)
   python3 -m venv venv

   # Activate the virtual environment:
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. Install Dependencies:

   Now, install the required dependencies from the `requirements.txt` file:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the Tool:

   After installing the dependencies, you can run the tool using the following command:

   ```bash
   python cvequery.py 
   ```

5. (Optional) Install as a Global Tool:

   If you want to install the tool globally on your system for easier use, you can use:

   ```bash
   pip install .
   ```

   This will install the tool locally within your environment or globally depending on your Python setup.

## 🛠️ Command Options

### ⚙️ Basic Options
- `-c, --cve TEXT` - Get details for a specific CVE ID
- `-mc, --multiple-cves TEXT` - Query multiple CVEs (comma-separated or file path)
- `-pcve, --product-cve TEXT` - Search CVEs by product name
- `-pcpe, --product-cpe TEXT` - Search by product name for CPE lookup
- `--version` - Show the current version
- `-up, --update` - Update to the latest version

### 🔍 Search Filters
- `-k, --is-kev` - Show only Known Exploited Vulnerabilities
- `-s, --severity TEXT` - Filter by severity (critical,high,medium,low)
- `-sd, --start-date TEXT` - Start date for CVE search (YYYY-MM-DD)
- `-ed, --end-date TEXT` - End date for CVE search (YYYY-MM-DD)
- `--cpe23 TEXT` - Search CVEs by CPE 2.3 string
- `-epss, --sort-by-epss` - Sort results by EPSS score

### 📋 Output Options
- `-f, --fields TEXT` - Comma-separated list of fields to display
- `-j, --json TEXT` - Save output to JSON file
- `-oci, --only-cve-ids` - Output only CVE IDs
- `--count` - Show only the total count of results
- `-fl, --fields-list` - List all available fields

### 📊 Pagination Options
- `--skip-cves INTEGER` - Number of CVEs to skip
- `--limit-cves INTEGER` - Maximum number of CVEs to return
- `--skip-cpe INTEGER` - Number of CPEs to skip
- `--limit-cpe INTEGER` - Maximum number of CPEs to return

## 📚 Examples

### Basic CVE Lookup
```bash
# Look up a specific CVE
cvequery -c CVE-2019-5127

# Search for multiple CVEs
cvequery -mc CVE-2019-5129,CVE-2019-5127

# Load CVEs from a file
cvequery -mc cve_list.txt
```

### Product Search
```bash
# Search CVEs for a product
cvequery -pcve apache

# Search with severity filter
cvequery -pcve apache -s critical,high

# Search with date range
cvequery -pcve apache -sd 2023-01-01 -ed 2023-12-31
```

### Advanced Filtering
```bash
# Search for Known Exploited Vulnerabilities
cvequery -pcve windows -k

# Sort by EPSS score
cvequery -pcve apache -epss

# Show only specific fields
cvequery -pcve nginx -f cve_id,summary,cvss_v3
```

### CPE Lookup
```bash
# Search CPEs for a product
cvequery -pcpe apache

# Use CPE 2.3 format
cvequery --cpe23 cpe:2.3:a:libpng:libpng:0.8
```

### Output Options
```bash
# Save results to JSON
cvequery -pcve apache -j output.json

# Show only CVE IDs
cvequery -pcve apache -oci

# Show total count of CPES
cvequery -pcve apache --count
```

## 🗂️ Version Management

### Check Current Version
```bash
cvequery --version
```

### Update to Latest Version
```bash
cvequery -up
```

## 📋 Available Fields

To see all available fields:
```bash
cvequery -fl
```

Available fields include:
- id
- summary
- cvss
- cvss_v2
- cvss_v3
- epss
- epss_score
- kev
- references
- published
- modified
- cpes
- cwe

### **Upcoming Features**
- **Autocomplete**: Command and flag autocompletion for faster workflows.
- **Progress Tracking**: Real-time progress for batch CVE processing.
- **Integration with Security Tools**: Compatibility with tools like Nmap and Nessus.
- **Multiple Output Formats**: Output to Other formats like csv,html etc.

## **Contributing**

 Take a look at the [Contributing](CONTRIBUTING.md) Page.

## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📬 Contact

[![X](https://img.shields.io/badge/X-%23000000.svg?style=for-the-badge&logo=X&logoColor=white)](https://x.com/n3th4ck3rx) 

[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/users/n3th4ck3rx) 

---
Made with ❤️ by Neo

