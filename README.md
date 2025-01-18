
---

# **CVE-Query**

### **A Powerful CLI Tool for Vulnerability Research and Analysis**

**CVE-Query** is a Python-based command-line tool tailored for security researchers, bug bounty hunters, and IT professionals. It simplifies querying vulnerabilities (CVEs) and Common Platform Enumeration (CPEs) from Shodan's CVE database API, offering rich filtering, customization, and batch processing capabilities.

---

## **Features**

### ✅ Query CVE Details
- Fetch detailed information about a specific CVE by its ID.
- Process multiple CVEs in a single command (via a list or file).

### ✅ Search CVEs by Filters
- Search vulnerabilities by:
  - Product name.
  - CPE 2.3 identifier.
  - Severity level (e.g., info, low, medium, high, critical).
  - Date range (start and end dates).
- Filter Known Exploited Vulnerabilities (KEV).
- Sort vulnerabilities by EPSS (Exploit Prediction Scoring System).

### ✅ Fetch CPEs
- Retrieve CPEs (Common Platform Enumeration) for a specific product.

### ✅ Customizable Output
- Display only CVE IDs for a concise output.
- Save results to a plain text or JSON file.
- Optionally disable colorized output for better compatibility with logs.

---

## **Installation**

### **From PyPI**
Install the tool directly via `pip`:
```bash
pip install cve-query
```

---

### **From Source**
Clone the repository and install locally:
```bash
git clone https://github.com/n3th4ck3rx/cve-query.git
cd cve-query
pip install .
```

---

## **Usage**

Run the `cve-query` command followed by the desired flags and options.

---

### **Basic Examples**

#### **1. Fetch Details for a Single CVE**
Retrieve information for a specific CVE:
```bash
cve-query -c CVE-2023-12345
```

#### **2. Query Multiple CVEs**
Query multiple CVEs via a comma-separated list:
```bash
cve-query --mc CVE-2023-12345,CVE-2023-67890
```
Or provide a file containing CVE IDs:
```bash
cve-query --mc cves.txt
```

#### **3. Search CVEs by Product**
Find vulnerabilities related to a specific product:
```bash
cve-query --product apache
```

#### **4. Filter CVEs by Severity**
Filter CVEs based on impact severity:
```bash
cve-query --severity critical
```

#### **5. Retrieve Known Exploited Vulnerabilities**
Fetch only KEVs (Known Exploited Vulnerabilities):
```bash
cve-query --is-kev
```

#### **6. Fetch CPEs for a Product**
Retrieve Common Platform Enumeration data:
```bash
cve-query -p ubuntu
```

#### **7. Save Output to a File**
Save results in plain text:
```bash
cve-query --product apache -o output.txt
```
Or save in JSON format:
```bash
cve-query --product apache -j output.json
```

---

### **All Flags and Options**

#### **CVE Details**:
| Flag                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `-c`, `--cve`         | Fetch details about a specific CVE by its ID.    |
| `--mc`, `--multiple-cves` | Process multiple CVEs (comma-separated list or a file). |

#### **CVEs Search**:
| Flag                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `--product`           | Search vulnerabilities by product name.         |
| `--cpe23`             | Search vulnerabilities by a specific CPE 2.3 identifier. |
| `--severity`          | Filter CVEs by severity (e.g., info, low, medium, high, critical). |
| `--is-kev`            | Retrieve Known Exploited Vulnerabilities (KEV). |
| `--sort-by-epss`      | Sort vulnerabilities by EPSS score in descending order. |
| `--start-date`        | Filter CVEs published on or after this date (YYYY-MM-DD). |
| `--end-date`          | Filter CVEs published on or before this date (YYYY-MM-DD). |
| `--count`             | Retrieve only the total count of matching CVEs. |
| `--skip`              | Skip a specific number of CVEs (pagination).    |
| `--limit`             | Limit the number of CVEs returned (default: 100). |

#### **CPE Lookup**:
| Flag                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `-p`, `--product-cpe` | Retrieve CPEs for a specific product.            |
| `--skip`              | Skip a specific number of CPEs (pagination).    |
| `--limit`             | Limit the number of CPEs returned (default: 100). |

#### **Output Options**:
| Flag                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `-o`, `--output`      | Save the output to a plain text file.            |
| `-j`, `--jsonl`       | Save the output in JSON format.                  |
| `--only-cve-ids`      | Display only CVE IDs in the output.              |
| `-nc`, `--no-color`   | Disable colored output for logs or plain text.   |

---

## **Advanced Examples**

#### **Combine Multiple Filters**
Fetch vulnerabilities for a product within a date range, filter by severity, and save results:
```bash
cve-query --product apache --start-date 2023-01-01 --end-date 2023-12-31 --severity high -o high_vulns.txt
```

#### **Batch Process CVEs**
Batch process CVEs from a file and output only CVE IDs:
```bash
cve-query --mc cves.txt --only-cve-ids -o cve_ids.txt
```

---

### **Upcoming Features**
- **Autocomplete**: Command and flag autocompletion for faster workflows.
- **Progress Tracking**: Real-time progress for batch CVE processing.
- **Integration with Security Tools**: Compatibility with tools like Nmap and Nessus.

---

## **Contributing**
We welcome contributions from the community! Whether you’re fixing bugs, suggesting features, or improving documentation:
- Fork the repository.
- Create a feature branch.
- Submit a pull request.

Check out our [contribution guidelines](CONTRIBUTING.md) for more details.

---

## **License**
This project is licensed under the [MIT License](LICENSE).

---

