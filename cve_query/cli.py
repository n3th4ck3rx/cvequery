import argparse

def parse_args():
    """Setup and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Fetch vulnerability and CPE details using Shodan's CVE database API",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # CVE Details
    cve_group = parser.add_argument_group("CVE Details", "Options for fetching detailed information about a specific CVE")
    cve_group.add_argument(
        "-c", "--cve",
        help="Fetch detailed information about a specific CVE by its ID (e.g., CVE-2023-12345).",
        type=str
    )

    # CVEs Search
    cves_group = parser.add_argument_group("CVEs Search", "Options for searching vulnerabilities")
    cves_group.add_argument(
        "--product",
        help="Search for vulnerabilities related to a specific product (e.g., ubuntu, apache).",
        type=str
    )
    cves_group.add_argument(
        "--cpe23",
        help="Search for vulnerabilities using a specific CPE 2.3 identifier (e.g., cpe:2.3:a:libpng:libpng:0.8).",
        type=str
    )
    cves_group.add_argument(
        "--severity",
        help="Filter CVEs by severity levels (e.g., info, low, medium, high, critical).",
        type=str
    )
    cves_group.add_argument(
        "--is-kev",
        help="Retrieve only Known Exploited Vulnerabilities (KEV).",
        action="store_true"
    )
    cves_group.add_argument(
        "--sort-by-epss",
        help="Sort CVEs by their EPSS score in descending order.",
        action="store_true"
    )
    cves_group.add_argument(
        "--start-date",
        help="Filter vulnerabilities published on or after this date (YYYY-MM-DD).",
        type=str
    )
    cves_group.add_argument(
        "--end-date",
        help="Filter vulnerabilities published on or before this date (YYYY-MM-DD).",
        type=str
    )
    cves_group.add_argument(
        "--count",
        help="Retrieve only the total count of matching vulnerabilities.",
        action="store_true"
    )
    cves_group.add_argument(
        "--skip-cves",
        help="Skip a specific number of vulnerabilities (for pagination).",
        type=int,
        default=0
    )
    cves_group.add_argument(
        "--limit-cves",
        help="Limit the number of vulnerabilities returned in a single query (default: 100).",
        type=int,
        default=100
    )
    cves_group.add_argument(
        "--only-cve-ids",
        help="Display only CVE IDs in the output.",
        action="store_true"
    )
    cves_group.add_argument(
        "-mc", "--multiple-cves",
        help="Query multiple CVEs at once, either from a file or comma-separated string.",
        type=str
    )

    # CPE Lookup
    cpe_group = parser.add_argument_group("CPE Lookup", "Options for retrieving CPEs related to a product")
    cpe_group.add_argument(
        "-p", "--product-cpe",
        help="Fetch CPEs for a specific product (e.g., ubuntu, macos).",
        type=str
    )
    cpe_group.add_argument(
        "--skip-cpe",
        help="Skip a specific number of CPEs (for pagination).",
        type=int,
        default=0
    )
    cpe_group.add_argument(
        "--limit-cpe",
        help="Limit the number of CPEs returned in a single query (default: 100).",
        type=int,
        default=100
    )

    # Update Options
    update_group = parser.add_argument_group("Update", "Options to auto-update the script.")
    update_group.add_argument(
        "-up", "--update",
        help="Auto-update the script to the latest version.",
        action="store_true"
    )

    # Output Options
    output_group = parser.add_argument_group("Output Options", "Options for saving or formatting the output")
    output_group.add_argument(
        "-j", "--jsonl",
        help="Save the output in JSON format (e.g., output.json).",
        nargs="?",
        const="data.json"
    )
    output_group.add_argument(
        "-f", "--fields",
        help="Display only specific fields from the output (comma-separated, e.g., cvss,summary).",
        type=str
    )
    output_group.add_argument(
        "-fl", "--fields-list",
        help="List all available fields that can be displayed.",
        action="store_true"
    )

    return parser.parse_args()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch vulnerability and CPE details using Shodan's CVE database API",
        formatter_class=argparse.RawTextHelpFormatter
    )
    args = parse_args()
    parser.print_help()


