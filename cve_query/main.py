from cli import parse_args
from api import get_cve_data, get_cves_data, get_cpe_data
from utils import filter_by_severity, save_to_json, colorize_output, validate_date


def main():
    args = parse_args()

    # Handle --update
    if args.update:
        print("Updating script...")
        # Simulate a git pull or update logic here
        return

    # Handle --fields-list
    if args.fields_list:
        fields = [
            "cve_id", "summary", "cvss", "cvss_v2", "cvss_v3", "epss",
            "ranking_epss", "kev", "references", "published_time", "cpes",
            "propose_action", "ransomware_campaign"
        ]
        print("Available fields:")
        for field in fields:
            print(f"- {field}")
        return

    # Handle CVE Details
    if args.cve:
        data = get_cve_data(args.cve)
        if data:
            fields = args.fields.split(",") if args.fields else data.keys()
            colorize_output(data, fields)
            if args.jsonl:
                save_to_json(data, args.jsonl)

    # Handle CVEs Search
    if any([args.product, args.cpe23, args.is_kev, args.severity, args.start_date, args.end_date]):
        if args.start_date and not validate_date(args.start_date):
            print("Invalid start-date format. Use YYYY-MM-DD.")
            return
        if args.end_date and not validate_date(args.end_date):
            print("Invalid end-date format. Use YYYY-MM-DD.")
            return

        severity_levels = args.severity.split(",") if args.severity else None
        data = get_cves_data(
            product=args.product,
            cpe23=args.cpe23,
            is_kev=args.is_kev,
            sort_by_epss=args.sort_by_epss,
            start_date=args.start_date,
            end_date=args.end_date,
            skip=args.skip_cves,
            limit=args.limit_cves
        )
        if severity_levels:
            data = filter_by_severity(data, severity_levels)

        if args.count:
            print(f"Total CVEs: {data.get('total', 'Unknown')}")
            return

        if args.only_cve_ids:
            cve_ids = [cve["cve_id"] for cve in data.get("cves", [])]
            print("\n".join(cve_ids))
            if args.jsonl:
                save_to_json({"cves": cve_ids}, args.jsonl)
        else:
            for cve in data.get("cves", []):
                fields = args.fields.split(",") if args.fields else cve.keys()
                colorize_output(cve, fields)
            if args.jsonl:
                save_to_json(data, args.jsonl)

    # Handle CPE Lookup
    if args.product_cpe:
        data = get_cpe_data(args.product_cpe, skip=args.skip_cpe, limit=args.limit_cpe)
        if not data or not data.get("cpes"):
            print("No CPEs found for the specified product.")
            return

        print(f"Total CPEs: {data.get('total', 'Unknown')}")
        for cpe in data.get("cpes", []):
            print(cpe)
        if args.jsonl:
            save_to_json(data, args.jsonl)


if __name__ == "__main__":
    main()

