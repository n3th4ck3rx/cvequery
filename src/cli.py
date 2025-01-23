import click
from typing import Optional
from api import get_cve_data, get_cves_data, get_cpe_data
from utils import (
    filter_by_severity, save_to_json, colorize_output, 
    validate_date, sort_by_epss_score
)
from __version__ import __version__
import subprocess
import sys

def validate_mutually_exclusive(ctx, param, value):
    """Validate mutually exclusive parameters."""
    if value is None:
        return value
    
    # Get all parameter values
    params = ctx.params
    
    # Define mutually exclusive groups
    cve_group = ['cve', 'multiple_cves', 'product_cpe']
    search_group = ['product_cve', 'cpe23']
    
    if param.name in cve_group and any(params.get(p) for p in cve_group if p != param.name):
        raise click.BadParameter(
            f"--{param.name} cannot be used with other CVE query options"
        )
    
    if param.name in search_group and any(params.get(p) for p in search_group if p != param.name):
        raise click.BadParameter(
            f"--{param.name} cannot be used with other search options"
        )
    
    return value

def process_multiple_cves(cve_list: str, fields: Optional[str], jsonl: Optional[str], only_cve_ids: bool) -> None:
    """Process multiple CVEs from a comma-separated list or file."""
    cves = []
    if "," in cve_list:
        cves = [cve.strip() for cve in cve_list.split(",")]
    else:
        try:
            with open(cve_list, 'r') as f:
                cves = [line.strip() for line in f if line.strip()]
        except IOError:
            click.echo(f"Error: Could not read file {cve_list}", err=True)
            return

    results = []
    for cve_id in cves:
        data = get_cve_data(cve_id)
        if data and "error" not in data:
            if only_cve_ids:
                results.append(data.get("cve_id", "Unknown"))
            else:
                results.append(data)
                if not jsonl:
                    fields_list = fields.split(",") if fields else data.keys()
                    colorize_output(data, fields_list)
                    click.echo("=" * 80)

    if jsonl:
        save_to_json({"cves": results}, jsonl)

def process_cpe_lookup(product_cpe: str, skip: int, limit: int, jsonl: Optional[str], count: bool = False) -> None:
    """Process CPE lookup request."""
    data = get_cpe_data(product_cpe, skip, limit)
    
    if "error" in data:
        click.echo(f"Error: {data['error']}", err=True)
        sys.exit(1)
    
    if not data.get("cpes"):
        click.echo("No CPEs found for the specified product")
        return
    
    # Handle count flag
    if count:
        click.echo(f"Total CPEs found: {data['total']}")
        return
    
    if jsonl:
        save_to_json(data, jsonl)
        return
    
    # Display results
    click.echo(f"Total CPEs found: {data['total']}")
    for cpe in data["cpes"]:
        click.echo(cpe)

def process_cve_search(
    product_cve: Optional[str],
    cpe23: Optional[str],
    is_kev: bool,
    severity: Optional[str],
    start_date: Optional[str],
    end_date: Optional[str],
    sort_by_epss: bool,
    skip: int,
    limit: int,
    fields: Optional[str],
    json_file: Optional[str],
    only_cve_ids: bool,
    count: bool
) -> None:
    """Process CVE search request."""
    # Convert severity string to list and validate
    if severity:
        severity_levels = [s.strip() for s in severity.lower().split(',')]
        valid_levels = {"critical", "high", "medium", "low", "none"}
        invalid_levels = set(severity_levels) - valid_levels
        if invalid_levels:
            click.echo(f"Invalid severity levels: {', '.join(invalid_levels)}", err=True)
            click.echo(f"Valid levels are: {', '.join(valid_levels)}", err=True)
            sys.exit(1)
    else:
        severity_levels = None
    
    # Get CVE data
    data = get_cves_data(
        product=product_cve,
        cpe23=cpe23,
        is_kev=is_kev,
        sort_by_epss=sort_by_epss,
        start_date=start_date,
        end_date=end_date,
        skip=skip,
        limit=limit
    )
    
    if "error" in data:
        click.echo(f"Error: {data['error']}", err=True)
        sys.exit(1)

    # Apply severity filtering if specified
    if severity_levels:
        data = filter_by_severity(data, severity_levels)
        if not data["cves"]:
            click.echo(f"No CVEs found matching severity levels: {severity}")
            return

    # Handle output
    if count:
        click.echo(f"Total CVEs found: {data.get('total', 0)}")
        return

    if only_cve_ids:
        # Extract only CVE IDs
        cve_ids = [cve.get("cve_id", "Unknown") for cve in data.get("cves", [])]
        if json_file:
            save_to_json({"cve_ids": cve_ids}, json_file)
            return
        for cve_id in cve_ids:
            click.echo(cve_id)
        return

    if json_file:
        save_to_json(data, json_file)
        return

    # Display results
    fields_list = fields.split(",") if fields else None
    for cve in data.get("cves", []):
        colorize_output(cve, fields_list or cve.keys())
        click.echo("-" * 80)

def update_package():
    """Update the package using pipx."""
    try:
        # Check if pipx is installed
        subprocess.run(["pipx", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        click.echo("Error: pipx is not installed. Install it with: python -m pip install --user pipx", err=True)
        return False

    try:
        # Update the package
        result = subprocess.run(
            ["pipx", "upgrade", "cvequery"],
            capture_output=True,
            text=True,
            check=True
        )
        click.echo(result.stdout)
        click.echo("Successfully updated cvequery!")
        return True
    except subprocess.CalledProcessError as e:
        click.echo(f"Error updating package: {e.stderr}", err=True)
        return False

@click.command()
@click.version_option(version=__version__, prog_name="cvequery")  # Add version option
@click.option('-c', '--cve', callback=validate_mutually_exclusive, help='Get details for a specific CVE ID')
@click.option('-mc', '--multiple-cves', callback=validate_mutually_exclusive, help='Query multiple CVEs (comma-separated or file path)')
@click.option('-pcve', '--product-cve', callback=validate_mutually_exclusive, help='Search CVEs by product name')
@click.option('-k', '--is-kev', is_flag=True, help='Show only Known Exploited Vulnerabilities')
@click.option('-s', '--severity', help='Filter by severity levels (comma-separated: critical,high,medium,low)')
@click.option('-sd', '--start-date', help='Start date for CVE search (YYYY-MM-DD)')
@click.option('-ed', '--end-date', help='End date for CVE search (YYYY-MM-DD)')
@click.option('--cpe23', callback=validate_mutually_exclusive, help='Search CVEs by CPE 2.3 string')
@click.option('-pcpe', '--product-cpe', help='Search by product name (e.g., apache or nginx)')
@click.option('-epss','--sort-by-epss', is_flag=True, help='Sort results by EPSS score')
@click.option('-f', '--fields', help='Comma-separated list of fields to display')
@click.option('-j', '--json', help='Save output to JSON file')
@click.option('-oci', '--only-cve-ids', is_flag=True, help='Output only CVE IDs')
@click.option('--count', is_flag=True, help='Show only the total count of results')
@click.option('--skip-cves', type=int, help='Number of CVEs to skip')
@click.option('--limit-cves', type=int, help='Maximum number of CVEs to return')
@click.option('--skip-cpe', type=int, help='Number of CPEs to skip')
@click.option('--limit-cpe', type=int, help='Maximum number of CPEs to return')
@click.option('-up', '--update', is_flag=True, help='Update the script to the latest version')
@click.option('-fl', '--fields-list', is_flag=True, help='List all available fields')
def cli(**kwargs):
    """CVE Query Tool - Search and analyze CVE data from Shodan's CVE database."""
    try:
        # Handle utility options first
        if kwargs.get('update'):
            click.echo(f"Current version: {__version__}")  # Show current version before update
            if update_package():
                sys.exit(0)
            else:
                sys.exit(1)

        if kwargs.get('fields_list'):
            fields = [
                "id", "summary", "cvss", "cvss_v2", "cvss_v3", "epss",
                "epss_score", "kev", "references", "published", "modified",
                "cpes", "cwe"
            ]
            click.echo("Available fields:")
            for field in fields:
                click.echo(f"- {field}")
            return

        # Validate dates if provided
        if kwargs.get('start_date') and not validate_date(kwargs['start_date']):
            click.echo("Invalid start-date format. Use YYYY-MM-DD.", err=True)
            sys.exit(1)
        
        if kwargs.get('end_date') and not validate_date(kwargs['end_date']):
            click.echo("Invalid end-date format. Use YYYY-MM-DD.", err=True)
            sys.exit(1)

        # Handle CVE queries
        if kwargs.get('cve'):
            data = get_cve_data(kwargs['cve'])
            if data and "error" not in data:
                fields_list = kwargs.get('fields', '').split(",") if kwargs.get('fields') else data.keys()
                colorize_output(data, fields_list)
                if kwargs.get('json'):
                    save_to_json(data, kwargs['json'])
            return

        if kwargs.get('multiple_cves'):
            process_multiple_cves(
                kwargs['multiple_cves'],
                kwargs.get('fields'),
                kwargs.get('json'),
                kwargs.get('only_cve_ids', False)
            )
            return

        if kwargs.get('product_cpe'):
            process_cpe_lookup(
                kwargs['product_cpe'],
                kwargs.get('skip_cpe', 0),
                kwargs.get('limit_cpe', 1000),
                kwargs.get('json'),
                kwargs.get('count', False)
            )
            return

        # Handle CVE search with filters
        if any([kwargs.get(k) for k in ['product_cve', 'cpe23', 'is_kev', 'severity', 'start_date', 'end_date', 'sort_by_epss']]):
            process_cve_search(
                kwargs.get('product_cve'),
                kwargs.get('cpe23'),
                kwargs.get('is_kev', False),
                kwargs.get('severity'),
                kwargs.get('start_date'),
                kwargs.get('end_date'),
                kwargs.get('sort_by_epss', False),
                kwargs.get('skip_cves'),
                kwargs.get('limit_cves'),
                kwargs.get('fields'),
                kwargs.get('json'),
                kwargs.get('only_cve_ids', False),
                kwargs.get('count', False)
            )
            return

        # If no options specified, show help
        ctx = click.get_current_context()
        click.echo(ctx.get_help())

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

def main():
    cli(auto_envvar_prefix='CVE_QUERY')

if __name__ == '__main__':
    main()


