import click
from typing import Optional
from src.api import get_cve_data, get_cves_data, get_cpe_data, get_multiple_cves_parallel, batch_cve_lookup
from src.utils import (
    filter_by_severity, save_to_json, save_to_csv, save_to_yaml, save_to_xml, save_to_stix,
    colorize_output, validate_date, sort_by_epss_score
)
from src.formatting import format_cve_output, format_cve_list_output
from src.interactive import start_interactive_mode
from src.completion import (
    complete_cve_id, complete_product_name, complete_severity,
    complete_fields, complete_file_path, setup_completion,
    install_completion_automatically
)
from src.__version__ import __version__
from src.constants import PACKAGE_NAME, DEFAULT_LIMIT, SEVERITY_MAP
import subprocess
import sys

# Rich imports for beautiful CLI
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box
from rich.align import Align

# Initialize Rich console
console = Console()

# Context settings for Click command
CONTEXT_SETTINGS = dict(auto_envvar_prefix='CVE_QUERY')

def validate_mutually_exclusive(ctx, param, value):
    """Validate mutually exclusive parameters."""
    if value is None:
        return value
    
    # Get all parameter values
    params = ctx.params
    
    # Define mutually exclusive groups
    cve_group = ['cve', 'multiple_cves']
    search_group = ['product_cve', 'product_cpe', 'cpe23']
    
    # Check within group exclusivity
    if param.name in cve_group and any(params.get(p) for p in cve_group if p != param.name):
        raise click.BadParameter(
            f"--{param.name} cannot be used with other CVE query options"
        )
    
    if param.name in search_group and any(params.get(p) for p in search_group if p != param.name):
        raise click.BadParameter(
            f"--{param.name} cannot be used with other search options"
        )
    
    # Check cross-group exclusivity (CVE queries vs search queries)
    if param.name in cve_group and any(params.get(p) for p in search_group):
        raise click.BadParameter(
            f"--{param.name} cannot be used with search options"
        )
    
    if param.name in search_group and any(params.get(p) for p in cve_group):
        raise click.BadParameter(
            f"--{param.name} cannot be used with CVE query options"
        )
    
    return value

def validate_cve_id(ctx, param, value):
    """Validate CVE ID format."""
    if value is None:
        return value
    
    import re
    cve_pattern = r'^CVE-\d{4}-\d{4,}$'
    if not re.match(cve_pattern, value.upper()):
        raise click.BadParameter(
            f"Invalid CVE ID format: {value}. Expected format: CVE-YYYY-NNNN (e.g., CVE-2023-12345)"
        )
    
    return value.upper()

def validate_severity_levels(ctx, param, value):
    """Validate severity levels."""
    if value is None:
        return value
    
    severity_levels = [s.strip().lower() for s in value.split(',')]
    valid_levels = set(SEVERITY_MAP.keys())
    invalid_levels = set(severity_levels) - valid_levels
    
    if invalid_levels:
        raise click.BadParameter(
            f"Invalid severity levels: {', '.join(invalid_levels)}. "
            f"Valid levels are: {', '.join(sorted(valid_levels))}"
        )
    
    return value.lower()

def validate_date_format(ctx, param, value):
    """Validate date format (YYYY-MM-DD)."""
    if value is None:
        return value
    
    from src.utils import validate_date
    if not validate_date(value):
        raise click.BadParameter(
            f"Invalid date format: {value}. Expected format: YYYY-MM-DD (e.g., 2023-12-31)"
        )
    
    return value

def validate_positive_integer(ctx, param, value):
    """Validate positive integer values."""
    if value is None:
        return value
    
    if value < 0:
        raise click.BadParameter(f"Value must be a positive integer, got: {value}")
    
    return value

def validate_file_exists(ctx, param, value):
    """Validate that file exists."""
    if value is None:
        return value
    
    import os
    if not os.path.exists(value):
        raise click.BadParameter(f"File not found: {value}")
    
    if not os.path.isfile(value):
        raise click.BadParameter(f"Path is not a file: {value}")
    
    return value

def validate_directory_exists(ctx, param, value):
    """Validate that directory exists."""
    if value is None:
        return value
    
    import os
    if not os.path.exists(value):
        raise click.BadParameter(f"Directory not found: {value}")
    
    if not os.path.isdir(value):
        raise click.BadParameter(f"Path is not a directory: {value}")
    
    return value

def export_data(data, json_file=None, csv_file=None, yaml_file=None, xml_file=None, stix_file=None):
    """Export data to multiple formats based on provided file paths."""
    exports_performed = []
    
    try:
        if json_file:
            save_to_json(data, json_file)
            exports_performed.append(f"JSON: {json_file}")
        
        if csv_file:
            save_to_csv(data, csv_file)
            exports_performed.append(f"CSV: {csv_file}")
        
        if yaml_file:
            save_to_yaml(data, yaml_file)
            exports_performed.append(f"YAML: {yaml_file}")
        
        if xml_file:
            save_to_xml(data, xml_file)
            exports_performed.append(f"XML: {xml_file}")
        
        if stix_file:
            save_to_stix(data, stix_file)
            exports_performed.append(f"STIX 2.1: {stix_file}")
        
        if exports_performed:
            console.print()
            export_panel = Panel(
                "\n".join([f"📄 {export}" for export in exports_performed]),
                border_style="bright_green",
                title="✅ DATA EXPORTED SUCCESSFULLY",
                title_align="left",
                padding=(1, 2)
            )
            console.print(export_panel)
    
    except ImportError as e:
        console.print(f"❌ Export failed: {e}", style="red")
        console.print("💡 Install required dependencies:", style="yellow")
        if "yaml" in str(e).lower():
            console.print("   pip install PyYAML", style="bright_blue")
        if "stix" in str(e).lower():
            console.print("   pip install stix2", style="bright_blue")
    except Exception as e:
        console.print(f"❌ Export failed: {e}", style="red")

def process_multiple_cves(cve_list: str, fields: Optional[str], fields_exclude: Optional[str], json_file: Optional[str], csv_file: Optional[str], yaml_file: Optional[str], xml_file: Optional[str], stix_file: Optional[str], only_cve_ids: bool, detailed: bool, output_format: str = "compact") -> None:
    """Process multiple CVEs from a comma-separated list or file using parallel processing."""
    from src.api import get_multiple_cves_parallel, batch_cve_lookup
    import click
    
    cves = []
    if "," in cve_list:
        cves = [cve.strip() for cve in cve_list.split(",")]
    else:
        try:
            with open(cve_list, 'r') as f:
                cves = [line.strip() for line in f if line.strip()]
        except IOError:
            console.print(f"❌ Error: Could not read file {cve_list}", style="red")
            return

    if not cves:
        click.echo("No CVE IDs provided.", err=True)
        return

    # Use parallel processing for better performance
    click.echo(f"Fetching {len(cves)} CVEs in parallel...")
    
    if len(cves) <= 50:
        # Use direct parallel processing for smaller batches
        results_list = get_multiple_cves_parallel(cves)
    else:
        # Use batch processing for larger sets
        results_list = batch_cve_lookup(cves)
    
    # Process results
    results = []
    for data in results_list:
        if data and "error" not in data:
            if only_cve_ids:
                results.append(data.get("cve_id", "Unknown"))
            else:
                results.append(data)
        elif data and "error" in data:
            console.print(f"⚠️ Warning: Failed to fetch CVE: {data['error']}", style="yellow")

    # Handle exports
    if any([json_file, csv_file, yaml_file, xml_file, stix_file]):
        export_data({"cves": results}, json_file, csv_file, yaml_file, xml_file, stix_file)
        if not only_cve_ids:  # Don't show output if we're only exporting
            return

    if only_cve_ids:
        for cve_id in results:
            click.echo(cve_id)
    else:
        # Use enhanced formatting based on flags
        fields_list = fields.split(",") if fields else None
        fields_exclude_list = fields_exclude.split(",") if fields_exclude else None
        
        # Determine format to use
        if detailed:
            format_to_use = 'detailed'
        elif output_format in ['compact', 'summary']:
            format_to_use = output_format
        else:
            format_to_use = 'table'
        
        if len(results) == 1:
            # For single result, use appropriate single CVE format
            single_format = 'detailed' if format_to_use == 'detailed' else 'default'
            format_cve_output(results[0], single_format, fields_list, fields_exclude_list)
        else:
            # For multiple results, use list format
            format_cve_list_output(results, format_to_use, fields_list, fields_exclude_list)



def process_cpe_lookup(product_cpe: str, skip: int, limit: int, jsonl: Optional[str], count: bool = False) -> None:
    """Process CPE lookup request."""
    data = get_cpe_data(product_cpe, skip, limit)
    
    if "error" in data:
        console.print(f"❌ Error: {data['error']}", style="red")
        sys.exit(1)
    
    if not data.get("cpes"):
        console.print(f"ℹ️ No CPEs found for product '{product_cpe}'", style="yellow")
        return
    
    # Handle count flag
    if count:
        click.echo(f"Total CPEs found: {data['total']}")
        return
    
    if jsonl:
        save_to_json(data, jsonl)
        return
    
    # Display results with beautiful Rich formatting
    cpes = data["cpes"]
    total = data.get('total', len(cpes))
    
    # Parse CPE data and analyze content for dynamic column sizing
    parsed_data = []
    max_cpe_len = len("CPE String")
    max_product_len = len("Product")
    max_version_len = len("Version")
    
    for cpe in cpes:
        if isinstance(cpe, str):
            # Parse CPE to extract readable information
            parts = cpe.split(':')
            if len(parts) >= 6:
                vendor = parts[3] if parts[3] != '*' else 'Unknown'
                product = parts[4] if parts[4] != '*' else 'Unknown'
                version = parts[5] if parts[5] != '*' else 'Any'
                
                # Create readable product name
                readable_product = f"{vendor.title()} {product.replace('_', ' ').title()}"
                
                parsed_data.append((cpe, readable_product, version))
                
                # Track maximum lengths for dynamic sizing
                max_cpe_len = max(max_cpe_len, len(cpe))
                max_product_len = max(max_product_len, len(readable_product))
                max_version_len = max(max_version_len, len(version))
            else:
                parsed_data.append((cpe, "Unknown", "Unknown"))
                max_cpe_len = max(max_cpe_len, len(cpe))
                max_product_len = max(max_product_len, len("Unknown"))
                max_version_len = max(max_version_len, len("Unknown"))
    
    # Calculate dynamic column ratios based on content
    total_content_width = max_cpe_len + max_product_len + max_version_len
    if total_content_width > 0:
        cpe_ratio = max_cpe_len / total_content_width
        product_ratio = max_product_len / total_content_width
        version_ratio = max_version_len / total_content_width
        
        # Ensure minimum ratios for readability
        cpe_ratio = max(cpe_ratio, 0.3)  # CPE strings are usually long
        product_ratio = max(product_ratio, 0.25)
        version_ratio = max(version_ratio, 0.15)
        
        # Normalize ratios to sum to ~3 (good for 3 columns)
        total_ratio = cpe_ratio + product_ratio + version_ratio
        cpe_ratio = (cpe_ratio / total_ratio) * 3
        product_ratio = (product_ratio / total_ratio) * 3
        version_ratio = (version_ratio / total_ratio) * 3
    else:
        # Fallback ratios
        cpe_ratio, product_ratio, version_ratio = 1.5, 1.0, 0.5
    
    # Create beautiful CPE results table with dynamic sizing
    console.print()
    cpe_table = Table(
        show_header=True,
        box=box.ROUNDED,
        border_style="bright_cyan",
        title=f"🎯 FOUND {total} CPE(S) FOR '{product_cpe.upper()}'",
        title_style="bold bright_cyan",
        expand=True
    )
    cpe_table.add_column("CPE String", style="bright_white", ratio=cpe_ratio)
    cpe_table.add_column("Product", style="cyan", ratio=product_ratio)
    cpe_table.add_column("Version", style="bright_green", ratio=version_ratio)
    
    # Add all parsed data to table
    for cpe_string, readable_product, version in parsed_data:
        cpe_table.add_row(cpe_string, readable_product, version)
    
    console.print(cpe_table)
    console.print()
    
    # Show helpful tip
    if total > len(cpes):
        console.print(f"💡 Showing {len(cpes)} of {total} CPEs. Use --limit-cpe to see more.", style="bright_blue")
    
    console.print("💡 Use these CPE strings with --cpe23 flag to search for CVEs", style="bright_blue")

def process_cve_search(
    product_cve: Optional[str],
    cpe23: Optional[str],
    is_kev: bool,
    severity: Optional[str],
    start_date: Optional[str],
    end_date: Optional[str],
    sort_by_epss: bool,
    skip: int,
    limit: Optional[int],
    fields: Optional[str],
    fields_exclude: Optional[str],
    json_file: Optional[str],
    csv_file: Optional[str],
    yaml_file: Optional[str],
    xml_file: Optional[str],
    stix_file: Optional[str],
    only_cve_ids: bool,
    count: bool,
    detailed: bool,
    output_format: str = "table"
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
    
    # Determine API limit: use default if client-side filtering is active,
    # otherwise use user's limit or default if not specified by user.
    api_limit_to_pass = DEFAULT_LIMIT
    user_specified_limit = limit

    if not severity_levels and user_specified_limit is not None:
        api_limit_to_pass = user_specified_limit
    # If user_specified_limit is None (no --limit-cves flag), api_limit_to_pass remains DEFAULT_LIMIT
    # If severity filter is on, api_limit_to_pass remains DEFAULT_LIMIT to fetch enough for filtering.

    # Get CVE data
    data = get_cves_data(
        product=product_cve,
        cpe23=cpe23,
        is_kev=is_kev,
        sort_by_epss=sort_by_epss,
        start_date=start_date,
        end_date=end_date,
        skip=skip,
        limit=api_limit_to_pass
    )
    
    if "error" in data:
        console.print(f"❌ Error: {data['error']}", style="red")
        sys.exit(1)

    # Apply severity filtering if specified
    if severity_levels:
        data = filter_by_severity(data, severity_levels)
        if not data["cves"]:
            click.echo(f"No CVEs found matching severity levels: {severity}")
            return

    # Apply user-specified limit *after* client-side filtering
    # And before the count is determined if --count is used.
    if user_specified_limit is not None and data.get("cves"):
        data["cves"] = data["cves"][:user_specified_limit]
        data["total"] = len(data["cves"]) # Update total to reflect the limit

    # Handle output
    if count:
        # Calculate total from actual CVEs list since 'total' key may not exist
        total_count = data.get('total', len(data.get('cves', [])))
        click.echo(f"Total CVEs found: {total_count}")
        return

    # Handle exports
    if any([json_file, csv_file, yaml_file, xml_file, stix_file]):
        if only_cve_ids:
            cve_ids = [cve.get("cve_id", "Unknown") for cve in data.get("cves", [])]
            export_data({"cve_ids": cve_ids}, json_file, csv_file, yaml_file, xml_file, stix_file)
        else:
            export_data(data, json_file, csv_file, yaml_file, xml_file, stix_file)
        return

    if only_cve_ids:
        # Extract only CVE IDs
        cve_ids = [cve.get("cve_id", "Unknown") for cve in data.get("cves", [])]
        for cve_id in cve_ids:
            click.echo(cve_id)
        return

    # Display results using enhanced formatting
    fields_list = fields.split(",") if fields else None
    fields_exclude_list = fields_exclude.split(",") if fields_exclude else None
    cves = data.get("cves", [])
    
    if not cves:
        console.print("ℹ️ No CVEs found matching your criteria", style="yellow")
        return
    
    # Determine format to use based on flags and parameters
    if detailed:
        format_to_use = 'detailed'
    elif output_format in ['compact', 'summary']:
        format_to_use = output_format
    else:
        # Default behavior for search operations: show CVE IDs only
        cve_ids = [cve.get("cve_id", "Unknown") for cve in cves]
        console.print()
        cve_table = Table(
            show_header=True,
            box=box.ROUNDED,
            border_style="bright_cyan",
            title=f"🎯 FOUND {len(cve_ids)} CVE(S)",
            title_style="bold bright_cyan",
            expand=True
        )
        cve_table.add_column("CVE ID", style="bold bright_white", ratio=1)
        
        for cve_id in cve_ids:
            cve_table.add_row(cve_id)
        
        console.print(cve_table)
        console.print()
        console.print("💡 Use -d/--detailed flag to see full CVE information", style="bright_blue")
        return
    
    # Display results with the determined format
    format_cve_list_output(cves, format_to_use, fields_list, fields_exclude_list)

def suggest_related_commands(query_type: str, query_value: str) -> None:
    """Suggest related commands based on the current query."""
    suggestions = []
    
    if query_type == "cve":
        suggestions = [
            f"cvequery --product-cve {query_value.split('-')[0].lower()} --severity critical,high",
            f"cvequery --cve {query_value} --json {query_value.lower()}.json",
            f"cvequery --cve {query_value} --fields id,summary,cvss_v3,kev"
        ]
    elif query_type == "product":
        suggestions = [
            f"cvequery --product-cve {query_value} --is-kev",
            f"cvequery --product-cve {query_value} --start-date 2023-01-01",
            f"cvequery --product-cve {query_value} --format table --json {query_value}_report.json"
        ]

    
    if suggestions:
        click.echo(f"\n💡 Related commands you might find useful:")
        for suggestion in suggestions[:3]:  # Show max 3 suggestions
            click.echo(f"   {suggestion}")

def update_package():
    """Update the package using pipx."""
    try:
        # Check if pipx is installed
        subprocess.run(["pipx", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print("❌ Error: pipx is not installed. Install it with: python -m pip install --user pipx", style="red")
        return False

    try:
        # Update the package
        result = subprocess.run(
            ["pipx", "upgrade", PACKAGE_NAME],
            capture_output=True,
            text=True,
            check=True
        )
        click.echo(result.stdout)
        console.print("✅ Successfully updated cvequery!", style="bright_green")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"❌ Error updating package: {e.stderr}", style="red")
        return False

# Create custom command class for organized help output
class OrganizedCommand(click.Command):
    def format_help(self, ctx, formatter):
        """Writes the help into the formatter if it exists."""
        self.format_usage(ctx, formatter)
        self.format_help_text(ctx, formatter)
        self.format_options(ctx, formatter)
        self.format_examples_and_tips(ctx, formatter)
        self.format_epilog(ctx, formatter)
    
    def format_examples_and_tips(self, ctx, formatter):
        """Add examples, supported formats, and tips at the end."""
        with formatter.section('Examples'):
            formatter.write_text("""
# Query specific CVE (normal info)
cvequery --cve CVE-2023-12345

# Query specific CVE with full details
cvequery --cve CVE-2023-12345 --detailed

# Search by product (shows CVE IDs only)
cvequery --product-cve apache --severity critical,high

# Search by product with full details
cvequery --product-cve apache --detailed

# Interactive mode
cvequery --interactive
""".strip())
        
        with formatter.section('Tips'):
            formatter.write_text("""
• Use --interactive for guided queries
• Product searches show CVE IDs by default, use -d/--detailed for full info
• Install shell completion: --install-completion
• Get field list: --fields-list
• Set CVEQUERY_DEBUG=1 for detailed error information
""".strip())

    def format_options(self, ctx, formatter):
        """Writes all the options into the formatter organized by category."""
        opts = []
        for param in self.get_params(ctx):
            rv = param.get_help_record(ctx)
            if rv is not None:
                opts.append(rv)

        if opts:
            # Define option categories
            query_opts = []
            filter_opts = []
            output_opts = []

            utility_opts = []
            
            # Categorize options based on their names and purposes
            for opt in opts:
                opt_name = opt[0].lower()
                
                # Query Options
                if any(x in opt_name for x in ['-c,', '--cve', '-mc,', '--multiple-cves', '-pcve,', '--product-cve', '--cpe23', '-pcpe,', '--product-cpe']):
                    query_opts.append(opt)
                
                # Filter & Search Options  
                elif any(x in opt_name for x in ['-k,', '--is-kev', '-s,', '--severity', '-sd,', '--start-date', '-ed,', '--end-date', '-epss,', '--sort-by-epss', '-scv,', '--skip-cves', '-lcv,', '--limit-cves', '-scp,', '--skip-cpe', '-lcp,', '--limit-cpe']):
                    filter_opts.append(opt)
                
                # Output & Format Options
                elif any(x in opt_name for x in ['-d,', '--detailed', '-f,', '--fields', '--format', '-oci,', '--only-cve-ids', '--count', '-j,', '--json', '--csv', '--yaml', '--xml', '--stix']):
                    output_opts.append(opt)
                

                
                # Utility Options (everything else including --version, --help, etc.)
                else:
                    utility_opts.append(opt)
            
            # Write organized sections
            if query_opts:
                with formatter.section('Query Options'):
                    formatter.write_dl(query_opts)
            
            if filter_opts:
                with formatter.section('Filter & Search Options'):
                    formatter.write_dl(filter_opts)
            
            if output_opts:
                with formatter.section('Output & Format Options'):
                    formatter.write_dl(output_opts)
            

            if utility_opts:
                with formatter.section('Utility Options'):
                    formatter.write_dl(utility_opts)

@click.command(PACKAGE_NAME, context_settings=CONTEXT_SETTINGS, cls=OrganizedCommand)
@click.version_option(version=__version__, prog_name=PACKAGE_NAME)
# Query Options
@click.option('-c', '--cve', callback=lambda ctx, param, value: validate_cve_id(ctx, param, validate_mutually_exclusive(ctx, param, value)), 
              shell_complete=complete_cve_id, help='Get details for a specific CVE ID')
@click.option('-mc', '--multiple-cves', callback=validate_mutually_exclusive, shell_complete=complete_file_path, 
              help='Query multiple CVEs (comma-separated or file path)')
@click.option('-pcve', '--product-cve', callback=validate_mutually_exclusive, shell_complete=complete_product_name, 
              help='Search CVEs by product name')
@click.option('--cpe23', callback=validate_mutually_exclusive, 
              help='Search CVEs by CPE 2.3 string')
@click.option('-pcpe', '--product-cpe', shell_complete=complete_product_name, 
              help='Search by product name (e.g., apache or nginx)')

# Filter & Search Options
@click.option('-k', '--is-kev', is_flag=True, 
              help='Show only Known Exploited Vulnerabilities')
@click.option('-s', '--severity', callback=validate_severity_levels, shell_complete=complete_severity, 
              help='Filter by severity levels (comma-separated: critical,high,medium,low,none)')
@click.option('-sd', '--start-date', callback=validate_date_format,
              help='Start date for CVE search (YYYY-MM-DD)')
@click.option('-ed', '--end-date', callback=validate_date_format,
              help='End date for CVE search (YYYY-MM-DD)')
@click.option('-epss','--sort-by-epss', is_flag=True, 
              help='Sort results by EPSS score')
@click.option('-scv', '--skip-cves', type=int, default=0, callback=validate_positive_integer,
              help='Number of CVEs to skip (default: 0)')
@click.option('-lcv', '--limit-cves', type=int, callback=validate_positive_integer,
              help='Maximum number of CVEs to return')
@click.option('-scp', '--skip-cpe', type=int, default=0, callback=validate_positive_integer,
              help='Number of CPEs to skip (default: 0)')
@click.option('-lcp', '--limit-cpe', type=int, default=1000, callback=validate_positive_integer,
              help='Maximum number of CPEs to return (default: 1000)')

# Output & Format Options
@click.option('-d', '--detailed', is_flag=True, 
              help='Show detailed CVE information without truncation')
@click.option('-f', '--fields', shell_complete=complete_fields, 
              help='Comma-separated list of fields to display')
@click.option('-fe', '--fields-exclude', shell_complete=complete_fields,
              help='Comma-separated list of fields to exclude from display')
@click.option('--format', 'output_format', type=click.Choice(['compact', 'summary']), default=None, 
              help='Output format (compact or summary)')
@click.option('-oci', '--only-cve-ids', is_flag=True, 
              help='Output only CVE IDs')
@click.option('--count', is_flag=True, 
              help='Show only the total count of results')
@click.option('-j', '--json', "json_output_file", shell_complete=complete_file_path, 
              help='Save output to JSON file')
@click.option('--csv', "csv_output_file", shell_complete=complete_file_path, 
              help='Save output to CSV file (cybersecurity optimized)')
@click.option('--yaml', "yaml_output_file", shell_complete=complete_file_path, 
              help='Save output to YAML file (automation friendly)')
@click.option('--xml', "xml_output_file", shell_complete=complete_file_path, 
              help='Save output to XML file (enterprise integration)')
@click.option('--stix', "stix_output_file", shell_complete=complete_file_path, 
              help='Save output to STIX 2.1 file (threat intelligence)')



# Utility Options
@click.option('-i', '--interactive', is_flag=True, 
              help='Start interactive mode', is_eager=True)
@click.option('-fl', '--fields-list', is_flag=True, 
              help='List all available fields', is_eager=True)
@click.option('-up', '--update', is_flag=True, 
              help='Update the script to the latest version')
@click.option('--setup-completion', type=click.Choice(['auto', 'windows', 'linux', 'macos'], case_sensitive=False), 
              help='Setup shell completion for specified platform (auto-detects if not specified)', is_eager=True)
@click.option('--install-completion', is_flag=True, 
              help='Automatically install shell completion for current platform', is_eager=True)
@click.pass_context
def cli(ctx, **kwargs):
    """CVE Query Tool - Search and analyze CVE data from Shodan's CVE database."""
    try:
        # Set up better error handling and debugging
        import os
        debug_mode = os.getenv('CVEQUERY_DEBUG', '').lower() in ('1', 'true', 'yes')
        
        # Check for common user errors and provide guidance
        provided_options = [k for k, v in kwargs.items() if v is not None and v is not False and v != 0]
        if not provided_options:
            examples_panel = Panel(
                """🔍 Single CVE lookup (normal info):
   cvequery --cve CVE-2023-12345

🔍 Single CVE with full details:
   cvequery --cve CVE-2023-12345 --detailed

🔎 Product search (CVE IDs only):
   cvequery --product-cve apache --severity critical

🔍 Product search with full details:
   cvequery --product-cve apache --detailed

🎯 Interactive mode:
   cvequery --interactive

💡 Use --help for full documentation.""",
                border_style="bright_blue",
                title="💡 QUICK EXAMPLES",
                title_align="left",
                padding=(1, 2)
            )
            console.print(examples_panel)
            click.echo("\nUse --help for full documentation.")
            ctx.exit(0)
        
        # Handle eager options first
        if kwargs.get('interactive'):
            start_interactive_mode()
            ctx.exit()
        
        if kwargs.get('setup_completion'):
            platform_choice = kwargs.get('setup_completion', 'auto')
            completion_instructions = setup_completion(platform_choice)
            click.echo(completion_instructions)
            ctx.exit()
        
        if kwargs.get('install_completion'):
            click.echo("ⴵ Installing shell completion automatically...")
            success, message = install_completion_automatically('auto')
            if success:
                click.echo(f"✔ {message}")
            else:
                click.echo(f"✖ {message}", err=True)
            ctx.exit(0 if success else 1)
        
        if kwargs.get('fields_list'):
            _fields_available = [
                "cve_id", "summary", "cvss", "cvss_v2", "cvss_v3", "cvss_version", 
                "epss", "ranking_epss", "kev", "propose_action", "ransomware_campaign", 
                "references", "published_time", "published", "modified", "cpes"
            ]
            click.echo("Available fields:")
            for f_item in _fields_available: click.echo(f"- {f_item}")
            return
        
        if kwargs.get('update'):
            click.echo(f"Current version: {__version__} of {PACKAGE_NAME}")
            if update_package(): ctx.exit(0)
        

        if kwargs.get('start_date') and not validate_date(kwargs['start_date']): 
            console.print("❌ Invalid start-date format. Use YYYY-MM-DD.", style="red")
            ctx.exit(1)
        if kwargs.get('end_date') and not validate_date(kwargs['end_date']): 
            console.print("❌ Invalid end-date format. Use YYYY-MM-DD.", style="red")
            ctx.exit(1)

        if kwargs.get('cve'):
            data = get_cve_data(kwargs['cve'])
            if data and "error" not in data:
                # Handle exports
                if any([kwargs.get('json_output_file'), kwargs.get('csv_output_file'), 
                       kwargs.get('yaml_output_file'), kwargs.get('xml_output_file'), 
                       kwargs.get('stix_output_file')]):
                    export_data(data, kwargs.get('json_output_file'), kwargs.get('csv_output_file'),
                               kwargs.get('yaml_output_file'), kwargs.get('xml_output_file'),
                               kwargs.get('stix_output_file'))
                else:
                    # Show CVE info with appropriate format
                    fields_to_show = kwargs.get('fields').split(",") if kwargs.get('fields') else None
                    fields_to_exclude = kwargs.get('fields_exclude').split(",") if kwargs.get('fields_exclude') else None
                    
                    # Determine format to use
                    if kwargs.get('detailed', False):
                        format_to_use = 'detailed'
                    elif kwargs.get('output_format') in ['compact', 'summary']:
                        format_to_use = kwargs.get('output_format')
                    else:
                        format_to_use = 'default'
                    
                    # For summary format, use list formatter even for single CVE
                    if format_to_use == 'summary':
                        format_cve_list_output([data], format_to_use, fields_to_show, fields_to_exclude)
                    else:
                        format_cve_output(data, format_to_use, fields_to_show, fields_to_exclude)
            else:
                console.print(f"❌ Error: {data.get('error', 'CVE not found')}", style="red")
            return

        if kwargs.get('multiple_cves'): 
            process_multiple_cves(
                kwargs['multiple_cves'], 
                kwargs.get('fields'), 
                kwargs.get('fields_exclude'),
                kwargs.get('json_output_file'),
                kwargs.get('csv_output_file'),
                kwargs.get('yaml_output_file'),
                kwargs.get('xml_output_file'),
                kwargs.get('stix_output_file'),
                kwargs.get('only_cve_ids', False),
                kwargs.get('detailed', False),
                kwargs.get('output_format', 'compact')
            )
            return
        

        
        if kwargs.get('product_cpe'): 
            process_cpe_lookup(kwargs['product_cpe'], kwargs.get('skip_cpe'), kwargs.get('limit_cpe'), kwargs.get('json_output_file'), kwargs.get('count', False)); return

        # Check if any search-related flags are present to call process_cve_search
        search_flags_present = any([
            kwargs.get('product_cve'), kwargs.get('cpe23'), kwargs.get('is_kev'), 
            kwargs.get('severity'), kwargs.get('start_date'), kwargs.get('end_date'), 
            kwargs.get('sort_by_epss'), 
            kwargs.get('skip_cves', 0) > 0, # Check if default is overridden
            kwargs.get('limit_cves') is not None,
            kwargs.get('count') # If only --count is passed, it implies a general search
        ])

        if search_flags_present:
            process_cve_search(
                kwargs.get('product_cve'), kwargs.get('cpe23'), kwargs.get('is_kev', False), 
                kwargs.get('severity'), kwargs.get('start_date'), kwargs.get('end_date'),
                kwargs.get('sort_by_epss', False), kwargs.get('skip_cves'), kwargs.get('limit_cves'), 
                kwargs.get('fields'), kwargs.get('fields_exclude'), kwargs.get('json_output_file'),
                kwargs.get('csv_output_file'), kwargs.get('yaml_output_file'),
                kwargs.get('xml_output_file'), kwargs.get('stix_output_file'),
                kwargs.get('only_cve_ids', False), kwargs.get('count', False),
                kwargs.get('detailed', False), kwargs.get('output_format')
            )
            return
        
        # If no relevant options specified (and not handled by eager options that exit), show help.
        # This covers the case where the script is called with no arguments or only --version/--help.
        if not (kwargs.get('fields_list') or kwargs.get('update') or kwargs.get('cve') or kwargs.get('multiple_cves') or kwargs.get('product_cpe') or search_flags_present):
             click.echo(ctx.get_help())

    except KeyboardInterrupt:
        click.echo("\n⚠️  Operation cancelled by user.", err=True)
        ctx.exit(130)  # Standard exit code for SIGINT
    except click.ClickException:
        # Re-raise Click exceptions to preserve their formatting
        raise
    except Exception as e:
        if debug_mode:
            import traceback
            click.echo(f"\n🐛 Debug traceback:", err=True)
            traceback.print_exc()
        
        error_msg = str(e)
        
        # Provide helpful suggestions for common errors with Rich styling
        if "connection" in error_msg.lower() or "network" in error_msg.lower():
            error_panel = Panel(
                f"🌐 Network Error: {error_msg}\n\n💡 Check your internet connection and try again.",
                border_style="red",
                title="❌ CONNECTION ERROR",
                title_align="left"
            )
            console.print(error_panel)
        elif "not found" in error_msg.lower():
            error_panel = Panel(
                f"🔍 File/Resource Not Found: {error_msg}\n\n💡 Verify the file path or resource exists.",
                border_style="red",
                title="❌ NOT FOUND ERROR",
                title_align="left"
            )
            console.print(error_panel)
        elif "permission" in error_msg.lower():
            error_panel = Panel(
                f"🔒 Permission Error: {error_msg}\n\n💡 Check file permissions or run with appropriate privileges.",
                border_style="red",
                title="❌ PERMISSION ERROR",
                title_align="left"
            )
            console.print(error_panel)
        else:
            error_panel = Panel(
                f"⚠️ Error: {error_msg}\n\n💡 Use CVEQUERY_DEBUG=1 for detailed error information.",
                border_style="red",
                title="❌ GENERAL ERROR",
                title_align="left"
            )
            console.print(error_panel)
        
        ctx.exit(1)

def main():
    cli()

if __name__ == '__main__':
    main()



