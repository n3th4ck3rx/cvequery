"""Interactive mode for cvequery."""
import click
from typing import Optional, List, Dict, Any
from src.api import get_cve_data, get_cves_data, get_cpe_data
from src.utils import colorize_output, save_to_json, validate_date
from src.completion import COMMON_PRODUCTS, SEVERITY_LEVELS, AVAILABLE_FIELDS
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

class InteractiveSession:
    """Interactive session handler for cvequery."""
    
    def __init__(self):
        self.session_data = {}
        self.results_history = []
    
    def welcome(self):
        """Display welcome message."""
        print(f"\n{Fore.CYAN + Style.BRIGHT}🔍 CVE Query Interactive Mode{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Welcome to the interactive CVE search tool!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Type 'help' for available commands or 'quit' to exit.{Style.RESET_ALL}\n")
    
    def show_help(self):
        """Display help information."""
        help_text = f"""
{Fore.CYAN + Style.BRIGHT}Available Commands:{Style.RESET_ALL}

{Fore.GREEN}Search Commands:{Style.RESET_ALL}
  search cve <CVE-ID>           - Look up specific CVE
  search product <name>         - Search CVEs by product
  search interactive            - Guided search wizard
  
{Fore.GREEN}Utility Commands:{Style.RESET_ALL}
  history                       - Show search history
  export <filename>             - Export last results to JSON
  clear                         - Clear screen
  help                          - Show this help
  quit/exit                     - Exit interactive mode

{Fore.GREEN}Examples:{Style.RESET_ALL}
  search cve CVE-2023-12345
  search product apache
  search interactive
  export results.json
"""
        print(help_text)
    
    def guided_search_wizard(self):
        """Interactive search wizard."""
        print(f"\n{Fore.CYAN + Style.BRIGHT}🧙 Guided Search Wizard{Style.RESET_ALL}")
        
        # Search type selection
        search_types = [
            "1. Search by specific CVE ID",
            "2. Search by product name", 
            "3. Search by CPE string",
            "4. Advanced filtered search"
        ]
        
        print(f"\n{Fore.YELLOW}Select search type:{Style.RESET_ALL}")
        for option in search_types:
            print(f"  {option}")
        
        while True:
            choice = input(f"\n{Fore.GREEN}Enter choice (1-4): {Style.RESET_ALL}").strip()
            if choice in ['1', '2', '3', '4']:
                break
            print(f"{Fore.RED}Invalid choice. Please enter 1-4.{Style.RESET_ALL}")
        
        if choice == '1':
            return self._wizard_cve_search()
        elif choice == '2':
            return self._wizard_product_search()
        elif choice == '3':
            return self._wizard_cpe_search()
        elif choice == '4':
            return self._wizard_advanced_search()
    
    def _wizard_cve_search(self):
        """CVE ID search wizard."""
        print(f"\n{Fore.CYAN}CVE ID Search{Style.RESET_ALL}")
        
        while True:
            cve_id = input(f"{Fore.GREEN}Enter CVE ID (e.g., CVE-2023-12345): {Style.RESET_ALL}").strip()
            if cve_id.upper().startswith('CVE-'):
                break
            print(f"{Fore.RED}Please enter a valid CVE ID starting with 'CVE-'{Style.RESET_ALL}")
        
        # Optional fields selection
        print(f"\n{Fore.YELLOW}Available fields:{Style.RESET_ALL}")
        for i, field in enumerate(AVAILABLE_FIELDS, 1):
            print(f"  {i:2d}. {field}")
        
        fields_input = input(f"\n{Fore.GREEN}Select fields (comma-separated numbers, or press Enter for all): {Style.RESET_ALL}").strip()
        
        fields_to_show = None
        if fields_input:
            try:
                field_indices = [int(x.strip()) - 1 for x in fields_input.split(',')]
                fields_to_show = [AVAILABLE_FIELDS[i] for i in field_indices if 0 <= i < len(AVAILABLE_FIELDS)]
            except (ValueError, IndexError):
                print(f"{Fore.YELLOW}Invalid field selection, showing all fields.{Style.RESET_ALL}")
        
        # Execute search
        print(f"\n{Fore.CYAN}Searching for {cve_id}...{Style.RESET_ALL}")
        data = get_cve_data(cve_id)
        
        if data and "error" not in data:
            self.results_history.append({"type": "cve", "query": cve_id, "data": data})
            
            # Default fields excluding 'cpes' if not specifically requested
            if not fields_to_show:
                fields_to_show = [k for k in data.keys() if k != 'cpes']
            
            colorize_output(data, fields_to_show)
            
            # Ask for export
            export_choice = input(f"\n{Fore.GREEN}Export results to JSON? (y/N): {Style.RESET_ALL}").strip().lower()
            if export_choice in ['y', 'yes']:
                filename = input(f"{Fore.GREEN}Enter filename (default: cve_result.json): {Style.RESET_ALL}").strip()
                if not filename:
                    filename = "cve_result.json"
                save_to_json(data, filename)
                print(f"{Fore.GREEN}Results saved to {filename}{Style.RESET_ALL}")
        else:
            error_msg = data.get("error", "Unknown error") if data else "No data received"
            print(f"{Fore.RED}Error: {error_msg}{Style.RESET_ALL}")
    
    def _wizard_product_search(self):
        """Product search wizard."""
        print(f"\n{Fore.CYAN}Product Search{Style.RESET_ALL}")
        
        # Show common products
        print(f"\n{Fore.YELLOW}Common products:{Style.RESET_ALL}")
        for i, product in enumerate(COMMON_PRODUCTS[:10], 1):
            print(f"  {i:2d}. {product}")
        
        product = input(f"\n{Fore.GREEN}Enter product name: {Style.RESET_ALL}").strip()
        if not product:
            print(f"{Fore.RED}Product name is required.{Style.RESET_ALL}")
            return
        
        # Severity filter
        print(f"\n{Fore.YELLOW}Severity levels: {', '.join(SEVERITY_LEVELS)}{Style.RESET_ALL}")
        severity_input = input(f"{Fore.GREEN}Filter by severity (comma-separated, or press Enter for all): {Style.RESET_ALL}").strip()
        
        severity_levels = None
        if severity_input:
            severity_levels = [s.strip().lower() for s in severity_input.split(',')]
            invalid_levels = set(severity_levels) - set(SEVERITY_LEVELS)
            if invalid_levels:
                print(f"{Fore.RED}Invalid severity levels: {', '.join(invalid_levels)}{Style.RESET_ALL}")
                return
        
        # Date range
        start_date = input(f"{Fore.GREEN}Start date (YYYY-MM-DD, optional): {Style.RESET_ALL}").strip()
        if start_date and not validate_date(start_date):
            print(f"{Fore.RED}Invalid date format. Use YYYY-MM-DD.{Style.RESET_ALL}")
            return
        
        end_date = input(f"{Fore.GREEN}End date (YYYY-MM-DD, optional): {Style.RESET_ALL}").strip()
        if end_date and not validate_date(end_date):
            print(f"{Fore.RED}Invalid date format. Use YYYY-MM-DD.{Style.RESET_ALL}")
            return
        
        # KEV filter
        kev_filter = input(f"{Fore.GREEN}Show only Known Exploited Vulnerabilities? (y/N): {Style.RESET_ALL}").strip().lower()
        is_kev = kev_filter in ['y', 'yes']
        
        # Limit results
        limit_input = input(f"{Fore.GREEN}Maximum results (default: 50): {Style.RESET_ALL}").strip()
        limit = 50
        if limit_input:
            try:
                limit = int(limit_input)
            except ValueError:
                print(f"{Fore.YELLOW}Invalid limit, using default (50).{Style.RESET_ALL}")
        
        # Execute search
        print(f"\n{Fore.CYAN}Searching for CVEs related to '{product}'...{Style.RESET_ALL}")
        
        data = get_cves_data(
            product=product,
            is_kev=is_kev,
            start_date=start_date if start_date else None,
            end_date=end_date if end_date else None,
            limit=limit
        )
        
        if "error" in data:
            print(f"{Fore.RED}Error: {data['error']}{Style.RESET_ALL}")
            return
        
        # Apply severity filtering if specified
        if severity_levels:
            from src.utils import filter_by_severity
            data = filter_by_severity(data, severity_levels)
        
        if not data.get("cves"):
            print(f"{Fore.YELLOW}No CVEs found matching your criteria.{Style.RESET_ALL}")
            return
        
        self.results_history.append({"type": "product", "query": product, "data": data})
        
        # Display results summary
        total = data.get("total", 0)
        print(f"\n{Fore.GREEN}Found {total} CVE(s) for '{product}'{Style.RESET_ALL}")
        
        # Show first few results
        display_limit = min(5, len(data["cves"]))
        print(f"\n{Fore.CYAN}Showing first {display_limit} results:{Style.RESET_ALL}")
        
        for i, cve in enumerate(data["cves"][:display_limit]):
            print(f"\n{Fore.YELLOW}--- CVE {i+1} ---{Style.RESET_ALL}")
            colorize_output(cve, ["id", "summary", "cvss_v3", "published"])
        
        if len(data["cves"]) > display_limit:
            show_all = input(f"\n{Fore.GREEN}Show all {total} results? (y/N): {Style.RESET_ALL}").strip().lower()
            if show_all in ['y', 'yes']:
                for i, cve in enumerate(data["cves"][display_limit:], display_limit + 1):
                    print(f"\n{Fore.YELLOW}--- CVE {i} ---{Style.RESET_ALL}")
                    colorize_output(cve, ["id", "summary", "cvss_v3", "published"])
        
        # Export option
        export_choice = input(f"\n{Fore.GREEN}Export results to JSON? (y/N): {Style.RESET_ALL}").strip().lower()
        if export_choice in ['y', 'yes']:
            filename = input(f"{Fore.GREEN}Enter filename (default: product_search.json): {Style.RESET_ALL}").strip()
            if not filename:
                filename = "product_search.json"
            save_to_json(data, filename)
            print(f"{Fore.GREEN}Results saved to {filename}{Style.RESET_ALL}")
    
    def _wizard_cpe_search(self):
        """CPE search wizard."""
        print(f"\n{Fore.CYAN}CPE Search{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Enter CPE 2.3 string (e.g., cpe:2.3:a:apache:http_server:2.4.41){Style.RESET_ALL}")
        
        cpe_string = input(f"{Fore.GREEN}CPE string: {Style.RESET_ALL}").strip()
        if not cpe_string:
            print(f"{Fore.RED}CPE string is required.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Searching CVEs for CPE: {cpe_string}...{Style.RESET_ALL}")
        
        data = get_cves_data(cpe23=cpe_string, limit=50)
        
        if "error" in data:
            print(f"{Fore.RED}Error: {data['error']}{Style.RESET_ALL}")
            return
        
        if not data.get("cves"):
            print(f"{Fore.YELLOW}No CVEs found for the specified CPE.{Style.RESET_ALL}")
            return
        
        self.results_history.append({"type": "cpe", "query": cpe_string, "data": data})
        
        total = data.get("total", 0)
        print(f"\n{Fore.GREEN}Found {total} CVE(s) for CPE{Style.RESET_ALL}")
        
        for i, cve in enumerate(data["cves"][:10]):  # Show first 10
            print(f"\n{Fore.YELLOW}--- CVE {i+1} ---{Style.RESET_ALL}")
            colorize_output(cve, ["id", "summary", "cvss_v3", "published"])
    
    def _wizard_advanced_search(self):
        """Advanced search wizard with multiple filters."""
        print(f"\n{Fore.CYAN}Advanced Search{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Configure multiple search criteria{Style.RESET_ALL}")
        
        # Collect all parameters
        params = {}
        
        # Product
        product = input(f"{Fore.GREEN}Product name (optional): {Style.RESET_ALL}").strip()
        if product:
            params['product'] = product
        
        # Severity
        print(f"\n{Fore.YELLOW}Severity levels: {', '.join(SEVERITY_LEVELS)}{Style.RESET_ALL}")
        severity = input(f"{Fore.GREEN}Severity filter (comma-separated, optional): {Style.RESET_ALL}").strip()
        if severity:
            params['severity'] = severity
        
        # Date range
        start_date = input(f"{Fore.GREEN}Start date (YYYY-MM-DD, optional): {Style.RESET_ALL}").strip()
        if start_date:
            if validate_date(start_date):
                params['start_date'] = start_date
            else:
                print(f"{Fore.RED}Invalid start date format.{Style.RESET_ALL}")
                return
        
        end_date = input(f"{Fore.GREEN}End date (YYYY-MM-DD, optional): {Style.RESET_ALL}").strip()
        if end_date:
            if validate_date(end_date):
                params['end_date'] = end_date
            else:
                print(f"{Fore.RED}Invalid end date format.{Style.RESET_ALL}")
                return
        
        # KEV filter
        kev_choice = input(f"{Fore.GREEN}Known Exploited Vulnerabilities only? (y/N): {Style.RESET_ALL}").strip().lower()
        if kev_choice in ['y', 'yes']:
            params['is_kev'] = True
        
        # EPSS sorting
        epss_choice = input(f"{Fore.GREEN}Sort by EPSS score? (y/N): {Style.RESET_ALL}").strip().lower()
        if epss_choice in ['y', 'yes']:
            params['sort_by_epss'] = True
        
        # Limit
        limit_input = input(f"{Fore.GREEN}Maximum results (default: 100): {Style.RESET_ALL}").strip()
        limit = 100
        if limit_input:
            try:
                limit = int(limit_input)
                params['limit'] = limit
            except ValueError:
                print(f"{Fore.YELLOW}Invalid limit, using default (100).{Style.RESET_ALL}")
        
        if not any(params.values()):
            print(f"{Fore.YELLOW}No search criteria specified. Please try again.{Style.RESET_ALL}")
            return
        
        # Execute search
        print(f"\n{Fore.CYAN}Executing advanced search...{Style.RESET_ALL}")
        
        data = get_cves_data(
            product=params.get('product'),
            is_kev=params.get('is_kev', False),
            sort_by_epss=params.get('sort_by_epss', False),
            start_date=params.get('start_date'),
            end_date=params.get('end_date'),
            limit=params.get('limit', 100)
        )
        
        if "error" in data:
            print(f"{Fore.RED}Error: {data['error']}{Style.RESET_ALL}")
            return
        
        # Apply severity filtering if specified
        if params.get('severity'):
            severity_levels = [s.strip().lower() for s in params['severity'].split(',')]
            from src.utils import filter_by_severity
            data = filter_by_severity(data, severity_levels)
        
        if not data.get("cves"):
            print(f"{Fore.YELLOW}No CVEs found matching your criteria.{Style.RESET_ALL}")
            return
        
        self.results_history.append({"type": "advanced", "query": str(params), "data": data})
        
        total = data.get("total", 0)
        print(f"\n{Fore.GREEN}Found {total} CVE(s) matching your criteria{Style.RESET_ALL}")
        
        # Display summary
        for i, cve in enumerate(data["cves"][:5]):
            print(f"\n{Fore.YELLOW}--- CVE {i+1} ---{Style.RESET_ALL}")
            colorize_output(cve, ["id", "summary", "cvss_v3", "epss", "published"])
    
    def show_history(self):
        """Show search history."""
        if not self.results_history:
            print(f"{Fore.YELLOW}No search history available.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN + Style.BRIGHT}Search History:{Style.RESET_ALL}")
        for i, entry in enumerate(self.results_history, 1):
            search_type = entry["type"]
            query = entry["query"]
            result_count = len(entry["data"].get("cves", [])) if "cves" in entry["data"] else 1
            
            print(f"{Fore.GREEN}{i:2d}. {search_type.upper()}: {query} ({result_count} results){Style.RESET_ALL}")
    
    def export_last_results(self, filename: str):
        """Export the last search results."""
        if not self.results_history:
            print(f"{Fore.YELLOW}No results to export.{Style.RESET_ALL}")
            return
        
        last_result = self.results_history[-1]
        try:
            save_to_json(last_result["data"], filename)
            print(f"{Fore.GREEN}Last results exported to {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error exporting results: {str(e)}{Style.RESET_ALL}")
    
    def clear_screen(self):
        """Clear the terminal screen."""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def run(self):
        """Run the interactive session."""
        self.welcome()
        
        while True:
            try:
                command = input(f"{Fore.CYAN}cvequery> {Style.RESET_ALL}").strip()
                
                if not command:
                    continue
                
                if command.lower() in ['quit', 'exit', 'q']:
                    print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
                    break
                
                elif command.lower() == 'help':
                    self.show_help()
                
                elif command.lower() == 'clear':
                    self.clear_screen()
                    self.welcome()
                
                elif command.lower() == 'history':
                    self.show_history()
                
                elif command.lower().startswith('export '):
                    filename = command[7:].strip()
                    if filename:
                        self.export_last_results(filename)
                    else:
                        print(f"{Fore.RED}Please specify a filename.{Style.RESET_ALL}")
                
                elif command.lower().startswith('search '):
                    search_cmd = command[7:].strip()
                    
                    if search_cmd.lower() == 'interactive':
                        self.guided_search_wizard()
                    
                    elif search_cmd.lower().startswith('cve '):
                        cve_id = search_cmd[4:].strip()
                        if cve_id:
                            data = get_cve_data(cve_id)
                            if data and "error" not in data:
                                self.results_history.append({"type": "cve", "query": cve_id, "data": data})
                                fields_to_show = [k for k in data.keys() if k != 'cpes']
                                colorize_output(data, fields_to_show)
                            else:
                                error_msg = data.get("error", "Unknown error") if data else "No data received"
                                print(f"{Fore.RED}Error: {error_msg}{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}Please specify a CVE ID.{Style.RESET_ALL}")
                    
                    elif search_cmd.lower().startswith('product '):
                        product = search_cmd[8:].strip()
                        if product:
                            data = get_cves_data(product=product, limit=10)
                            if "error" not in data and data.get("cves"):
                                self.results_history.append({"type": "product", "query": product, "data": data})
                                print(f"\n{Fore.GREEN}Found {len(data['cves'])} CVE(s) for '{product}'{Style.RESET_ALL}")
                                for i, cve in enumerate(data["cves"][:5]):
                                    print(f"\n{Fore.YELLOW}--- CVE {i+1} ---{Style.RESET_ALL}")
                                    colorize_output(cve, ["id", "summary", "cvss_v3"])
                            else:
                                print(f"{Fore.YELLOW}No CVEs found for '{product}'.{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}Please specify a product name.{Style.RESET_ALL}")
                    
                    else:
                        print(f"{Fore.RED}Unknown search command. Use 'search interactive' for guided search.{Style.RESET_ALL}")
                
                else:
                    print(f"{Fore.RED}Unknown command. Type 'help' for available commands.{Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Use 'quit' to exit.{Style.RESET_ALL}")
            except EOFError:
                print(f"\n{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

def start_interactive_mode():
    """Start interactive mode."""
    session = InteractiveSession()
    session.run()