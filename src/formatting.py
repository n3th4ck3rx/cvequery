"""Enhanced output formatting for cvequery."""
import json
from typing import Dict, Any, List, Optional
from colorama import Fore, Style, init as colorama_init
import click
from datetime import datetime
import textwrap
import re

# Rich imports for beautiful tables
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns
from rich.align import Align
from rich import box
from rich.padding import Padding

# Initialize colorama and Rich console
colorama_init(autoreset=True)
console = Console()

class OutputFormatter:
    """Enhanced output formatter with multiple display modes."""
    
    def __init__(self, format_type: str = "default"):
        self.format_type = format_type
    
    def _should_exclude_field(self, field_name: str, fields_exclude: Optional[List[str]] = None) -> bool:
        """Check if a field should be excluded from display."""
        if not fields_exclude:
            return False
        
        # Normalize field names for comparison
        field_name_lower = field_name.lower().replace('_', '').replace('-', '')
        
        for exclude_field in fields_exclude:
            exclude_field_lower = exclude_field.lower().replace('_', '').replace('-', '')
            
            # Check for exact match or common aliases
            if (field_name_lower == exclude_field_lower or
                self._is_field_alias(field_name_lower, exclude_field_lower)):
                return True
        
        return False
    
    def _is_field_alias(self, field_name: str, exclude_field: str) -> bool:
        """Check if field names are aliases of each other."""
        # Define field aliases
        aliases = {
            'summary': ['description', 'desc'],
            'cvss': ['cvssv3', 'cvss_v3', 'cvssv30'],
            'cvssv2': ['cvss_v2', 'cvss2'],
            'epss': ['epsscore'],
            'published': ['publishedtime', 'published_time', 'pubdate'],
            'modified': ['modifiedtime', 'modified_time', 'moddate'],
            'kev': ['kevstatus', 'kev_status'],
            'ransomware': ['ransomwarecampaign', 'ransomware_campaign'],
            'proposeaction': ['proposed_action', 'propose_action', 'mitigation'],
            'references': ['refs', 'reference'],
            'cpes': ['affectedproducts', 'affected_products', 'products']
        }
        
        # Check if either field is an alias of the other
        for main_field, field_aliases in aliases.items():
            if ((field_name == main_field and exclude_field in field_aliases) or
                (exclude_field == main_field and field_name in field_aliases) or
                (field_name in field_aliases and exclude_field in field_aliases)):
                return True
        
        return False
        
    def format_cve_data(self, data: Dict[str, Any], fields: Optional[List[str]] = None, fields_exclude: Optional[List[str]] = None) -> None:
        """Format and display CVE data based on format type."""
        if self.format_type == "table":
            self._format_table([data], fields, fields_exclude)
        elif self.format_type == "compact":
            self._format_compact(data, fields, fields_exclude)
        elif self.format_type == "detailed":
            self._format_detailed(data, fields, fields_exclude)
        else:
            self._format_default(data, fields, fields_exclude)
    
    def format_cve_list(self, cves: List[Dict[str, Any]], fields: Optional[List[str]] = None, fields_exclude: Optional[List[str]] = None) -> None:
        """Format and display a list of CVEs."""
        if not cves:
            click.echo("No CVEs found.")
            return
            
        if self.format_type == "table":
            self._format_table(cves, fields, fields_exclude)
        elif self.format_type == "summary":
            self._format_summary(cves)
        elif self.format_type == "compact":
            for cve in cves:
                self._format_compact(cve, fields, fields_exclude)
                click.echo()
        elif self.format_type == "detailed":
            for i, cve in enumerate(cves):
                if i > 0:
                    click.echo("\n" + "="*80 + "\n")
                self._format_detailed(cve, fields, fields_exclude)
        else:
            for i, cve in enumerate(cves):
                if i > 0:
                    click.echo("-" * 80)
                self._format_default(cve, fields, fields_exclude)
    
    def _format_default(self, data: Dict[str, Any], fields: Optional[List[str]] = None, fields_exclude: Optional[List[str]] = None) -> None:
        """Enhanced default formatting with Rich styling for better visual appeal."""
        if not data:
            console.print("No data available.", style="red")
            return
            
        # Handle error cases
        if "error" in data:
            console.print(f"❌ Error: {data['error']}", style="red")
            return
        
        # If specific fields are requested, show only those fields
        if fields:
            self._display_specific_fields(data, fields)
            return
        
        cve_id = data.get('cve_id', data.get('id', 'Unknown'))
        severity = self._get_severity_text(data)
        severity_color = self._get_rich_severity_color(severity)
        severity_icon = self._get_severity_icon(severity)
        kev_status = data.get('kev', False)
        
        # Create beautiful header panel
        header_text = Text()
        header_text.append(f"{severity_icon} ", style="bold")
        header_text.append(f"{cve_id}", style="bold bright_white")
        header_text.append(" - ", style="white")
        header_text.append(f"{severity.upper()}", style=f"bold {severity_color}")
        
        if kev_status:
            header_text.append("\n🚨 KNOWN EXPLOITED VULNERABILITY", style="bold red blink")
        
        # Main content sections
        content_sections = []
        
        # Summary section
        if ('summary' in data and data['summary'] and 
            not self._should_exclude_field('summary', fields_exclude)):
            summary_text = Text()
            summary_text.append("📋 Summary:\n", style="bold bright_magenta")
            # Responsive text wrapping based on terminal width
            terminal_width = console.size.width
            wrap_width = max(60, min(120, int(terminal_width * 0.85)))
            wrapped_summary = textwrap.fill(data['summary'], width=wrap_width, 
                                          initial_indent="", 
                                          subsequent_indent="")
            summary_text.append(wrapped_summary, style="white")
            content_sections.append(summary_text)
        
        # Severity and scoring section
        severity_text = Text()
        severity_text.append("⚡ Severity & Risk:\n", style="bold bright_yellow")
        has_severity_content = False
        
        # CVSS scores
        cvss_v3 = self._get_cvss_score(data)
        if (cvss_v3 != "N/A" and not self._should_exclude_field('cvss', fields_exclude)):
            severity_text.append(f"🎯 CVSS v3.0: ", style="bright_yellow")
            severity_text.append(f"{cvss_v3}/10.0", style=f"bold {severity_color}")
            severity_text.append(f" ({severity.upper()})\n", style=f"{severity_color}")
            has_severity_content = True
        
        cvss_v2 = self._get_cvss_v2_score(data)
        if (cvss_v2 != "N/A" and cvss_v2 != cvss_v3 and 
            not self._should_exclude_field('cvss_v2', fields_exclude)):
            severity_text.append(f"🎯 CVSS v2.0: ", style="yellow")
            severity_text.append(f"{cvss_v2}/10.0\n", style="bold yellow")
            has_severity_content = True
        
        # EPSS score
        epss = data.get('epss', 0)
        if epss and not self._should_exclude_field('epss', fields_exclude):
            epss_percent = epss * 100
            epss_color = "red" if epss > 0.7 else "yellow" if epss > 0.3 else "green"
            epss_icon = "🔥" if epss > 0.7 else "⚠️" if epss > 0.3 else "📊"
            severity_text.append(f"{epss_icon} EPSS Score: ", style="bright_cyan")
            severity_text.append(f"{epss:.4f}", style=f"bold {epss_color}")
            severity_text.append(f" ({epss_percent:.2f}% exploitation probability)", style=epss_color)
            has_severity_content = True
        
        if has_severity_content:
            content_sections.append(severity_text)
        
        # Timeline section
        if (any(key in data for key in ['published_time', 'published', 'modified']) and
            not self._should_exclude_field('published', fields_exclude) and
            not self._should_exclude_field('modified', fields_exclude)):
            timeline_text = Text()
            timeline_text.append("📅 Timeline:\n", style="bold bright_green")
            has_timeline_content = False
            
            published = data.get('published_time') or data.get('published')
            if published and not self._should_exclude_field('published', fields_exclude):
                formatted_date = self._format_date_value(published)
                timeline_text.append(f"Published: ", style="green")
                timeline_text.append(f"{formatted_date}\n", style="bold green")
                has_timeline_content = True
            
            modified = data.get('modified')
            if (modified and modified != published and 
                not self._should_exclude_field('modified', fields_exclude)):
                formatted_date = self._format_date_value(modified)
                timeline_text.append(f"Modified: ", style="green")
                timeline_text.append(f"{formatted_date}", style="bold green")
                has_timeline_content = True
            
            if has_timeline_content:
                content_sections.append(timeline_text)
        
        # Ransomware campaign section
        ransomware_campaign = data.get('ransomware_campaign')
        if (ransomware_campaign and ransomware_campaign.lower() != 'unknown' and
            not self._should_exclude_field('ransomware_campaign', fields_exclude)):
            ransomware_text = Text()
            ransomware_text.append("🦠 Ransomware Campaign:\n", style="bold red")
            if ransomware_campaign.lower() == 'known':
                ransomware_text.append("Known ransomware campaigns target this vulnerability", style="bold red")
            else:
                ransomware_text.append(f"{ransomware_campaign}", style="bold red")
            content_sections.append(ransomware_text)
        
        # Proposed action section
        propose_action = data.get('propose_action')
        if (propose_action and not self._should_exclude_field('propose_action', fields_exclude)):
            action_text = Text()
            action_text.append("💡 Mitigation:\n", style="bold bright_yellow")
            # Truncate long proposed actions for better display in default view
            terminal_width = console.size.width
            wrap_width = max(60, min(120, int(terminal_width * 0.85)))
            wrapped_action = textwrap.fill(propose_action, width=wrap_width, 
                                         initial_indent="", 
                                         subsequent_indent="")
            action_text.append(wrapped_action, style="bright_yellow")
            content_sections.append(action_text)
        
        # Key references section
        references = data.get('references', [])
        if references and not self._should_exclude_field('references', fields_exclude):
            ref_text = Text()
            ref_text.append("🔗 Key References:\n", style="bold bright_blue")
            
            for i, ref in enumerate(references[:4]):
                if isinstance(ref, str) and ref.startswith('http'):
                    ref_text.append(f"• ", style="bright_blue")
                    ref_text.append(f"{ref}\n", style="blue")
            
            if len(references) > 4:
                ref_text.append(f"... and {len(references) - 4} more references", style="bright_black")
            
            content_sections.append(ref_text)
        
        # Affected products section
        cpes = data.get('cpes', [])
        if cpes and not self._should_exclude_field('cpes', fields_exclude):
            products_text = Text()
            products_text.append("🎯 Affected Products:\n", style="bold bright_cyan")
            
            for i, cpe in enumerate(cpes[:5]):
                if isinstance(cpe, str):
                    product_name = self._extract_product_from_cpe(cpe)
                    products_text.append(f"• ", style="bright_cyan")
                    products_text.append(f"{product_name}\n", style="cyan")
            
            if len(cpes) > 5:
                products_text.append(f"... and {len(cpes) - 5} more products", style="bright_black")
            
            content_sections.append(products_text)
        
        # Create and display the main panel
        main_content = Text()
        for i, section in enumerate(content_sections):
            if i > 0:
                main_content.append("\n\n", style="white")
            main_content.append(section)
        
        main_panel = Panel(
            main_content,
            border_style=severity_color,
            title=header_text,
            title_align="left",
            padding=(1, 2)
        )
        
        console.print(main_panel) 
   
    def _format_compact(self, data: Dict[str, Any], fields: Optional[List[str]] = None, fields_exclude: Optional[List[str]] = None) -> None:
        """Compact single-line format with Rich styling."""
        cve_id = data.get('cve_id', data.get('id', 'Unknown'))
        
        # If specific fields are requested, show only those in compact format
        if fields:
            field_values = []
            for field in fields:
                field = field.strip().lower()
                if field in data and data[field]:
                    if field == 'summary':
                        summary = str(data[field])[:50] + "..." if len(str(data[field])) > 50 else str(data[field])
                        field_values.append(f"{field}: {summary}")
                    else:
                        field_values.append(f"{field}: {data[field]}")
            
            # Use Rich for better compact display
            compact_text = Text()
            compact_text.append(f"{cve_id}", style="bold bright_white")
            compact_text.append(" │ ", style="bright_black")
            compact_text.append(' │ '.join(field_values), style="white")
            console.print(compact_text)
            return
        
        # Enhanced compact format with Rich
        summary = data.get('summary', 'No summary available')
        severity = self._get_severity_text(data)
        cvss_score = self._get_cvss_score(data)
        kev_status = data.get('kev', False)
        
        # Truncate summary for compact view
        if len(summary) > 80:
            summary = summary[:77] + "..."
        
        # Create compact Rich display
        compact_line = Text()
        
        # CVE ID with icon
        severity_icon = self._get_severity_icon(severity)
        severity_color = self._get_rich_severity_color(severity)
        
        compact_line.append(f"{severity_icon} ", style="bold")
        compact_line.append(f"{cve_id}", style="bold bright_white")
        compact_line.append(f" [{severity.upper()} {cvss_score}]", style=f"bold {severity_color}")
        
        if kev_status:
            compact_line.append(" 🚨 KEV", style="bold red")
        
        console.print(compact_line)
        
        # Summary line with subtle styling
        summary_text = Text()
        summary_text.append("  ", style="white")
        summary_text.append(summary, style="bright_black")
        console.print(summary_text)
    
    def _format_detailed(self, data: Dict[str, Any], fields: Optional[List[str]] = None, fields_exclude: Optional[List[str]] = None) -> None:
        """Detailed format with single comprehensive table - shows ALL information without truncation."""
        if not data:
            console.print("No data available.", style="red")
            return
            
        # Handle error cases
        if "error" in data:
            console.print(f"❌ Error: {data['error']}", style="red")
            return
        
        # If specific fields are requested, show only those fields in detailed format
        if fields:
            self._display_specific_fields_detailed(data, fields)
            return
        
        cve_id = data.get('cve_id', data.get('id', 'Unknown'))
        severity = self._get_severity_text(data)
        severity_color = self._get_rich_severity_color(severity)
        severity_icon = self._get_severity_icon(severity)
        kev_status = data.get('kev', False)
        
        # Analyze content for dynamic column sizing
        field_names = ["CVE ID", "Summary", "CVSS v3.0", "EPSS Score", "EPSS Ranking", "Published", "KEV Status", "Ransomware", "Proposed Action", "References", "Affected Products"]
        max_field_len = max(len(field) for field in field_names)
        
        # Get terminal width for responsive sizing
        terminal_width = console.size.width
        
        # Use simpler, more reliable column ratios
        field_ratio = 1.0   # Field column gets 1 part
        info_ratio = 4.0    # Information column gets 4 parts (80% of space)
        
        # Create single comprehensive table with dynamic sizing
        detail_table = Table(
            show_header=True,
            box=box.ROUNDED,
            border_style=severity_color,
            expand=True,
            padding=(0, 1)
        )
        detail_table.add_column("Field", style="bold bright_white", ratio=field_ratio, no_wrap=True)
        detail_table.add_column("Information", style="white", ratio=info_ratio, no_wrap=True)
        
        # CVE ID and Severity Header
        header_text = Text()
        header_text.append(f"{severity_icon} ", style="bold")
        header_text.append(f"{cve_id}", style="bold bright_white")
        header_text.append(" - ", style="white")
        header_text.append(f"{severity.upper()}", style=f"bold {severity_color}")
        
        if kev_status:
            header_text.append(" 🚨 KEV", style="bold red blink")
        
        detail_table.add_row("CVE ID", header_text)
        
        # Summary
        if ('summary' in data and data['summary'] and 
            not self._should_exclude_field('summary', fields_exclude)):
            summary_text = Text()
            summary_text.append("📋 ", style="bold bright_magenta")
            # Wrap summary text responsively
            terminal_width = console.size.width
            wrap_width = max(60, min(100, int(terminal_width * 0.6)))
            wrapped_summary = textwrap.fill(data['summary'], width=wrap_width, 
                                          initial_indent="", 
                                          subsequent_indent="")
            summary_text.append(wrapped_summary, style="white")
            detail_table.add_row("Summary", summary_text)
        
        # CVSS Scores
        cvss_v3 = self._get_cvss_score(data)
        if cvss_v3 != "N/A" and not self._should_exclude_field('cvss', fields_exclude):
            cvss_display = f"⚡ {cvss_v3} ({severity.capitalize()} severity)"
            detail_table.add_row("CVSS v3.0", cvss_display)
        
        cvss_v2 = self._get_cvss_v2_score(data)
        if (cvss_v2 != "N/A" and cvss_v2 != cvss_v3 and 
            not self._should_exclude_field('cvss_v2', fields_exclude)):
            cvss2_display = f"⚡ {cvss_v2} (Legacy scoring)"
            detail_table.add_row("CVSS v2.0", cvss2_display)
        
        # EPSS Score
        epss = data.get('epss', 0)
        if epss and not self._should_exclude_field('epss', fields_exclude):
            epss_percent = epss * 100
            epss_risk = "High" if epss > 0.7 else "Medium" if epss > 0.3 else "Low"
            epss_color = "red" if epss > 0.7 else "yellow" if epss > 0.3 else "green"
            epss_icon = "🔥" if epss > 0.7 else "⚠️" if epss > 0.3 else "📊"
            
            # Create as a plain string to prevent unwanted line breaks
            epss_display = f"{epss_icon} {epss:.4f} ({epss_percent:.1f}% exploitation probability - {epss_risk} risk)"
            detail_table.add_row("EPSS Score", epss_display)
        
        # EPSS Ranking
        ranking_epss = data.get('ranking_epss', 0)
        if ranking_epss and not self._should_exclude_field('epss', fields_exclude):
            ranking_percent = ranking_epss * 100
            ranking_display = f"📊 {ranking_epss:.4f} ({ranking_percent:.2f}% percentile)"
            detail_table.add_row("EPSS Ranking", ranking_display)
        
        # Timeline
        published = data.get('published_time') or data.get('published')
        if published and not self._should_exclude_field('published', fields_exclude):
            formatted_date = self._format_date_value(published)
            published_display = f"📅 {formatted_date}"
            detail_table.add_row("Published", published_display)
        
        modified = data.get('modified')
        if (modified and modified != published and 
            not self._should_exclude_field('modified', fields_exclude)):
            formatted_date = self._format_date_value(modified)
            modified_display = f"📅 {formatted_date}"
            detail_table.add_row("Modified", modified_display)
        
        # KEV Status
        if kev_status and not self._should_exclude_field('kev', fields_exclude):
            kev_display = "🚨 YES - Actively exploited in the wild"
            detail_table.add_row("KEV Status", kev_display)
        
        # Ransomware Campaign
        ransomware_campaign = data.get('ransomware_campaign')
        if (ransomware_campaign and ransomware_campaign.lower() != 'unknown' and
            not self._should_exclude_field('ransomware_campaign', fields_exclude)):
            if ransomware_campaign.lower() == 'known':
                ransomware_display = "🦠 Known ransomware campaigns targeting this vulnerability"
            else:
                ransomware_display = f"🦠 {ransomware_campaign}"
            detail_table.add_row("Ransomware", ransomware_display)
        
        # Proposed Action
        propose_action = data.get('propose_action')
        if propose_action and not self._should_exclude_field('propose_action', fields_exclude):
            action_text = Text()
            action_text.append("💡 ", style="bold bright_yellow")
            # Wrap the proposed action text
            terminal_width = console.size.width
            wrap_width = max(60, min(100, int(terminal_width * 0.6)))
            wrapped_action = textwrap.fill(propose_action, width=wrap_width, 
                                         initial_indent="", 
                                         subsequent_indent="")
            action_text.append(wrapped_action, style="bright_yellow")
            detail_table.add_row("Proposed Action", action_text)
        
        # References (show ALL references in detailed mode)
        references = data.get('references', [])
        if (references and isinstance(references, list) and 
            not self._should_exclude_field('references', fields_exclude)):
            ref_text = Text()
            ref_text.append("🔗 ", style="bold bright_blue")
            
            # Show ALL references in detailed mode
            for i, ref in enumerate(references):
                if i > 0:
                    ref_text.append("\n   ")
                if isinstance(ref, str) and ref.startswith('http'):
                    # Show full URLs in detailed mode - no truncation
                    ref_text.append(f"• {ref}", style="blue")
            
            detail_table.add_row(f"References ({len(references)})", ref_text)
        
        # Affected Products (show ALL products in detailed mode)
        cpes = data.get('cpes', [])
        if cpes and not self._should_exclude_field('cpes', fields_exclude):
            cpe_text = Text()
            cpe_text.append("🎯 ", style="bold bright_cyan")
            
            # Show ALL products in detailed mode
            for i, cpe in enumerate(cpes):
                if i > 0:
                    cpe_text.append("\n   ")
                if isinstance(cpe, str):
                    product_name = self._extract_product_from_cpe(cpe)
                    cpe_text.append(f"• {product_name}", style="cyan")
                    # Also show the full CPE string for detailed analysis
                    cpe_text.append(f"\n     {cpe}", style="bright_black")
            
            detail_table.add_row(f"Affected Products ({len(cpes)})", cpe_text)
        
        # Additional technical details
        tech_fields = ['cwe', 'cvss_vector', 'attack_vector', 'attack_complexity']
        for field in tech_fields:
            if field in data and data[field]:
                field_name = field.replace('_', ' ').title()
                tech_text = Text()
                tech_text.append("🔍 ", style="bold bright_red")
                tech_text.append(str(data[field]), style="white")
                detail_table.add_row(field_name, tech_text)
        
        # Print the single comprehensive table
        console.print(detail_table)
    
    def _format_table(self, cves: List[Dict[str, Any]], fields: Optional[List[str]] = None, fields_exclude: Optional[List[str]] = None) -> None:
        """Enhanced table format for CVEs with Rich library for beautiful output."""
        if not cves:
            return
        
        # If specific fields are requested, use a different table layout
        if fields:
            self._format_table_with_fields(cves, fields)
            return
        
        for i, cve in enumerate(cves):
            if i > 0:
                console.print()  # Add spacing between CVEs
            
            # Extract CVE information
            cve_id = cve.get('cve_id', cve.get('id', 'Unknown'))
            severity = self._get_severity_text(cve)
            cvss_v3 = self._get_cvss_score(cve)
            cvss_v2 = self._get_cvss_v2_score(cve)
            epss = f"{cve.get('epss', 0):.4f}" if cve.get('epss') else "N/A"
            kev_status = cve.get('kev', False)
            published = self._format_date_value(cve.get('published_time', cve.get('published', '')))
            summary = cve.get('summary', 'No summary available')
            
            # Create Rich table with responsive styling
            table = Table(
                show_header=False,
                box=box.ROUNDED,
                border_style="bright_blue",
                expand=True,  # Expand to fill available width
                padding=(0, 1)
            )
            table.add_column("content", style="white", no_wrap=False, ratio=1)
            
            # Header row with CVE ID and severity
            severity_color = self._get_rich_severity_color(severity)
            severity_icon = self._get_severity_icon(severity)
            
            header_text = Text()
            header_text.append(f"{severity_icon} ", style="bold")
            header_text.append(f"{cve_id}", style="bold bright_white")
            header_text.append(" - ", style="white")
            header_text.append(f"{severity.upper()}", style=f"bold {severity_color}")
            
            if kev_status:
                header_text.append(" ", style="white")
                header_text.append("🚨 KEV", style="bold red blink")
            
            table.add_row(header_text)
            
            # Metrics row with beautiful formatting
            metrics_text = Text()
            
            # CVSS v3 score
            if cvss_v3 != "N/A":
                metrics_text.append("⚡ CVSS v3.0: ", style="bright_yellow")
                metrics_text.append(f"{cvss_v3}", style=f"bold {severity_color}")
                
                # Add CVSS v2 if different
                if cvss_v2 != "N/A" and cvss_v2 != cvss_v3:
                    metrics_text.append(" │ ", style="bright_black")
                    metrics_text.append("⚡ CVSS v2.0: ", style="yellow")
                    metrics_text.append(f"{cvss_v2}", style="bold yellow")
            
            # EPSS score with risk indicator
            if epss != "N/A":
                epss_float = float(epss)
                epss_color = "red" if epss_float > 0.7 else "yellow" if epss_float > 0.3 else "green"
                epss_icon = "🔥" if epss_float > 0.7 else "⚠️" if epss_float > 0.3 else "📊"
                
                if metrics_text.plain:
                    metrics_text.append(" │ ", style="bright_black")
                metrics_text.append(f"{epss_icon} EPSS: ", style="bright_cyan")
                metrics_text.append(f"{epss}", style=f"bold {epss_color}")
                metrics_text.append(f" ({epss_float*100:.1f}%)", style=epss_color)
            
            # Publication date
            if published:
                if metrics_text.plain:
                    metrics_text.append(" │ ", style="bright_black")
                metrics_text.append("📅 Published: ", style="bright_green")
                metrics_text.append(f"{published}", style="green")
            
            table.add_row(metrics_text)
            
            # Ransomware campaign section
            ransomware_campaign = cve.get('ransomware_campaign')
            if ransomware_campaign and ransomware_campaign.lower() != 'unknown':
                ransomware_text = Text()
                ransomware_text.append("🦠 Ransomware Campaign: ", style="bold red")
                if ransomware_campaign.lower() == 'known':
                    ransomware_text.append("Known ransomware campaigns target this vulnerability", style="bold red")
                else:
                    ransomware_text.append(f"{ransomware_campaign}", style="bold red")
                table.add_row(ransomware_text)
            
            # Proposed action section
            propose_action = cve.get('propose_action')
            if propose_action:
                action_text = Text()
                action_text.append("💡 Mitigation: ", style="bold bright_yellow")
                # Wrap action text responsively based on terminal width
                terminal_width = console.size.width
                wrap_width = max(60, min(120, int(terminal_width * 0.85)))
                wrapped_action = textwrap.fill(propose_action, width=wrap_width, 
                                             initial_indent="", 
                                             subsequent_indent="")
                action_text.append(wrapped_action, style="bright_yellow")
                table.add_row(action_text)
            
            # Summary section with proper text wrapping
            if summary:
                summary_text = Text()
                summary_text.append("📋 Summary:\n", style="bold bright_magenta")
                
                # Wrap summary text responsively based on terminal width
                terminal_width = console.size.width
                # Use 85% of terminal width, with minimum of 60 and maximum of 120
                wrap_width = max(60, min(120, int(terminal_width * 0.85)))
                wrapped_summary = textwrap.fill(summary, width=wrap_width, 
                                              initial_indent="", 
                                              subsequent_indent="")
                summary_text.append(wrapped_summary, style="white")
                
                table.add_row(summary_text)
            
            # Key references section (truncated for readability)
            references = cve.get('references', [])
            if references and isinstance(references, list):
                ref_text = Text()
                ref_text.append("🔗 Key References:\n", style="bold bright_blue")
                
                # Show first 3-5 most relevant references
                key_refs = references[:4]
                for ref in key_refs:
                    if isinstance(ref, str) and ref.startswith('http'):
                        # Truncate URLs responsively based on terminal width
                        terminal_width = console.size.width
                        max_url_length = max(50, int(terminal_width * 0.7))
                        display_ref = ref if len(ref) <= max_url_length else ref[:max_url_length-3] + "..."
                        ref_text.append(f"• {display_ref}\n", style="blue")
                
                if len(references) > 4:
                    ref_text.append(f"... and {len(references) - 4} more references", style="bright_black")
                
                table.add_row(ref_text)
            
            # Print the beautiful table
            console.print(table)
    
    def _format_table_with_fields(self, cves: List[Dict[str, Any]], fields: List[str]) -> None:
        """Format fields showing FULL information without truncation using Rich panels."""
        for i, cve in enumerate(cves):
            if i > 0:
                console.print()  # Add spacing between CVEs
            
            cve_id = cve.get('cve_id', cve.get('id', 'Unknown'))
            severity = self._get_severity_text(cve)
            severity_color = self._get_rich_severity_color(severity)
            severity_icon = self._get_severity_icon(severity)
            
            # Create header for each CVE
            header_text = Text()
            header_text.append(f"{severity_icon} ", style="bold")
            header_text.append(f"{cve_id}", style="bold bright_white")
            header_text.append(" - ", style="white")
            header_text.append(f"{severity.upper()}", style=f"bold {severity_color}")
            
            if cve.get('kev'):
                header_text.append(" 🚨 KEV", style="bold red blink")
            
            # Create main panel for this CVE
            main_panel = Panel(
                self._format_fields_content(cve, fields),
                border_style=severity_color,
                title=header_text,
                title_align="left"
            )
            console.print(main_panel)
    
    def _format_fields_content(self, cve: Dict[str, Any], fields: List[str]) -> Text:
        """Format the content for specific fields without truncation."""
        content = Text()
        
        for i, field in enumerate(fields):
            field_lower = field.strip().lower()
            
            # Skip cve_id as it's in the header
            if field_lower in ['cve_id', 'id']:
                continue
            
            if i > 0 and content.plain:
                content.append("\n\n", style="white")
            
            if field_lower == 'summary':
                summary = cve.get('summary', 'N/A')
                content.append("📋 Summary:\n", style="bold bright_magenta")
                # Show FULL summary with responsive wrapping
                terminal_width = console.size.width
                wrap_width = max(60, min(120, int(terminal_width * 0.85)))
                wrapped_summary = textwrap.fill(summary, width=wrap_width, 
                                              initial_indent="", 
                                              subsequent_indent="")
                content.append(wrapped_summary, style="white")
            
            elif field_lower in ['cvss', 'cvss_v3']:
                cvss_score = self._get_cvss_score(cve)
                severity = self._get_severity_text(cve)
                severity_color = self._get_rich_severity_color(severity)
                content.append("⚡ CVSS v3.0 Score:\n", style="bold bright_yellow")
                content.append(f"{cvss_score} ({severity.upper()})", style=f"bold {severity_color}")
            
            elif field_lower == 'cvss_v2':
                cvss_v2 = self._get_cvss_v2_score(cve)
                content.append("⚡ CVSS v2.0 Score:\n", style="bold bright_yellow")
                content.append(cvss_v2, style="bold yellow")
            
            elif field_lower == 'epss':
                epss = cve.get('epss', 0)
                content.append("📊 EPSS Score:\n", style="bold bright_cyan")
                if epss:
                    epss_percent = epss * 100
                    epss_risk = "High" if epss > 0.7 else "Medium" if epss > 0.3 else "Low"
                    epss_color = "red" if epss > 0.7 else "yellow" if epss > 0.3 else "green"
                    epss_icon = "🔥" if epss > 0.7 else "⚠️" if epss > 0.3 else "📊"
                    content.append(f"{epss_icon} {epss:.4f} ({epss_percent:.1f}% exploitation probability - {epss_risk} risk)", 
                                 style=f"bold {epss_color}")
                else:
                    content.append("N/A", style="bright_black")
            
            elif field_lower == 'severity':
                severity = self._get_severity_text(cve)
                severity_icon = self._get_severity_icon(severity)
                severity_color = self._get_rich_severity_color(severity)
                content.append("⚡ Severity Level:\n", style="bold bright_white")
                content.append(f"{severity_icon} {severity.upper()}", style=f"bold {severity_color}")
            
            elif field_lower == 'kev':
                content.append("🚨 Known Exploited Vulnerability:\n", style="bold bright_red")
                kev_status = cve.get('kev', False)
                if kev_status:
                    content.append("🚨 YES - Actively exploited in the wild", style="bold red blink")
                else:
                    content.append("No", style="green")
            
            elif field_lower == 'published':
                published = cve.get('published_time', cve.get('published', ''))
                content.append("📅 Published Date:\n", style="bold bright_green")
                if published:
                    formatted_date = self._format_date_value(published)
                    content.append(formatted_date, style="green")
                else:
                    content.append("N/A", style="bright_black")
            
            elif field_lower == 'modified':
                modified = cve.get('modified', '')
                content.append("📅 Modified Date:\n", style="bold bright_green")
                if modified:
                    formatted_date = self._format_date_value(modified)
                    content.append(formatted_date, style="green")
                else:
                    content.append("N/A", style="bright_black")
            
            elif field_lower == 'references':
                refs = cve.get('references', [])
                content.append("🔗 References:\n", style="bold bright_blue")
                if refs and isinstance(refs, list):
                    # Show ALL references without truncation
                    for j, ref in enumerate(refs):
                        if j > 0:
                            content.append("\n")
                        content.append(f"• ", style="bright_blue")
                        content.append(str(ref), style="blue")
                    content.append(f"\n\nTotal: {len(refs)} references", style="bright_black")
                else:
                    content.append("N/A", style="bright_black")
            
            elif field_lower == 'cwe':
                cwe = cve.get('cwe', 'N/A')
                content.append("⚠️ CWE (Common Weakness Enumeration):\n", style="bold bright_magenta")
                content.append(str(cwe), style="magenta")
            
            elif field_lower in ['ransomware_campaign', 'ransomware']:
                ransomware_campaign = cve.get('ransomware_campaign')
                content.append("🦠 Ransomware Campaign:\n", style="bold red")
                if ransomware_campaign and ransomware_campaign.lower() != 'unknown':
                    if ransomware_campaign.lower() == 'known':
                        content.append("Known ransomware campaigns targeting this vulnerability", style="bold red")
                    else:
                        content.append(f"{ransomware_campaign}", style="bold red")
                else:
                    content.append("No known ransomware campaigns", style="green")
            
            elif field_lower in ['propose_action', 'proposed_action', 'mitigation']:
                propose_action = cve.get('propose_action')
                content.append("💡 Proposed Action/Mitigation:\n", style="bold bright_yellow")
                if propose_action:
                    # Show FULL proposed action with responsive wrapping
                    terminal_width = console.size.width
                    wrap_width = max(60, min(120, int(terminal_width * 0.85)))
                    wrapped_action = textwrap.fill(propose_action, width=wrap_width, 
                                                 initial_indent="", 
                                                 subsequent_indent="")
                    content.append(wrapped_action, style="bright_yellow")
                else:
                    content.append("N/A", style="bright_black")
            
            else:
                # Generic field handling - show full content
                value = cve.get(field_lower, 'N/A')
                field_display = field_lower.replace('_', ' ').title()
                content.append(f"📋 {field_display}:\n", style="bold bright_white")
                if isinstance(value, dict):
                    content.append(json.dumps(value, indent=2), style="white")
                elif isinstance(value, list):
                    for item in value:
                        content.append(f"• {item}\n", style="white")
                else:
                    content.append(str(value), style="white")
        
        return content
    
    def _format_summary(self, cves: List[Dict[str, Any]]) -> None:
        """Summary format showing statistics with Rich styling."""
        total = len(cves)
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
        kev_count = 0
        
        for cve in cves:
            severity = self._get_severity_level(cve)
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            if cve.get('kev'):
                kev_count += 1
        
        # Create beautiful summary panel with responsive sizing
        summary_table = Table(
            show_header=False,
            box=box.ROUNDED,
            border_style="bright_cyan",
            title="📊 CVE ANALYSIS SUMMARY",
            title_style="bold bright_cyan",
            expand=True
        )
        summary_table.add_column("Metric", style="bright_white", ratio=2)
        summary_table.add_column("Value", style="bold bright_green", ratio=1, justify="right")
        summary_table.add_column("Details", style="white", ratio=3)
        
        # Add total and KEV counts
        summary_table.add_row("🎯 Total CVEs", str(total), "Vulnerabilities analyzed")
        if kev_count > 0:
            kev_percentage = (kev_count / total) * 100
            summary_table.add_row("🚨 KEV Count", str(kev_count), f"{kev_percentage:.1f}% actively exploited")
        
        console.print(summary_table)
        console.print()
        
        # Create severity distribution table with responsive sizing
        severity_table = Table(
            show_header=True,
            box=box.ROUNDED,
            border_style="bright_yellow",
            title="⚡ SEVERITY DISTRIBUTION",
            title_style="bold bright_yellow",
            expand=True
        )
        severity_table.add_column("Severity", style="bold", ratio=2)
        severity_table.add_column("Count", justify="right", style="bold", ratio=1)
        severity_table.add_column("Percentage", justify="right", style="bold", ratio=2)
        severity_table.add_column("Visual", ratio=3)
        
        for severity, count in severity_counts.items():
            if count > 0:
                percentage = (count / total) * 100
                icon = self._get_severity_icon(severity)
                color = self._get_rich_severity_color(severity)
                
                # Create visual bar
                bar_length = int((count / max(severity_counts.values())) * 15)
                visual_bar = "█" * bar_length + "░" * (15 - bar_length)
                
                severity_table.add_row(
                    f"{icon} {severity.capitalize()}",
                    str(count),
                    f"{percentage:.1f}%",
                    Text(visual_bar, style=color)
                )
        
        console.print(severity_table)
    
    def _get_severity_display(self, data: Dict[str, Any]) -> tuple:
        """Get severity color and icon for display."""
        cvss = data.get('cvss_v3', data.get('cvss', 0))
        
        if isinstance(cvss, dict):
            cvss = cvss.get('baseScore', 0)
        
        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            cvss = 0
        
        if cvss >= 9.0:
            return Fore.RED + Style.BRIGHT, "🔴"
        elif cvss >= 7.0:
            return Fore.RED, "🟠"
        elif cvss >= 4.0:
            return Fore.YELLOW, "🟡"
        elif cvss > 0:
            return Fore.GREEN, "🟢"
        else:
            return Fore.WHITE, "⚪"
    
    def _display_enhanced_severity(self, data: Dict[str, Any]) -> None:
        """Display enhanced severity information."""
        # CVSS scores
        cvss_v3 = data.get('cvss_v3', data.get('cvss', 0))
        cvss_v2 = data.get('cvss_v2', 0)
        
        if isinstance(cvss_v3, dict):
            cvss_v3_score = cvss_v3.get('baseScore', 0)
        else:
            cvss_v3_score = cvss_v3
        
        if cvss_v3_score:
            severity_text = self._get_severity_text_enhanced(cvss_v3_score)
            click.echo(f"  {Fore.RED}🎯 CVSS v3.0: {Style.BRIGHT}{cvss_v3_score}/10.0{Style.RESET_ALL} ({severity_text})")
        
        if cvss_v2 and cvss_v2 != cvss_v3_score:
            click.echo(f"  {Fore.LIGHTRED_EX}🎯 CVSS v2.0: {cvss_v2}/10.0{Style.RESET_ALL}")
        
        # EPSS score
        epss = data.get('epss', 0)
        if epss:
            epss_percent = epss * 100
            epss_color = Fore.RED if epss > 0.7 else Fore.YELLOW if epss > 0.3 else Fore.GREEN
            click.echo(f"  {epss_color}📊 EPSS Score: {epss:.4f} ({epss_percent:.2f}% exploitation probability){Style.RESET_ALL}")
    
    def _get_severity_text_enhanced(self, cvss: float) -> str:
        """Get enhanced severity text description."""
        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            return f"{Fore.WHITE}UNKNOWN{Style.RESET_ALL}"
            
        if cvss >= 9.0:
            return f"{Fore.RED + Style.BRIGHT}CRITICAL{Style.RESET_ALL}"
        elif cvss >= 7.0:
            return f"{Fore.RED}HIGH{Style.RESET_ALL}"
        elif cvss >= 4.0:
            return f"{Fore.YELLOW}MEDIUM{Style.RESET_ALL}"
        elif cvss > 0:
            return f"{Fore.GREEN}LOW{Style.RESET_ALL}"
        else:
            return f"{Fore.WHITE}NONE{Style.RESET_ALL}" 
   
    def _extract_product_from_cpe(self, cpe: str) -> str:
        """Extract readable product name from CPE string."""
        try:
            # CPE format: cpe:2.3:a:vendor:product:version:...
            parts = cpe.split(':')
            if len(parts) >= 5:
                vendor = parts[3].replace('_', ' ').title()
                product = parts[4].replace('_', ' ').title()
                version = parts[5] if len(parts) > 5 and parts[5] != '*' else ''
                
                if vendor.lower() == product.lower():
                    return f"{product} {version}".strip()
                else:
                    return f"{vendor} {product} {version}".strip()
        except:
            pass
        return cpe
    
    def _display_compact_timeline(self, data: Dict[str, Any]) -> None:
        """Display timeline information in a compact format."""
        published = data.get('published_time') or data.get('published')
        if published:
            formatted_date = self._format_date_value(published)
            click.echo(f"  Published: {Fore.GREEN}{formatted_date}{Style.RESET_ALL}")
        
        modified = data.get('modified')
        if modified and modified != published:
            formatted_date = self._format_date_value(modified)
            click.echo(f"  Modified:  {Fore.YELLOW}{formatted_date}{Style.RESET_ALL}")
    
    def _display_technical_details(self, data: Dict[str, Any], fields: List[str]) -> None:
        """Display additional technical details if requested."""
        if 'cwe' in fields and 'cwe' in data and data['cwe']:
            click.echo(f"\n{Fore.YELLOW + Style.BRIGHT}Weakness:{Style.RESET_ALL}")
            click.echo(f"  {data['cwe']}")
        
        if 'references' in fields and 'references' in data and data['references']:
            click.echo(f"\n{Fore.BLUE + Style.BRIGHT}References:{Style.RESET_ALL}")
            refs = data['references']
            if isinstance(refs, list):
                # Show first 3 references
                for ref in refs[:3]:
                    click.echo(f"  • {ref}")
                if len(refs) > 3:
                    click.echo(f"  ... and {len(refs) - 3} more references")
            else:
                click.echo(f"  {refs}")
    
    def _colorize_cve_id(self, cve_id: str) -> str:
        """Colorize CVE ID."""
        return f"{Fore.WHITE + Style.BRIGHT}{cve_id}{Style.RESET_ALL}"
    
    def _get_severity_info(self, data: Dict[str, Any]) -> str:
        """Get formatted severity information."""
        cvss_score = self._get_cvss_score(data)
        severity = self._get_severity_level(data)
        color = self._get_severity_color(severity)
        
        return f"{color}[{severity.upper()} {cvss_score}]{Style.RESET_ALL}"
    
    def _get_severity_level(self, data: Dict[str, Any]) -> str:
        """Get severity level from CVE data."""
        # Try CVSS v3 first - handle both dict and float formats
        if 'cvss_v3' in data:
            if isinstance(data['cvss_v3'], dict):
                severity = data['cvss_v3'].get('baseSeverity', '').lower()
                if severity:
                    return severity
                score = data['cvss_v3'].get('baseScore', 0)
            else:
                # Handle float/numeric format
                score = float(data['cvss_v3']) if data['cvss_v3'] else 0
        # Try CVSS (general) - handle both dict and float formats
        elif 'cvss' in data:
            if isinstance(data['cvss'], dict):
                score = data['cvss'].get('score', 0)
            else:
                # Handle float/numeric format
                score = float(data['cvss']) if data['cvss'] else 0
        else:
            return "unknown"
        
        # Calculate severity from score
        try:
            score = float(score)
            if score >= 9.0:
                return "critical"
            elif score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            elif score > 0.0:
                return "low"
            else:
                return "none"
        except (ValueError, TypeError):
            return "unknown"
    
    def _get_severity_text(self, data: Dict[str, Any]) -> str:
        """Get severity text for table display."""
        severity = self._get_severity_level(data)
        return severity.capitalize()
    
    def _get_cvss_score(self, data: Dict[str, Any]) -> str:
        """Get CVSS score as string."""
        # Try CVSS v3 first - handle both dict and float formats
        if 'cvss_v3' in data:
            if isinstance(data['cvss_v3'], dict):
                score = data['cvss_v3'].get('baseScore')
            else:
                # Handle float/numeric format
                score = data['cvss_v3']
            
            if score is not None:
                try:
                    return f"{float(score):.1f}"
                except (ValueError, TypeError):
                    pass
        
        # Try CVSS (general) - handle both dict and float formats
        if 'cvss' in data:
            if isinstance(data['cvss'], dict):
                score = data['cvss'].get('score')
            else:
                # Handle float/numeric format
                score = data['cvss']
            
            if score is not None:
                try:
                    return f"{float(score):.1f}"
                except (ValueError, TypeError):
                    pass
        
        return "N/A"
    
    def _get_cvss_v2_score(self, data: Dict[str, Any]) -> str:
        """Get CVSS v2 score as string."""
        if 'cvss_v2' in data:
            if isinstance(data['cvss_v2'], dict):
                score = data['cvss_v2'].get('baseScore')
            else:
                score = data['cvss_v2']
            
            if score is not None:
                try:
                    return f"{float(score):.1f}"
                except (ValueError, TypeError):
                    pass
        
        return "N/A"
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        color_map = {
            'critical': Fore.RED + Style.BRIGHT,
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'low': Fore.GREEN,
            'none': Fore.LIGHTBLACK_EX,
            'unknown': Fore.LIGHTBLACK_EX
        }
        return color_map.get(severity.lower(), Fore.WHITE)
    
    def _get_rich_severity_color(self, severity: str) -> str:
        """Get Rich color for severity level."""
        color_map = {
            'critical': 'bright_red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green',
            'none': 'bright_black',
            'unknown': 'bright_black'
        }
        return color_map.get(severity.lower(), 'white')
    
    def _get_severity_icon(self, severity: str) -> str:
        """Get Unicode icon for severity level."""
        icon_map = {
            'critical': '🔴',
            'high': '🟠', 
            'medium': '🟡',
            'low': '🟢',
            'none': '⚪',
            'unknown': '❓'
        }
        return icon_map.get(severity.lower(), '❓')
    
    def _display_severity_section(self, data: Dict[str, Any]) -> None:
        """Display detailed severity information."""
        if 'cvss_v3' in data and isinstance(data['cvss_v3'], dict):
            cvss3 = data['cvss_v3']
            score = cvss3.get('baseScore', 'N/A')
            severity = cvss3.get('baseSeverity', 'Unknown')
            vector = cvss3.get('vectorString', 'N/A')
            
            color = self._get_severity_color(severity.lower())
            click.echo(f"  CVSS v3: {color}{score} ({severity}){Style.RESET_ALL}")
            click.echo(f"  Vector:  {vector}")
        
        if 'epss' in data:
            epss_score = data['epss']
            click.echo(f"  EPSS:    {epss_score:.4f} ({epss_score*100:.2f}% probability)")
    
    def _display_dates_section(self, data: Dict[str, Any]) -> None:
        """Display date information."""
        if 'published' in data:
            published = self._format_date_value(data['published'])
            click.echo(f"  Published: {published}")
        
        if 'modified' in data:
            modified = self._format_date_value(data['modified'])
            click.echo(f"  Modified:  {modified}")
    
    def _format_date_value(self, value: str) -> str:
        """Format date values."""
        try:
            # Parse ISO date and format nicely
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M UTC')
        except:
            return str(value)
    
    def _truncate(self, text: str, max_length: int) -> str:
        """Truncate text to fit in table columns."""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."


    def _format_dict_value(self, value: Dict[str, Any]) -> str:
        """Format dictionary values."""
        if 'baseScore' in value:  # CVSS data
            score = value.get('baseScore', 0)
            severity = value.get('baseSeverity', 'Unknown')
            color = self._get_severity_color(severity.lower())
            return f"{color}{score} ({severity}){Style.RESET_ALL}"
        else:
            return json.dumps(value, indent=2)
    
    def _format_list_value(self, value: List[Any]) -> str:
        """Format list values."""
        if len(value) <= 3:
            return ", ".join(str(item) for item in value)
        else:
            return f"{', '.join(str(item) for item in value[:3])}, ... (+{len(value)-3} more)"
    
    def _get_severity_score(self, severity: str) -> float:
        """Get numeric score for severity level for sorting."""
        severity_scores = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
            "none": 0.0,
            "unknown": 0.0
        }
        return severity_scores.get(severity.lower(), 0.0)
    
    def _get_severity_from_score(self, cvss_score: float) -> str:
        """Get severity level from CVSS score."""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score > 0:
            return "low"
        else:
            return "none"
    
    def _display_specific_fields(self, data: Dict[str, Any], fields: List[str]) -> None:
        """Display only the specified fields with Rich formatting."""
        cve_id = data.get('cve_id', data.get('id', 'Unknown'))
        
        # Create a beautiful table for specific fields
        fields_table = Table(
            show_header=True,
            box=box.ROUNDED,
            border_style="bright_blue",
            title=f"🔍 {cve_id} - SELECTED FIELDS",
            title_style="bold bright_white",
            expand=True
        )
        fields_table.add_column("Field", style="bold bright_white", no_wrap=True, ratio=1)
        fields_table.add_column("Value", style="white", ratio=3)
        
        for field in fields:
            field = field.strip().lower()
            
            if field == 'id' or field == 'cve_id':
                fields_table.add_row("CVE ID", f"[bold bright_white]{cve_id}[/bold bright_white]")
                
            elif field == 'summary' and data.get('summary'):
                summary = data['summary']
                # Wrap summary text for better display
                terminal_width = console.size.width
                wrap_width = max(60, min(100, int(terminal_width * 0.6)))
                wrapped_summary = textwrap.fill(summary, width=wrap_width)
                fields_table.add_row("📋 Summary", wrapped_summary)
                
            elif field == 'cvss' and data.get('cvss'):
                cvss_score = data['cvss']
                severity = self._get_severity_from_score(cvss_score)
                severity_color = self._get_rich_severity_color(severity)
                fields_table.add_row("🎯 CVSS Score", f"[{severity_color}]{cvss_score}/10.0 ({severity.upper()})[/{severity_color}]")
                
            elif field == 'cvss_v2' and data.get('cvss_v2'):
                cvss_v2 = data['cvss_v2']
                if isinstance(cvss_v2, dict):
                    cvss_display = "\n".join([f"{key}: {value}" for key, value in cvss_v2.items()])
                else:
                    cvss_display = f"[bold yellow]{cvss_v2}/10.0[/bold yellow]"
                fields_table.add_row("🎯 CVSS v2.0", cvss_display)
                    
            elif field == 'cvss_v3' and data.get('cvss_v3'):
                cvss_v3 = data['cvss_v3']
                if isinstance(cvss_v3, dict):
                    cvss_display = "\n".join([f"{key}: {value}" for key, value in cvss_v3.items()])
                else:
                    severity = self._get_severity_from_score(cvss_v3)
                    severity_color = self._get_rich_severity_color(severity)
                    cvss_display = f"[{severity_color}]{cvss_v3}/10.0 ({severity.upper()})[/{severity_color}]"
                fields_table.add_row("🎯 CVSS v3.0", cvss_display)
                    
            elif field == 'cvss_version' and data.get('cvss_version'):
                fields_table.add_row("📊 CVSS Version", f"[bright_cyan]{data['cvss_version']}[/bright_cyan]")
                    
            elif field == 'epss' and data.get('epss'):
                epss = data['epss']
                epss_percent = epss * 100 if isinstance(epss, (int, float)) else epss
                epss_color = "red" if epss > 0.7 else "yellow" if epss > 0.3 else "green"
                epss_icon = "🔥" if epss > 0.7 else "⚠️" if epss > 0.3 else "📊"
                fields_table.add_row(f"{epss_icon} EPSS Score", f"[{epss_color}]{epss:.4f} ({epss_percent:.2f}% exploitation probability)[/{epss_color}]")
                
            elif field == 'ranking_epss' and data.get('ranking_epss'):
                ranking = data['ranking_epss']
                ranking_percent = ranking * 100
                fields_table.add_row("📊 EPSS Ranking", f"[bright_cyan]{ranking:.4f} ({ranking_percent:.2f}% percentile)[/bright_cyan]")
                
            elif field == 'kev' and data.get('kev'):
                kev_status = "🚨 YES - Actively exploited" if data['kev'] else "❌ NO"
                kev_color = "bold red" if data['kev'] else "bright_black"
                fields_table.add_row("🚨 KEV Status", f"[{kev_color}]{kev_status}[/{kev_color}]")
                
            elif field == 'propose_action' and data.get('propose_action'):
                action = data['propose_action']
                terminal_width = console.size.width
                wrap_width = max(60, min(100, int(terminal_width * 0.6)))
                wrapped_action = textwrap.fill(action, width=wrap_width)
                fields_table.add_row("💡 Proposed Action", f"[bright_yellow]{wrapped_action}[/bright_yellow]")
                
            elif field == 'ransomware_campaign' and data.get('ransomware_campaign'):
                ransomware = data['ransomware_campaign']
                if ransomware.lower() == 'known':
                    ransomware_display = "[bold red]🦠 Known ransomware campaigns target this vulnerability[/bold red]"
                elif ransomware.lower() != 'unknown':
                    ransomware_display = f"[bold red]🦠 {ransomware}[/bold red]"
                else:
                    ransomware_display = "[bright_black]❌ No known ransomware campaigns[/bright_black]"
                fields_table.add_row("🦠 Ransomware", ransomware_display)
                
            elif field == 'references' and data.get('references'):
                refs = data['references']
                if isinstance(refs, list):
                    ref_count = len(refs)
                    ref_display = "\n".join([f"• {ref}" for ref in refs[:5]])  # Show first 5
                    if ref_count > 5:
                        ref_display += f"\n... and {ref_count - 5} more references"
                    fields_table.add_row(f"🔗 References ({ref_count})", f"[blue]{ref_display}[/blue]")
                else:
                    fields_table.add_row("🔗 References", f"[blue]{refs}[/blue]")
                    
            elif field == 'published' and data.get('published'):
                published_date = self._format_date_value(data['published'])
                fields_table.add_row("📅 Published", f"[green]{published_date}[/green]")
                
            elif field == 'published_time' and data.get('published_time'):
                published_date = self._format_date_value(data['published_time'])
                fields_table.add_row("📅 Published Time", f"[green]{published_date}[/green]")
                
            elif field == 'modified' and data.get('modified'):
                modified_date = self._format_date_value(data['modified'])
                fields_table.add_row("📅 Modified", f"[yellow]{modified_date}[/yellow]")
                
            elif field == 'cpes' and data.get('cpes'):
                cpes = data['cpes']
                if isinstance(cpes, list):
                    cpe_count = len(cpes)
                    cpe_display = ""
                    for i, cpe in enumerate(cpes[:5]):  # Show first 5
                        if isinstance(cpe, str):
                            product_name = self._extract_product_from_cpe(cpe)
                            cpe_display += f"• {product_name}\n"
                    if cpe_count > 5:
                        cpe_display += f"... and {cpe_count - 5} more products"
                    fields_table.add_row(f"🎯 Affected Products ({cpe_count})", f"[cyan]{cpe_display.rstrip()}[/cyan]")
                else:
                    fields_table.add_row("🎯 CPEs", f"[cyan]{cpes}[/cyan]")
                    
            elif field in data and data[field] is not None:
                # Generic field display for any other fields
                field_name = field.replace('_', ' ').title()
                value = data[field]
                if isinstance(value, dict):
                    value_display = "\n".join([f"{key}: {val}" for key, val in value.items()])
                elif isinstance(value, list):
                    value_display = "\n".join([f"• {item}" for item in value])
                else:
                    value_display = str(value)
                fields_table.add_row(f"📋 {field_name}", value_display)
        
        # Display the beautiful table
        console.print()
        console.print(fields_table)
        console.print()
    
    def _display_specific_fields_detailed(self, data: Dict[str, Any], fields: List[str]) -> None:
        """Display only the specified fields in detailed format."""
        for field in fields:
            field = field.strip().lower()
            
            if field == 'id' or field == 'cve_id':
                # Already displayed in header
                continue
                
            elif field == 'summary' and data.get('summary'):
                click.echo(f"\n{Fore.YELLOW + Style.BRIGHT}SUMMARY{Style.RESET_ALL}")
                summary = data['summary']
                wrapped_summary = textwrap.fill(summary, width=76, initial_indent="  ", subsequent_indent="  ")
                click.echo(wrapped_summary)
                
            elif field == 'cvss' and data.get('cvss'):
                click.echo(f"\n{Fore.RED + Style.BRIGHT}CVSS SCORE{Style.RESET_ALL}")
                click.echo(f"  {data['cvss']}")
                
            elif field == 'cvss_v2' and data.get('cvss_v2'):
                click.echo(f"\n{Fore.RED + Style.BRIGHT}CVSS v2{Style.RESET_ALL}")
                if isinstance(data['cvss_v2'], dict):
                    for key, value in data['cvss_v2'].items():
                        click.echo(f"  {key}: {value}")
                else:
                    click.echo(f"  {data['cvss_v2']}")
                    
            elif field == 'cvss_v3' and data.get('cvss_v3'):
                click.echo(f"\n{Fore.RED + Style.BRIGHT}CVSS v3{Style.RESET_ALL}")
                if isinstance(data['cvss_v3'], dict):
                    for key, value in data['cvss_v3'].items():
                        click.echo(f"  {key}: {value}")
                else:
                    click.echo(f"  {data['cvss_v3']}")
                    
            elif field == 'epss' and data.get('epss'):
                click.echo(f"\n{Fore.BLUE + Style.BRIGHT}EPSS SCORE{Style.RESET_ALL}")
                epss = data['epss']
                epss_percent = epss * 100 if isinstance(epss, (int, float)) else epss
                click.echo(f"  Score: {epss}")
                click.echo(f"  Probability: {epss_percent:.2f}%")
                
            elif field == 'kev' and data.get('kev'):
                click.echo(f"\n{Fore.RED + Style.BRIGHT}KNOWN EXPLOITED VULNERABILITY{Style.RESET_ALL}")
                click.echo(f"  Status: {data['kev']}")
                
            elif field == 'references' and data.get('references'):
                click.echo(f"\n{Fore.BLUE + Style.BRIGHT}REFERENCES{Style.RESET_ALL}")
                refs = data['references']
                if isinstance(refs, list):
                    for ref in refs:
                        click.echo(f"  • {ref}")
                else:
                    click.echo(f"  {refs}")
                    
            elif field == 'published' and data.get('published'):
                click.echo(f"\n{Fore.GREEN + Style.BRIGHT}PUBLISHED{Style.RESET_ALL}")
                click.echo(f"  {self._format_date_value(data['published'])}")
                
            elif field == 'modified' and data.get('modified'):
                click.echo(f"\n{Fore.YELLOW + Style.BRIGHT}MODIFIED{Style.RESET_ALL}")
                click.echo(f"  {self._format_date_value(data['modified'])}")
                
            elif field == 'cpes' and data.get('cpes'):
                click.echo(f"\n{Fore.MAGENTA + Style.BRIGHT}AFFECTED PRODUCTS (CPEs){Style.RESET_ALL}")
                cpes = data['cpes']
                if isinstance(cpes, list):
                    for cpe in cpes:
                        if isinstance(cpe, str):
                            product_name = self._extract_product_from_cpe(cpe)
                            click.echo(f"  • {product_name}")
                            click.echo(f"    {Fore.LIGHTBLACK_EX}{cpe}{Style.RESET_ALL}")
                else:
                    click.echo(f"  {cpes}")
                    
            elif field == 'cwe' and data.get('cwe'):
                click.echo(f"\n{Fore.YELLOW + Style.BRIGHT}WEAKNESS (CWE){Style.RESET_ALL}")
                click.echo(f"  {data['cwe']}")
                
            elif field in data:
                # Generic field display for any other fields
                click.echo(f"\n{Fore.WHITE + Style.BRIGHT}{field.upper()}{Style.RESET_ALL}")
                value = data[field]
                if isinstance(value, dict):
                    for key, val in value.items():
                        click.echo(f"  {key}: {val}")
                elif isinstance(value, list):
                    for item in value:
                        click.echo(f"  • {item}")
                else:
                    click.echo(f"  {value}")


# Convenience functions
def format_cve_output(data: Dict[str, Any], format_type: str = "table", fields: Optional[List[str]] = None, fields_exclude: Optional[List[str]] = None) -> None:
    """Format and display single CVE output."""
    formatter = OutputFormatter(format_type)
    formatter.format_cve_data(data, fields, fields_exclude)

def format_cve_list_output(cves: List[Dict[str, Any]], format_type: str = "table", fields: Optional[List[str]] = None, fields_exclude: Optional[List[str]] = None) -> None:
    """Format and display CVE list output."""
    formatter = OutputFormatter(format_type)
    formatter.format_cve_list(cves, fields, fields_exclude)