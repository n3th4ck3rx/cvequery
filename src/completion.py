"""Shell completion functionality for CVEQuery."""
import os
import platform
from typing import List, Optional

# Common completion data
COMMON_PRODUCTS = [
    'apache', 'nginx', 'mysql', 'postgresql', 'redis', 'mongodb',
    'windows', 'linux', 'ubuntu', 'centos', 'debian', 'java', 'python',
    'nodejs', 'php', 'ruby', 'docker', 'kubernetes', 'jenkins', 'gitlab'
]

SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'none']

AVAILABLE_FIELDS = [
    'id', 'summary', 'cvss', 'cvss_v2', 'cvss_v3', 'epss', 'epss_score',
    'kev', 'references', 'published', 'modified', 'cpes', 'cwe'
]

CVE_PATTERNS = ['CVE-2023-', 'CVE-2024-', 'CVE-2025-']

def complete_cve_id(ctx, param, incomplete):
    """Complete CVE ID patterns."""
    return [pattern for pattern in CVE_PATTERNS if pattern.startswith(incomplete.upper())]

def complete_product_name(ctx, param, incomplete):
    """Complete product names."""
    return [product for product in COMMON_PRODUCTS if product.startswith(incomplete.lower())]

def complete_severity(ctx, param, incomplete):
    """Complete severity levels with comma-separated support."""
    if ',' in incomplete:
        parts = incomplete.split(',')
        prefix = ','.join(parts[:-1]) + ','
        last_part = parts[-1]
        return [prefix + severity for severity in SEVERITY_LEVELS if severity.startswith(last_part.lower())]
    return [severity for severity in SEVERITY_LEVELS if severity.startswith(incomplete.lower())]

def complete_fields(ctx, param, incomplete):
    """Complete field names with comma-separated support."""
    if ',' in incomplete:
        parts = incomplete.split(',')
        prefix = ','.join(parts[:-1]) + ','
        last_part = parts[-1]
        return [prefix + field for field in AVAILABLE_FIELDS if field.startswith(last_part.lower())]
    return [field for field in AVAILABLE_FIELDS if field.startswith(incomplete.lower())]

def complete_file_path(ctx, param, incomplete):
    """Complete file paths."""
    if not incomplete:
        return ['output.json', 'report.json', 'package.json', 'requirements.txt']
    
    try:
        import glob
        matches = glob.glob(incomplete + '*')
        return [match for match in matches[:10]]
    except:
        return []

def setup_completion(platform_choice='auto'):
    """Setup shell completion with platform detection and automatic installation."""
    import platform
    import os
    
    # Determine target platform
    if platform_choice == 'auto':
        system = platform.system().lower()
        if system == 'windows':
            target_platform = 'windows'
        elif system == 'darwin':
            target_platform = 'macos'
        else:
            target_platform = 'linux'
    else:
        target_platform = platform_choice.lower()
    
    if target_platform == 'windows':
        return setup_windows_completion()
    elif target_platform == 'macos':
        return setup_macos_completion()
    else:
        return setup_linux_completion()

def setup_windows_completion():
    """Setup Windows PowerShell completion with automatic installation."""
    import subprocess
    import os
    
    powershell_script = get_embedded_powershell_completion()
    
    instructions = f"""
🪟 Windows PowerShell Completion Setup

{powershell_script}

☰ Installation Options:

1️⃣ AUTOMATIC SETUP (Recommended):
   Run this command to automatically add completion to your PowerShell profile:
   
   cvequery --install-completion

2️⃣ MANUAL SETUP:
   Copy the PowerShell code above and add it to your PowerShell profile:
   
   # Check if profile exists
   Test-Path $PROFILE
   
   # Create profile if it doesn't exist
   if (!(Test-Path $PROFILE)) {{ New-Item -Path $PROFILE -Type File -Force }}
   
   # Edit your profile
   notepad $PROFILE
   
   # Add the completion code and restart PowerShell

3️⃣ SESSION-ONLY (Temporary):
   Copy and paste the PowerShell code directly into your current session.

💡 Tips:
   • Works with both 'cvequery' and 'python -m src.main' commands
   • Supports smart completion for products, severities, fields, and file paths
   • Handles comma-separated values intelligently
"""
    
    return instructions

def setup_linux_completion():
    """Setup Linux shell completion with automatic installation."""
    bash_completion = get_embedded_bash_completion()
    zsh_completion = get_embedded_zsh_completion()
    
    instructions = f"""
🐧 Linux Shell Completion Setup

📋 Bash Completion:
{bash_completion}

📋 Zsh Completion:
{zsh_completion}

📋 Installation Options:

1️⃣ AUTOMATIC SETUP (Recommended):
   Run this command to automatically add completion:
   
   cvequery --install-completion

2️⃣ MANUAL SETUP:
   
   For Bash - Add to ~/.bashrc:
   eval "$(_CVEQUERY_COMPLETE=bash_source cvequery)"
   
   For Zsh - Add to ~/.zshrc:
   eval "$(_CVEQUERY_COMPLETE=zsh_source cvequery)"
   
   For Fish - Add to ~/.config/fish/config.fish:
   eval (env _CVEQUERY_COMPLETE=fish_source cvequery)

3️⃣ SESSION-ONLY (Temporary):
   Run the eval command directly in your current shell session.

💡 Tips:
   • Restart your shell or run 'source ~/.bashrc' (or ~/.zshrc) after setup
   • Supports smart completion for all CVEQuery options and values
"""
    
    return instructions

def setup_macos_completion():
    """Setup macOS shell completion with automatic installation."""
    bash_completion = get_embedded_bash_completion()
    zsh_completion = get_embedded_zsh_completion()
    
    instructions = f"""
🍎 macOS Shell Completion Setup

📋 Bash Completion:
{bash_completion}

📋 Zsh Completion (Default in macOS Catalina+):
{zsh_completion}

📋 Installation Options:

1️⃣ AUTOMATIC SETUP (Recommended):
   Run this command to automatically add completion:
   
   cvequery --install-completion

2️⃣ MANUAL SETUP:
   
   For Bash - Add to ~/.bash_profile or ~/.bashrc:
   eval "$(_CVEQUERY_COMPLETE=bash_source cvequery)"
   
   For Zsh (Default) - Add to ~/.zshrc:
   eval "$(_CVEQUERY_COMPLETE=zsh_source cvequery)"

3️⃣ SESSION-ONLY (Temporary):
   Run the eval command directly in your current shell session.

💡 Tips:
   • macOS Catalina+ uses Zsh by default
   • Restart your terminal or run 'source ~/.zshrc' after setup
   • Supports smart completion for all CVEQuery options and values
"""
    
    return instructions

def get_embedded_powershell_completion():
    """Get embedded PowerShell completion script."""
    return '''# CVEQuery PowerShell Completion
if (Get-Command cvequery -ErrorAction SilentlyContinue) {
    Register-ArgumentCompleter -Native -CommandName cvequery -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        
        $commandLine = $commandAst.ToString()
        $completions = @()
        
        # Product completion
        if ($commandLine -match '--product-cve\\s+\\S*$|--product-cve\\s+$|-pcve\\s+\\S*$|-pcve\\s+$') {
            $products = @('apache', 'nginx', 'mysql', 'postgresql', 'redis', 'mongodb', 'windows', 'linux', 'ubuntu', 'centos', 'debian', 'java', 'python', 'nodejs', 'php', 'ruby', 'docker', 'kubernetes', 'jenkins', 'gitlab')
            $completions = $products | Where-Object { $_ -like "$wordToComplete*" }
        }
        # Severity completion
        elseif ($commandLine -match '--severity\\s+\\S*$|--severity\\s+$|-s\\s+\\S*$|-s\\s+$') {
            $severities = @('critical', 'high', 'medium', 'low', 'none')
            if ($wordToComplete -match ',') {
                $parts = $wordToComplete -split ','
                $prefix = ($parts[0..($parts.Length-2)] -join ',') + ','
                $lastPart = $parts[-1]
                $completions = $severities | Where-Object { $_ -like "$lastPart*" } | ForEach-Object { "$prefix$_" }
            } else {
                $completions = $severities | Where-Object { $_ -like "$wordToComplete*" }
            }
        }
        # Fields completion
        elseif ($commandLine -match '--fields\\s+\\S*$|--fields\\s+$|-f\\s+\\S*$|-f\\s+$') {
            $fields = @('id', 'summary', 'cvss', 'cvss_v2', 'cvss_v3', 'epss', 'epss_score', 'kev', 'references', 'published', 'modified', 'cpes', 'cwe')
            if ($wordToComplete -match ',') {
                $parts = $wordToComplete -split ','
                $prefix = ($parts[0..($parts.Length-2)] -join ',') + ','
                $lastPart = $parts[-1]
                $completions = $fields | Where-Object { $_ -like "$lastPart*" } | ForEach-Object { "$prefix$_" }
            } else {
                $completions = $fields | Where-Object { $_ -like "$wordToComplete*" }
            }
        }
        # Format completion
        elseif ($commandLine -match '--format\\s+\\S*$|--format\\s+$') {
            $formats = @('default', 'table', 'compact', 'detailed', 'summary')
            $completions = $formats | Where-Object { $_ -like "$wordToComplete*" }
        }
        # CVE ID completion
        elseif ($commandLine -match '--cve\\s+\\S*$|--cve\\s+$|-c\\s+\\S*$|-c\\s+$') {
            $cvePatterns = @('CVE-2023-', 'CVE-2024-', 'CVE-2025-')
            $completions = $cvePatterns | Where-Object { $_ -like "$wordToComplete*" }
        }
        # File completion
        elseif ($commandLine -match '--json\\s+\\S*$|--json\\s+$|--sbom\\s+\\S*$|--sbom\\s+$|-j\\s+\\S*$|-j\\s+$') {
            if ($wordToComplete) {
                try {
                    $completions = Get-ChildItem -Path "$wordToComplete*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Select-Object -First 10
                } catch { $completions = @() }
            } else {
                $completions = @('output.json', 'report.json', 'package.json', 'requirements.txt')
            }
        }
        # Option completion
        elseif ($wordToComplete -like '-*') {
            $options = @('--help', '--version', '--cve', '--multiple-cves', '--product-cve', '--is-kev', '--severity', '--start-date', '--end-date', '--cpe23', '--product-cpe', '--sort-by-epss', '--fields', '--json', '--only-cve-ids', '--count', '--skip-cves', '--limit-cves', '--interactive', '--format', '--sbom', '--setup-completion', '--install-completion', '-c', '-mc', '-pcve', '-k', '-s', '-f', '-j', '-i')
            $completions = $options | Where-Object { $_ -like "$wordToComplete*" }
        }
        
        $completions | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}

# Also support python -m src.main for development
Register-ArgumentCompleter -Native -CommandName python -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $commandLine = $commandAst.ToString()
    if ($commandLine -match 'python\\s+(-m\\s+)?src\\.main|python\\s+cvequery') {
        if ($wordToComplete -like '-*') {
            $options = @('--help', '--version', '--cve', '--product-cve', '--severity', '--format', '--sbom', '--interactive')
            $options | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
    }
}'''

def get_embedded_bash_completion():
    """Get embedded Bash completion script."""
    return '''# CVEQuery Bash Completion
if command -v cvequery >/dev/null 2>&1; then
    eval "$(_CVEQUERY_COMPLETE=bash_source cvequery)"
fi'''

def get_embedded_zsh_completion():
    """Get embedded Zsh completion script."""
    return '''# CVEQuery Zsh Completion
if command -v cvequery >/dev/null 2>&1; then
    eval "$(_CVEQUERY_COMPLETE=zsh_source cvequery)"
fi'''

def get_embedded_fish_completion():
    """Get embedded Fish completion script."""
    return '''# CVEQuery Fish Completion
if command -v cvequery >/dev/null 2>&1
    eval (env _CVEQUERY_COMPLETE=fish_source cvequery)
end'''

def install_completion_automatically(platform_choice='auto'):
    """Automatically install shell completion for the current platform."""
    import platform
    import subprocess
    import os
    
    # Determine target platform
    if platform_choice == 'auto':
        system = platform.system().lower()
        if system == 'windows':
            target_platform = 'windows'
        elif system == 'darwin':
            target_platform = 'macos'
        else:
            target_platform = 'linux'
    else:
        target_platform = platform_choice.lower()
    
    if target_platform == 'windows':
        result = install_windows_completion()
        return (True, result) if "✅" in result else (False, result)
    else:
        result = install_unix_completion(target_platform)
        return (True, result) if "✅" in result else (False, result)

def install_windows_completion():
    """Install Windows PowerShell completion automatically."""
    import subprocess
    import os
    
    try:
        # Get the PowerShell completion script
        completion_script = get_embedded_powershell_completion()
        
        # Try to add to PowerShell profile
        powershell_command = f'''
        if (!(Test-Path $PROFILE)) {{
            New-Item -Path $PROFILE -Type File -Force | Out-Null
        }}
        
        $completionScript = @"
{completion_script}
"@
        
        if (!(Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue) -match "CVEQuery PowerShell Completion") {{
            Add-Content -Path $PROFILE -Value "`n$completionScript"
            Write-Host "✅ CVEQuery completion added to PowerShell profile successfully!"
            Write-Host "🔄 Please restart PowerShell or run: . $PROFILE"
        }} else {{
            Write-Host "ℹ️  CVEQuery completion is already installed in your PowerShell profile."
        }}
        '''
        
        result = subprocess.run(
            ['powershell', '-Command', powershell_command],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return f"✅ Windows PowerShell completion installed successfully!\n{result.stdout}"
        else:
            return f"❌ Failed to install Windows completion: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        return "❌ Installation timed out. Please try manual setup."
    except Exception as e:
        return f"❌ Error installing Windows completion: {str(e)}"

def install_unix_completion(platform_type):
    """Install Unix/Linux/macOS completion automatically."""
    import os
    import subprocess
    
    try:
        # Determine shell and config file
        shell = os.environ.get('SHELL', '/bin/bash')
        
        if 'zsh' in shell:
            config_file = os.path.expanduser('~/.zshrc')
            completion_line = 'eval "$(_CVEQUERY_COMPLETE=zsh_source cvequery)"'
        elif 'fish' in shell:
            config_file = os.path.expanduser('~/.config/fish/config.fish')
            completion_line = 'eval (env _CVEQUERY_COMPLETE=fish_source cvequery)'
            # Ensure fish config directory exists
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
        else:
            # Default to bash
            if platform_type == 'macos':
                config_file = os.path.expanduser('~/.bash_profile')
            else:
                config_file = os.path.expanduser('~/.bashrc')
            completion_line = 'eval "$(_CVEQUERY_COMPLETE=bash_source cvequery)"'
        
        # Check if completion is already installed
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                content = f.read()
                if 'CVEQUERY_COMPLETE' in content:
                    return f"ℹ️  CVEQuery completion is already installed in {config_file}"
        
        # Add completion to config file
        with open(config_file, 'a') as f:
            f.write(f'\n# CVEQuery completion\n{completion_line}\n')
        
        return f"✅ CVEQuery completion added to {config_file} successfully!\n🔄 Please restart your shell or run: source {config_file}"
        
    except Exception as e:
        return f"❌ Error installing completion: {str(e)}"