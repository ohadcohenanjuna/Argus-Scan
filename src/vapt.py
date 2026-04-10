import argparse
import sys
import shutil
from rich.console import Console
from rich.panel import Panel
from reporter import Reporter
from scanners import PortScanner, HeaderScanner, SSLScanner, ToolScanner

def check_dependencies():
    tools = ["nmap", "nikto", "nuclei"]
    missing = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing

import signal

def signal_handler(sig, frame):
    console = Console()
    console.print("\n[bold red]Scan interrupted by user. Exiting...[/bold red]")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(description="Argus-Scan - Automated Vulnerability Assessment Tool")
    parser.add_argument("--target", required=True, help="Target URL or IP address")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--full", action="store_true", help="Run comprehensive/long scans (Nikto, Nuclei)")
    parser.add_argument("--no-tool-check", action="store_true", help="Ignore missing external tools")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show tool commands and live output")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification for HTTP header checks (not recommended for production)")

    args = parser.parse_args()

    # Init Reporter
    reporter = Reporter(args.output)
    reporter.set_target(args.target)
    reporter.print_header()

    try:
        # Check dependencies (missing_tools defined so it's safe when --no-tool-check is used)
        missing_tools = []
        if not args.no_tool_check:
            reporter.print_status("Checking dependencies...")
            missing_tools = check_dependencies()
            
            if missing_tools:
                reporter.print_error(f"Missing external tools: {', '.join(missing_tools)}")
                
                if args.full:
                    reporter.print_error("Full scan requested but tools are missing.")
                    console = Console()
                    console.print(Panel(
                        "[yellow]Please install the missing tools (e.g., sudo apt install nmap nikto) or run setup.sh.\n"
                        "To run ONLY Python-native checks (Port/SSL/Headers), use [bold white]--no-tool-check[/bold white].[/yellow]",
                        title="Dependency Error"
                    ))
                    sys.exit(1)
                else:
                    reporter.print_status("Proceeding with python-native checks only. Use --no-tool-check to suppress this check.", style="yellow")
            else:
                reporter.print_success("All dependencies found.")

        # 1. Port Scan
        reporter.print_status("Starting Port Scan (Nmap)...")
        port_scanner = PortScanner(args.target)
        port_res = port_scanner.run()
        reporter.add_result("PortScanner", port_res)
        reporter.print_success("Port Scan complete.")

        # 2. Header Scan
        reporter.print_status("Starting Security Header Scan...")
        header_scanner = HeaderScanner(args.target, verify_ssl=not args.insecure)
        header_res = header_scanner.run()
        reporter.add_result("HeaderScanner", header_res)
        reporter.print_success("Header Scan complete.")

        # 3. SSL Scan
        reporter.print_status("Starting SSL/TLS Inspection...")
        ssl_scanner = SSLScanner(args.target)
        ssl_res = ssl_scanner.run()
        reporter.add_result("SSLScanner", ssl_res)
        reporter.print_success("SSL Inspection complete.")

        # 4. External Tools (Nikto / Nuclei)
        if args.full:
            # Nikto
            reporter.print_status("Starting Nikto Scan (this may take a while)...")
            nikto_cmd = "nikto -h {target} -Tuning 123b" 
            nikto_scanner = ToolScanner(args.target, "nikto", nikto_cmd, verbose=args.verbose)
            nikto_res = nikto_scanner.run()
            reporter.add_result("NiktoScanner", nikto_res)
            reporter.print_success("Nikto Scan complete.")

            # Nuclei
            reporter.print_status("Starting Nuclei Scan...")
            # -nc: No Color (prevents ANSI codes in report)
            nuclei_cmd = "nuclei -u {target} -silent -nc" 
            nuclei_scanner = ToolScanner(args.target, "nuclei", nuclei_cmd, verbose=args.verbose)
            nuclei_res = nuclei_scanner.run()
            reporter.add_result("NucleiScanner", nuclei_res)
            reporter.print_success("Nuclei Scan complete.")
        else:
            if not missing_tools: # Only suggest full if tools are actually there or we didn't check
                reporter.print_status("Skipping full vulnerability scans. Use --full to enable.", style="dim")

        # Generate Reports
        reporter.print_status("Generating Reports...")
        reporter.generate_cli_report()
        reporter.generate_file_report() # Keep Markdown for backup
        reporter.generate_html_report()
        
        reporter.print_success("Scan Verification Complete.")

    except Exception as e:
        reporter.print_error(f"An unexpected error occurred: {str(e)}")
        import traceback
        # console.print(traceback.format_exc()) # Optional: show traceback in verbose mode
        sys.exit(1)


if __name__ == "__main__":
    main()
