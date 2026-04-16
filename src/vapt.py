import argparse
import os
import sys
import shutil
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
from rich.console import Console
from rich.panel import Panel
from reporter import Reporter
from parallel_ui import monitor_parallel_jobs
from scanners import PortScanner, HeaderScanner, SSLScanner, ToolScanner
from nuclei_runner import run_nuclei_scan
from zap_parse import parse_zap_traditional_json

def check_dependencies():
    tools = ["nmap", "nikto", "nuclei"]
    missing = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing

import signal
import threading

def default_sigint_handler(sig, frame):
    console = Console()
    console.print("\n[bold red]Scan interrupted. Exiting...[/bold red]")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, default_sigint_handler)
    
    parser = argparse.ArgumentParser(description="AutoVAPT - Automated Vulnerability Assessment Tool")
    parser.add_argument("--target", required=True, help="Target URL or IP address")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--full", action="store_true", help="Run comprehensive/long scans (Nikto, Nuclei)")
    parser.add_argument("--no-tool-check", action="store_true", help="Ignore missing external tools")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show tool commands and live output")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification for HTTP header checks (not recommended for production)")
    parser.add_argument(
        "--nuclei-secret-file",
        default=None,
        metavar="PATH",
        help="Nuclei v3.2+ Secret File (YAML) for authenticated scans; passed as --secret-file to nuclei",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run independent scan stages in parallel worker processes (more load on the target)",
    )
    parser.add_argument(
        "--nikto-cgi-all",
        action="store_true",
        help="Nikto: pass -C all (force CGI checks in all possible dirs; slower and heavier; default skips CGI tests when no CGI dirs are found)",
    )
    parser.add_argument(
        "--lenient-exit",
        action="store_true",
        help="Exit 0 even when a scan stage failed or was incomplete (default: exit 1 if any module reports valid=false)",
    )
    parser.add_argument(
        "--site-manifest",
        default=None,
        metavar="PATH",
        help="YAML file listing URLs/paths to scan with Nuclei via -list (see examples/site-manifest.example.yaml)",
    )
    parser.add_argument(
        "--no-site-manifest-include-primary",
        action="store_true",
        help="Do not prepend --target to the manifest URL list (default: include primary target URL)",
    )
    parser.add_argument(
        "--zap-report-json",
        default=None,
        metavar="PATH",
        help="OWASP ZAP traditional JSON report (e.g. from zap-baseline.py -J); findings are parsed into this dossier",
    )
    parser.add_argument(
        "--zap-report-html",
        default=None,
        metavar="PATH",
        help="Optional path to ZAP HTML report for cross-reference in the dossier (not parsed)",
    )

    args = parser.parse_args()

    out_abs = os.path.abspath(args.output)
    os.makedirs(out_abs, exist_ok=True)
    scan_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    site_slug = Reporter.slug_from_target(args.target)
    session_dir = os.path.join(out_abs, site_slug, scan_ts)
    os.makedirs(session_dir, exist_ok=True)
    logs_dir = os.path.join(session_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    reporter = Reporter(session_dir, scan_ts=scan_ts)
    reporter.set_target(args.target)
    reporter.set_nuclei_secret_file_used(bool(args.nuclei_secret_file))
    reporter.print_header()
    reporter.print_status(f"Session directory: {session_dir}")
    reporter.print_status(f"Parallel worker logs: {logs_dir}/")

    console = Console()
    # In --parallel mode, stream tool output to log files only (no noisy console).
    worker_verbose = args.verbose and not args.parallel

    url_list_path = None
    if args.site_manifest:
        from site_manifest import load_site_manifest, merge_primary_target, write_url_list_file

        man_path = (
            args.site_manifest
            if os.path.isabs(args.site_manifest)
            else os.path.abspath(args.site_manifest)
        )
        urls, _meta = load_site_manifest(man_path, fallback_base=args.target)
        if not args.no_site_manifest_include_primary:
            urls = merge_primary_target(urls, args.target)
        slug = reporter._target_slug()
        url_list_path = write_url_list_file(
            urls, os.path.join(session_dir, f"nuclei_urls_{slug}_{reporter.report_ts}.txt")
        )
        reporter.set_site_manifest_url_count(len(urls))
        reporter.print_status(f"Site manifest: {len(urls)} URL(s) → {url_list_path}")

    if args.site_manifest and not args.full:
        reporter.print_status(
            "Note: --site-manifest only affects Nuclei; use --full to run Nuclei with the URL list.",
            style="yellow",
        )

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

        # 1–3. Port / Header / SSL  |  4. Nikto / Nuclei (when --full)
        if args.parallel:
            import parallel_workers as pw

            stop_event = threading.Event()
            pool_holder = [None]

            def parallel_sigint(sig, frame):
                # Second Ctrl+C: immediate process exit (workers may still be mid-tool otherwise).
                if stop_event.is_set():
                    console.print("\n[bold red]Force exit.[/bold red]")
                    os._exit(130)
                stop_event.set()
                p = pool_holder[0]
                if p is not None:
                    try:
                        p.shutdown(wait=False, cancel_futures=True)
                    except Exception:
                        pass
                console.print(
                    "\n[yellow]Stopping parallel workers (pending tasks cancelled). "
                    "Press Ctrl+C again to force immediate exit.[/yellow]"
                )

            old_sigint = signal.signal(signal.SIGINT, parallel_sigint)
            try:
                reporter.print_status(f"Starting 3 parallel jobs → logs: {logs_dir}")
                with ProcessPoolExecutor(max_workers=3) as pool:
                    pool_holder[0] = pool
                    fut_port = pool.submit(
                        pw.run_port,
                        args.target,
                        os.path.join(logs_dir, "port_scan.log"),
                    )
                    fut_header = pool.submit(
                        pw.run_header,
                        args.target,
                        not args.insecure,
                        os.path.join(logs_dir, "header_scan.log"),
                    )
                    fut_ssl = pool.submit(
                        pw.run_ssl,
                        args.target,
                        os.path.join(logs_dir, "ssl_scan.log"),
                    )
                    ok = monitor_parallel_jobs(
                        console,
                        [
                            ("Port scan (nmap)", fut_port),
                            ("Header scan", fut_header),
                            ("SSL / TLS", fut_ssl),
                        ],
                        stop_event=stop_event,
                    )
                    if stop_event.is_set() or not ok:
                        console.print("[yellow]Scan aborted before collecting port/header/SSL results.[/yellow]")
                        sys.exit(130)
                    port_res = fut_port.result()
                    header_res = fut_header.result()
                    ssl_res = fut_ssl.result()
                pool_holder[0] = None

                reporter.add_result("PortScanner", port_res)
                reporter.add_result("HeaderScanner", header_res)
                reporter.add_result("SSLScanner", ssl_res)
                reporter.print_success("Port, header, and SSL scans complete (parallel).")

                if args.full:
                    # Helps Rich / terminals recover between Live sessions; flush so the next status line shows promptly.
                    console.print()
                    try:
                        sys.stdout.flush()
                    except Exception:
                        pass
                    reporter.print_status(
                        f"Starting 2 parallel jobs (Nikto, Nuclei) → logs: {logs_dir}"
                    )
                    with ProcessPoolExecutor(max_workers=2) as pool:
                        pool_holder[0] = pool
                        fut_nikto = pool.submit(
                            pw.run_nikto,
                            args.target,
                            worker_verbose,
                            os.path.join(logs_dir, "nikto.log"),
                            args.nikto_cgi_all,
                        )
                        fut_nuclei = pool.submit(
                            pw.run_nuclei,
                            args.target,
                            args.nuclei_secret_file,
                            worker_verbose,
                            url_list_path,
                            session_dir,
                            reporter.report_ts,
                            os.path.join(logs_dir, "nuclei.log"),
                        )
                        ok_full = monitor_parallel_jobs(
                            console,
                            [
                                ("Nikto", fut_nikto),
                                ("Nuclei", fut_nuclei),
                            ],
                            stop_event=stop_event,
                        )
                        if stop_event.is_set() or not ok_full:
                            console.print(
                                "[yellow]Scan aborted before collecting Nikto/Nuclei results.[/yellow]"
                            )
                            sys.exit(130)
                        nikto_res = fut_nikto.result()
                        nuclei_res = fut_nuclei.result()
                    pool_holder[0] = None

                    reporter.add_result("NiktoScanner", nikto_res)
                    reporter.add_result("NucleiScanner", nuclei_res)
                    reporter.print_success("Nikto and Nuclei scans complete (parallel).")
            finally:
                signal.signal(signal.SIGINT, old_sigint)
                pool_holder[0] = None
        else:
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
                if args.nikto_cgi_all:
                    nikto_cmd += " -C all"
                nikto_scanner = ToolScanner(args.target, "nikto", nikto_cmd, verbose=args.verbose)
                nikto_res = nikto_scanner.run()
                reporter.add_result("NiktoScanner", nikto_res)
                reporter.print_success("Nikto Scan complete.")

                # Nuclei (JSONL + parsed findings)
                reporter.print_status("Starting Nuclei Scan...")
                nuclei_res = run_nuclei_scan(
                    args.target,
                    args.nuclei_secret_file,
                    args.verbose,
                    url_list_path,
                    session_dir,
                    reporter.report_ts,
                )
                reporter.add_result("NucleiScanner", nuclei_res)
                reporter.print_success("Nuclei Scan complete.")

        if not args.full:
            if not missing_tools:
                reporter.print_status(
                    "Skipping full vulnerability scans. Use --full to enable.", style="dim"
                )

        # Optional ZAP report (produced outside this process, e.g. scripts/run_zap_baseline.sh)
        zj = args.zap_report_json
        zh = args.zap_report_html
        if zj:
            zj = zj if os.path.isabs(zj) else os.path.abspath(os.path.join(out_abs, zj))
            if not os.path.isfile(zj):
                zj_alt = os.path.abspath(os.path.join(session_dir, os.path.basename(zj)))
                if os.path.isfile(zj_alt):
                    zj = zj_alt
        if zh:
            zh = zh if os.path.isabs(zh) else os.path.abspath(os.path.join(out_abs, zh))
            if zh and not os.path.isfile(zh):
                zh_alt = os.path.abspath(os.path.join(session_dir, os.path.basename(zh)))
                if os.path.isfile(zh_alt):
                    zh = zh_alt
        if zj and os.path.isfile(zj):
            zap_findings = parse_zap_traditional_json(zj)
            html_bn = os.path.basename(zh) if zh and os.path.isfile(zh) else None
            reporter.add_result(
                "ZAPScanner",
                {
                    "findings": zap_findings,
                    "output": f"ZAP JSON ingested: {zj}\nAlerts aggregated into findings list.",
                    "valid": True,
                    "json_path": zj,
                    "html_path": zh if zh and os.path.isfile(zh) else None,
                    "html_basename": html_bn,
                },
            )
            reporter.print_status(f"Loaded ZAP JSON report ({len(zap_findings)} aggregated finding row(s)).")
        elif args.zap_report_json or args.zap_report_html:
            reporter.print_status(
                "ZAP report path(s) set but JSON file not found; skipping ZAP ingestion.",
                style="yellow",
            )

        # Generate Reports
        reporter.print_status("Generating Reports...")
        reporter.save_individual_module_reports()
        reporter.generate_cli_report()
        reporter.generate_file_report() # Keep Markdown for backup
        reporter.generate_html_report()
        
        reporter.print_success("Scan Verification Complete.")
        if reporter.had_execution_failure() and not args.lenient_exit:
            reporter.print_status(
                "Exiting with status 1: one or more stages did not complete successfully "
                "(see logs under the session directory). Use --lenient-exit to always exit 0 after reports.",
                style="yellow",
            )
            sys.exit(1)

    except Exception as e:
        reporter.print_error(f"An unexpected error occurred: {str(e)}")
        import traceback
        # console.print(traceback.format_exc()) # Optional: show traceback in verbose mode
        sys.exit(1)


if __name__ == "__main__":
    main()
