import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

class Reporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.results = {}
        self.target = ""
        self.findings = []
        self.score = 100
        self.report_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.nuclei_secret_file_used = False

    def _target_slug(self):
        return (
            self.target.replace("http://", "")
            .replace("https://", "")
            .replace("/", "_")
            .replace(":", "_")
        )

    def set_target(self, target):
        self.target = target
        self.report_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    def set_nuclei_secret_file_used(self, used: bool):
        """True when --nuclei-secret-file was passed (Nuclei authenticated cookie/static auth)."""
        self.nuclei_secret_file_used = bool(used)

    def nuclei_scan_mode_markdown(self) -> str:
        if "NucleiScanner" not in self.results:
            return "**Nuclei scan:** Not run (use `--full` to include)."
        if self.nuclei_secret_file_used:
            return "**Nuclei scan:** Authenticated (`--nuclei-secret-file` provided). Port, header, SSL, and Nikto checks are still unauthenticated."
        return "**Nuclei scan:** Unauthenticated. Port, header, SSL, and Nikto checks are unauthenticated."

    def nuclei_scan_mode_plain(self) -> str:
        if "NucleiScanner" not in self.results:
            return "Nuclei scan was not run (use --full to include)."
        if self.nuclei_secret_file_used:
            return "Nuclei: authenticated (--nuclei-secret-file). Other stages are unauthenticated."
        return "Nuclei: unauthenticated. Other stages are unauthenticated."

    def add_result(self, module_name, data):
        self.results[module_name] = data
        if "findings" in data:
            self.findings.extend(data["findings"])

    def calculate_score(self):
        # Base 100, deduct
        deduction = 0
        for f in self.findings:
            deduction += f.get('score_penalty', 0)
        
        self.score = max(0, 100 - deduction)

        # Assign Grade
        if self.score >= 90: return "A", "green"
        if self.score >= 80: return "B", "blue"
        if self.score >= 70: return "C", "yellow"
        if self.score >= 60: return "D", "orange1"
        return "F", "red"

    def print_header(self):
        console.print(Panel(f"[bold blue]AutoVAPT v2.0[/bold blue]\nTarget: [green]{self.target}[/green]\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", expand=False))

    def print_status(self, message, style="bold white"):
        console.print(f"[{style}]{message}[/{style}]")

    def print_error(self, message):
        console.print(f"[bold red]ERROR: {message}[/bold red]")
    
    def print_success(self, message):
         console.print(f"[bold green]SUCCESS: {message}[/bold green]")

    def generate_cli_report(self):
        grade, color = self.calculate_score()
        
        console.print("\n[bold underline]Scan Summary[/bold underline]")
        console.print(f"[dim]{self.nuclei_scan_mode_plain()}[/dim]")
        console.print(f"Security Score: [{color}]{self.score}/100 ({grade})[/{color}]")
        
        # Findings Count
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity")
            if sev in counts:
                counts[sev] += 1
        
        table = Table(title="Vulnerabilities Found")
        table.add_column("Severity", style="cyan")
        table.add_column("Count", style="magenta")
        for sev, count in counts.items():
            if count > 0:
                style = "red" if sev in ["CRITICAL", "HIGH"] else "yellow"
                table.add_row(f"[{style}]{sev}[/{style}]", str(count))
        console.print(table)
        
        if not self.findings:
             console.print("[green]No specific vulnerabilities matched known signatures.[/green]")

    def generate_file_report(self):
        grade, color = self.calculate_score()
        safe_target = self._target_slug()
        filename = f"vapt_report_{safe_target}_{self.report_ts}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"# VAPT Report for {self.target}\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"{self.nuclei_scan_mode_markdown()}\n\n")
            f.write(f"# Security Score: {self.score}/100 (Grade: {grade})\n\n")
            
            # Exec Summary
            f.write("## Executive Summary\n")
            f.write("| Severity | Count |\n|---|---|\n")
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for finding in self.findings:
                sev = finding.get("severity")
                if sev in counts:
                    counts[sev] += 1
            for sev, count in counts.items():
                if count or sev in ["CRITICAL", "HIGH"]:
                    f.write(f"| {sev} | {count} |\n")
            
            f.write("\n---\n")

            # Detailed Findings
            if self.findings:
                f.write("## Detailed Findings\n")
                for finding in self.findings:
                    f.write(f"### [{finding['severity']}] {finding['name']}\n")
                    f.write(f"{finding['description']}\n\n")
            
            f.write("\n---\n")

            # Module Details
            f.write("## Raw Module Data\n")
            
            # Headers
            if "HeaderScanner" in self.results:
                h = self.results["HeaderScanner"]
                f.write("<details><summary><b>Header Analysis</b></summary>\n\n")
                if h.get("missing"):
                    f.write("**Missing Headers**:\n")
                    for m in h["missing"]: f.write(f"- {m}\n")
                else:
                    f.write("✅ All recommended security headers are present!\n")
                f.write("\n**Present Headers**:\n")
                for k, v in h.get("present", {}).items():
                    f.write(f"- **{k}**: `{v}`\n")
                f.write("\n</details>\n\n")

            # Ports
            if "PortScanner" in self.results:
                p = self.results["PortScanner"]
                f.write("<details><summary><b>Port Scan Results</b></summary>\n\n")
                if p.get("open_ports"):
                    f.write("| Port | State | Service |\n|---|---|---|\n")
                    for op in p["open_ports"]:
                        f.write(f"| {op['port']} | {op['state']} | {op['name']} |\n")
                else:
                    f.write("No open ports found (in top 100 scan) or firewall blocking.\n")
                f.write("\n</details>\n\n")

            # Tool Output
            for tool in ["NiktoScanner", "NucleiScanner"]:
                if tool in self.results:
                    f.write(f"<details><summary><b>{tool} Output</b></summary>\n\n")
                    f.write("```\n")
                    f.write(self.results[tool].get("output", "No Output"))
                    f.write("\n```\n")
                    f.write("\n</details>\n\n")

    def save_individual_module_reports(self):
        """Write one text file per scan module under output_dir (same session timestamp as aggregate reports)."""
        safe_target = self._target_slug()
        written = []

        def write_module(label, content):
            name = f"{label}_{safe_target}_{self.report_ts}.txt"
            path = os.path.join(self.output_dir, name)
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Target: {self.target}\n")
                f.write(f"Module: {label}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("---\n\n")
                f.write(content)
            written.append(path)

        if "PortScanner" in self.results:
            p = self.results["PortScanner"]
            if p.get("error"):
                body = f"Error: {p['error']}\n"
            elif not p.get("valid"):
                body = "Scan did not complete successfully.\n"
            else:
                lines = []
                for op in p.get("open_ports") or []:
                    lines.append(
                        f"Port {op['port']}\t{op['state']}\t{op['name']}\t(severity: {op.get('severity', 'N/A')})"
                    )
                if not lines:
                    lines.append("No open ports in fast scan range, or host unreachable / filtered.")
                body = "Open ports:\n" + "\n".join(lines) + "\n"
                if p.get("findings"):
                    body += "\nFindings:\n"
                    for fn in p["findings"]:
                        body += f"  [{fn.get('severity')}] {fn.get('name')}: {fn.get('description', '')}\n"
            write_module("portscan_nmap", body)

        if "HeaderScanner" in self.results:
            h = self.results["HeaderScanner"]
            if h.get("error"):
                body = f"Error: {h['error']}\n"
            elif not h.get("valid"):
                body = "Scan did not complete successfully.\n"
            else:
                body = ""
                miss = h.get("missing") or []
                if miss:
                    body += "Missing security headers:\n" + "\n".join(f"  - {m}" for m in miss) + "\n\n"
                else:
                    body += "All recommended security headers are present.\n\n"
                body += "Present (tracked) headers:\n"
                for k, v in (h.get("present") or {}).items():
                    body += f"  {k}: {v}\n"
                if h.get("findings"):
                    body += "\nFindings:\n"
                    for fn in h["findings"]:
                        body += f"  [{fn.get('severity')}] {fn.get('name')}: {fn.get('description', '')}\n"
            write_module("headers", body)

        if "SSLScanner" in self.results:
            s = self.results["SSLScanner"]
            lines = []
            if s.get("issuer"):
                lines.append(f"Issuer: {s['issuer']}")
            if s.get("expiry"):
                lines.append(f"Expiry: {s['expiry']}")
            lines.append(f"valid: {s.get('valid')}")
            if s.get("error"):
                lines.append(f"Error: {s['error']}")
            body = "\n".join(lines) + "\n"
            if s.get("findings"):
                body += "\nFindings:\n"
                for fn in s["findings"]:
                    body += f"  [{fn.get('severity')}] {fn.get('name')}: {fn.get('description', '')}\n"
            write_module("ssl_tls", body)

        for tool_key, file_label in (
            ("NiktoScanner", "nikto"),
            ("NucleiScanner", "nuclei"),
        ):
            if tool_key not in self.results:
                continue
            t = self.results[tool_key]
            if t.get("error"):
                body = f"Error: {t['error']}\n"
            else:
                body = t.get("output") or "(no output captured)\n"
                rc = t.get("return_code")
                if rc is not None:
                    body += f"\n---\nexit code: {rc}\n"
            write_module(file_label, body)

        for path in written:
            console.print(f"[bold green]Module report saved: {path}[/bold green]")

    def generate_html_report(self):
        try:
            from jinja2 import Environment, FileSystemLoader
            # Load template from 'templates' directory relative to this script
            template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template('report_template.html')
            
            grade, color = self.calculate_score()

            safe_target = self._target_slug()
            filename = f"vapt_report_{safe_target}_{self.report_ts}.html"
            filepath = os.path.join(self.output_dir, filename)
            
            html_content = template.render(
                target=self.target,
                score=self.score,
                grade=grade,
                date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                findings=self.findings,
                results=self.results,
                nuclei_scan_mode_plain=self.nuclei_scan_mode_plain(),
            )
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            console.print(f"\n[bold green]HTML report saved to: {filepath}[/bold green]")
            
        except ImportError:
            console.print("[red]Jinja2 not found. Cannot generate HTML report.[/red]")
        except Exception as e:
            console.print(f"[red]Failed to generate HTML report: {e}[/red]")
