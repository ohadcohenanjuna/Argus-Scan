import nmap
import re
import requests
import shlex
import ssl
import socket
import subprocess
import shutil
from urllib.parse import urlparse
from enum import Enum

class Severity(Enum):
    CRITICAL = 25
    HIGH = 15
    MEDIUM = 10
    LOW = 5
    INFO = 0

class ScannerModule:
    def __init__(self, target):
        self.target = target
        self.hostname = self._get_hostname(target)
        self.findings = [] # List of {"name": str, "severity": Severity, "description": str}

    def _get_hostname(self, target):
        parsed = urlparse(target)
        if parsed.netloc:
            return parsed.netloc
        return target.split("/")[0]

    def run(self):
        raise NotImplementedError

class PortScanner(ScannerModule):
    def run(self):
        try:
            nm = nmap.PortScanner()
        except nmap.PortScannerError:
             return {"error": "Nmap not found", "severity": Severity.INFO, "valid": False}
        except Exception:
             # Fallback if nmap installed but something else fails
             return {"error": "Nmap Init Failed", "severity": Severity.INFO, "valid": False}

        risky_ports = {
            21: "FTP (Plaintext)",
            23: "Telnet (Plaintext)",
            3389: "RDP (Exposed)",
            445: "SMB (High Risk)",
            3306: "MySQL (Exposed DB)"
        }

        try:
            ip = socket.gethostbyname(self.hostname)
            nm.scan(ip, arguments='-F -sV')
            
            open_ports = []
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                     for port in nm[ip][proto].keys():
                        state = nm[ip][proto][port]['state']
                        name = nm[ip][proto][port]['name']
                        
                        severity = Severity.INFO
                        if port in risky_ports and state == 'open':
                            severity = Severity.HIGH
                            self.findings.append({
                                "name": f"Risky Port {port} Open",
                                "severity": Severity.HIGH,
                                "description": f"{name} service found on {port}. {risky_ports[port]}",
                                "current": f"Port {port} is OPEN running {name}",
                                "recommendation": f"Close port {port} if not explicitly required. If needed, restrict access via firewall."
                            })
                        
                        open_ports.append({
                            "port": port,
                            "state": state,
                            "name": name,
                            "severity": severity.name
                        })
            
            return {"open_ports": open_ports, "findings": [fify(f) for f in self.findings], "valid": True}
        except Exception as e:
            return {"error": str(e), "valid": False}

class HeaderScanner(ScannerModule):
    def __init__(self, target, verify_ssl=True):
        super().__init__(target)
        self.verify_ssl = verify_ssl

    def run(self):
        target_url = self.target
        if not target_url.startswith("http"):
            target_url = "http://" + target_url
            
        required_headers = {
            "Strict-Transport-Security": (Severity.HIGH, "Ensure communication happens over HTTPS."),
            "Content-Security-Policy": (Severity.MEDIUM, "Restrict sources for content (scripts, images, etc.) to prevent XSS."),
            "X-Frame-Options": (Severity.MEDIUM, "Prevent clickjacking by denying or restricting iframe embedding."),
            "X-Content-Type-Options": (Severity.LOW, "Prevent MIME-sniffing."),
            "Referrer-Policy": (Severity.LOW, "Control how much referrer information is included with requests.")
        }
        
        try:
            r = requests.get(target_url, timeout=10, verify=self.verify_ssl)
            headers = r.headers
            
            missing = []
            present = {}
            
            for h, (sev, rationale) in required_headers.items():
                if h not in headers:
                    missing.append(h)
                    self.findings.append({
                        "name": f"Missing Header: {h}",
                        "severity": sev,
                        "description": f"The security header {h} is missing from the response. {rationale}",
                        "current": f"Header {h} is MISSING",
                        "recommendation": f"Configure the web server to send the '{h}' header."
                    })
                else:
                    present[h] = headers[h]
            
            return {
                "missing": missing, 
                "present": present, 
                "findings": [fify(f) for f in self.findings],
                "valid": True
            }
        except Exception as e:
            return {"error": str(e), "valid": False}

class SSLScanner(ScannerModule):
    def run(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check Expiry
                    import datetime
                    notAfter_str = cert['notAfter']
                    # Format: Sep 20 23:59:59 2024 GMT
                    expiry_date = datetime.datetime.strptime(notAfter_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry_date - datetime.datetime.now()).days
                    
                    if days_left < 0:
                        self.findings.append({
                            "name": "SSL Certificate Expired",
                            "severity": Severity.CRITICAL,
                            "description": f"The SSL certificate expired on {notAfter_str}.",
                            "current": f"Expired {abs(days_left)} days ago",
                            "recommendation": "Renew the SSL certificate immediately."
                        })
                    elif days_left < 30:
                        self.findings.append({
                            "name": "SSL Certificate Expiring Soon",
                            "severity": Severity.MEDIUM,
                            "description": f"The SSL certificate will expire in {days_left} days.",
                            "current": f"Expires in {days_left} days",
                            "recommendation": "Plan to renew the SSL certificate soon."
                        })

                    return {
                        "valid": True,
                        "issuer": dict(x[0] for x in cert['issuer']).get('commonName'),
                        "expiry": notAfter_str,
                        "findings": [fify(f) for f in self.findings]
                    }
        except Exception as e:
             # Basic error means SSL likely broken or not present
             self.findings.append({
                 "name": "SSL Connection Failed",
                 "severity": Severity.HIGH,
                 "description": f"Could not establish a secure connection: {str(e)}",
                 "current": "SSL Connection Failed",
                 "recommendation": "Ensure port 443 is open and a valid certificate is installed."
             })
             return {"valid": False, "error": str(e), "findings": [fify(f) for f in self.findings]}

class ToolScanner(ScannerModule):
    def __init__(self, target, tool_name, command_template, verbose=False, log_file=None):
        super().__init__(target)
        self.tool_name = tool_name
        self.command_template = command_template
        self.verbose = verbose
        self.log_file = log_file  # if set, stream tool stdout here instead of printing

    def check_installed(self):
        return shutil.which(self.tool_name) is not None

    def run(self):
        if not self.check_installed():
            return {"error": f"{self.tool_name} not installed", "valid": False}
        
        target_url = self.target
        if not target_url.startswith("http"):
            target_url = "http://" + target_url

        # Quote arguments to prevent shell injection when passing to subprocess
        try:
            safe_target = shlex.quote(target_url)
            safe_hostname = shlex.quote(self.hostname)
        except (ValueError, TypeError):
            return {"error": "Invalid target or hostname for command", "valid": False}
        cmd = self.command_template.format(target=safe_target, hostname=safe_hostname)

        log_fp = None
        if self.log_file:
            # Stream subprocess stdout line-by-line (not tee). Flush each line so tail -f sees output during long scans.
            log_fp = open(self.log_file, "w", encoding="utf-8", errors="replace")
            log_fp.write(f"command: {cmd}\n---\n")
            log_fp.flush()
        elif self.verbose:
            print(f"  [Tool] Running: {cmd}")

        try:
            # interactive output streaming
            process = subprocess.Popen(
                cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, # Merge stderr into stdout
                text=True,
                bufsize=1 # Line buffered
            )
            
            output_lines = []
            
            # Print output as it arrives
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            
            for line in process.stdout:
                line_clean = line.strip()
                if line_clean:
                    # Strip ANSI codes for clean logs
                    line_no_ansi = ansi_escape.sub('', line_clean)
                    if log_fp:
                        log_fp.write(line_no_ansi + "\n")
                        log_fp.flush()
                    elif self.verbose:
                        print(f"  [Tool] {line_no_ansi}")
                    output_lines.append(line_no_ansi)
            
            process.wait()
            if log_fp:
                log_fp.write(f"---\nexit code: {process.returncode}\n")
                log_fp.flush()
                log_fp.close()
                log_fp = None
            full_output = "\n".join(output_lines)

            valid = True
            # Nikto exit codes are not reliable (non-zero may mean findings); detect abandoned scans in output.
            if self.tool_name == "nikto" and full_output:
                lo = full_output.lower()
                if "error limit (" in lo and "giving up" in lo:
                    valid = False

            # Naive findings based on output size or keywords could be added here
            # For now, tool findings are generic INFO unless parsed
            return {
                "output": full_output,
                "error_output": "",  # Captured in stdout/output
                "return_code": process.returncode,
                "findings": [],
                "valid": valid,
            }
        except Exception as e:
            err = f"ERROR executing tool: {e}"
            if log_fp:
                try:
                    log_fp.write(err + "\n")
                finally:
                    log_fp.close()
            elif self.log_file:
                with open(self.log_file, "a", encoding="utf-8", errors="replace") as lf:
                    lf.write(err + "\n")
            else:
                print(err)
            return {"error": str(e), "valid": False}

def fify(finding):
    # Helper to convert Severity Enum to string for JSON serialization
    f = finding.copy()
    f['severity'] = f['severity'].name
    f['score_penalty'] = finding['severity'].value
    return f
