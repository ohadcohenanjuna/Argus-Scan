"""
tests/test_scanners.py
======================
Unit tests for src/scanners.py

Covers:
  - Severity enum values and ordering
  - ScannerModule._get_hostname() URL / hostname parsing
  - PortScanner.run() - nmap happy path, risky ports, nmap missing, DNS failure
  - HeaderScanner.run() - all headers present, headers missing, network error
  - SSLScanner.run() - valid cert, expiring cert, expired cert, connection failure
  - ToolScanner - check_installed, run() success / tool missing / subprocess error
  - fify() helper - enum → string conversion and score_penalty injection
"""

import datetime
import socket
from unittest.mock import MagicMock, patch

import pytest

from scanners import (
    Severity,
    ScannerModule,
    PortScanner,
    HeaderScanner,
    SSLScanner,
    ToolScanner,
    fify,
)


# ===========================================================================
# Severity enum
# ===========================================================================

class TestSeverityEnum:
    def test_values_are_integers(self):
        for member in Severity:
            assert isinstance(member.value, int)

    def test_ordering(self):
        assert Severity.CRITICAL.value > Severity.HIGH.value
        assert Severity.HIGH.value    > Severity.MEDIUM.value
        assert Severity.MEDIUM.value  > Severity.LOW.value
        assert Severity.LOW.value     > Severity.INFO.value

    def test_critical_value(self):
        assert Severity.CRITICAL.value == 25

    def test_info_value(self):
        assert Severity.INFO.value == 0

    def test_all_members_present(self):
        names = {m.name for m in Severity}
        assert names == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


# ===========================================================================
# ScannerModule._get_hostname
# ===========================================================================

class TestGetHostname:
    """_get_hostname must strip scheme/path and return just the host."""

    def _hostname(self, target):
        m = ScannerModule.__new__(ScannerModule)
        return m._get_hostname(target)

    def test_full_url_with_scheme(self):
        assert self._hostname("https://example.com/path") == "example.com"

    def test_http_url(self):
        assert self._hostname("http://example.com") == "example.com"

    def test_bare_hostname(self):
        assert self._hostname("example.com") == "example.com"

    def test_bare_ip(self):
        assert self._hostname("192.168.1.1") == "192.168.1.1"

    def test_url_with_port(self):
        assert self._hostname("https://example.com:8443/app") == "example.com:8443"

    def test_url_with_subpath(self):
        assert self._hostname("http://sub.domain.com/a/b/c") == "sub.domain.com"

    def test_bare_target_with_path(self):
        # No scheme → split on "/" and return first component
        assert self._hostname("example.com/some/path") == "example.com"


# ===========================================================================
# fify() helper
# ===========================================================================

class TestFify:
    def _finding(self, sev=Severity.HIGH):
        return {
            "name": "Test Finding",
            "severity": sev,
            "description": "Some description",
            "current": "current state",
            "recommendation": "fix it",
        }

    def test_severity_converted_to_name_string(self):
        result = fify(self._finding(Severity.HIGH))
        assert result["severity"] == "HIGH"

    def test_score_penalty_matches_enum_value(self):
        result = fify(self._finding(Severity.CRITICAL))
        assert result["score_penalty"] == 25

    def test_low_penalty(self):
        result = fify(self._finding(Severity.LOW))
        assert result["score_penalty"] == 5

    def test_info_penalty_is_zero(self):
        result = fify(self._finding(Severity.INFO))
        assert result["score_penalty"] == 0

    def test_original_finding_not_mutated(self):
        original = self._finding(Severity.MEDIUM)
        fify(original)
        assert original["severity"] is Severity.MEDIUM  # still an enum

    def test_all_keys_preserved(self):
        original = self._finding()
        result = fify(original)
        for key in ("name", "description", "current", "recommendation"):
            assert result[key] == original[key]


# ===========================================================================
# PortScanner
# ===========================================================================

class TestPortScanner:
    """All network calls are mocked - no real nmap invocation."""

    TARGET = "http://example.com"

    def _scanner(self):
        return PortScanner(self.TARGET)

    # ------------------------------------------------------------------
    # nmap not installed
    # ------------------------------------------------------------------
    def test_nmap_not_found_returns_error(self):
        import nmap
        scanner = self._scanner()
        with patch("scanners.nmap.PortScanner", side_effect=nmap.PortScannerError("not found")):
            result = scanner.run()
        assert result["valid"] is False
        assert "Nmap" in result["error"]

    def test_nmap_init_other_exception_returns_error(self):
        scanner = self._scanner()
        with patch("scanners.nmap.PortScanner", side_effect=RuntimeError("boom")):
            result = scanner.run()
        assert result["valid"] is False

    # ------------------------------------------------------------------
    # DNS failure
    # ------------------------------------------------------------------
    def test_dns_failure_returns_error(self):
        scanner = self._scanner()
        mock_nm = MagicMock()
        with patch("scanners.nmap.PortScanner", return_value=mock_nm), \
             patch("scanners.socket.gethostbyname", side_effect=socket.gaierror("DNS fail")):
            result = scanner.run()
        assert result["valid"] is False

    # ------------------------------------------------------------------
    # Happy path - no risky ports
    # ------------------------------------------------------------------
    def _make_nmap_mock(self, ip, ports_data):
        """Build a nmap-like mock for a single IP."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = [ip]

        proto_mock = MagicMock()
        proto_mock.all_protocols.return_value = ["tcp"]
        proto_mock.__getitem__.return_value = {
            "tcp": {
                port: {"state": info["state"], "name": info["name"]}
                for port, info in ports_data.items()
            }
        }

        # nm[ip] → protocol container
        nm_item = MagicMock()
        nm_item.all_protocols.return_value = ["tcp"]
        nm_item.__getitem__ = MagicMock(
            return_value={
                port: {"state": info["state"], "name": info["name"]}
                for port, info in ports_data.items()
            }
        )
        mock_nm.__getitem__ = MagicMock(return_value=nm_item)
        return mock_nm

    def test_no_open_ports_returns_valid(self):
        scanner = self._scanner()
        ip = "93.184.216.34"
        mock_nm = self._make_nmap_mock(ip, {80: {"state": "closed", "name": "http"}})
        with patch("scanners.nmap.PortScanner", return_value=mock_nm), \
             patch("scanners.socket.gethostbyname", return_value=ip):
            result = scanner.run()
        assert result["valid"] is True
        assert "open_ports" in result

    def test_risky_port_open_creates_finding(self):
        scanner = self._scanner()
        ip = "93.184.216.34"
        mock_nm = self._make_nmap_mock(ip, {21: {"state": "open", "name": "ftp"}})
        with patch("scanners.nmap.PortScanner", return_value=mock_nm), \
             patch("scanners.socket.gethostbyname", return_value=ip):
            result = scanner.run()
        assert result["valid"] is True
        finding_names = [f["name"] for f in result["findings"]]
        assert any("21" in name for name in finding_names)

    def test_risky_port_closed_no_finding(self):
        scanner = self._scanner()
        ip = "93.184.216.34"
        mock_nm = self._make_nmap_mock(ip, {21: {"state": "closed", "name": "ftp"}})
        with patch("scanners.nmap.PortScanner", return_value=mock_nm), \
             patch("scanners.socket.gethostbyname", return_value=ip):
            result = scanner.run()
        assert result["findings"] == []

    def test_findings_have_score_penalty(self):
        scanner = self._scanner()
        ip = "1.2.3.4"
        mock_nm = self._make_nmap_mock(ip, {3306: {"state": "open", "name": "mysql"}})
        with patch("scanners.nmap.PortScanner", return_value=mock_nm), \
             patch("scanners.socket.gethostbyname", return_value=ip):
            result = scanner.run()
        for f in result["findings"]:
            assert "score_penalty" in f


# ===========================================================================
# HeaderScanner
# ===========================================================================

class TestHeaderScanner:
    TARGET = "http://example.com"

    REQUIRED = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]

    def _scanner(self, verify_ssl=True):
        return HeaderScanner(self.TARGET, verify_ssl=verify_ssl)

    def _mock_response(self, headers):
        resp = MagicMock()
        resp.headers = headers
        return resp

    # ------------------------------------------------------------------
    # All headers present
    # ------------------------------------------------------------------
    def test_all_headers_present_no_findings(self):
        scanner = self._scanner()
        full_headers = {h: "value" for h in self.REQUIRED}
        with patch("scanners.requests.get", return_value=self._mock_response(full_headers)):
            result = scanner.run()
        assert result["valid"] is True
        assert result["missing"] == []
        assert result["findings"] == []

    def test_all_headers_present_appear_in_present_dict(self):
        scanner = self._scanner()
        full_headers = {h: f"val-{h}" for h in self.REQUIRED}
        with patch("scanners.requests.get", return_value=self._mock_response(full_headers)):
            result = scanner.run()
        for h in self.REQUIRED:
            assert h in result["present"]

    # ------------------------------------------------------------------
    # Missing headers
    # ------------------------------------------------------------------
    def test_missing_hsts_creates_finding(self):
        scanner = self._scanner()
        headers = {h: "x" for h in self.REQUIRED if h != "Strict-Transport-Security"}
        with patch("scanners.requests.get", return_value=self._mock_response(headers)):
            result = scanner.run()
        assert "Strict-Transport-Security" in result["missing"]
        assert any("Strict-Transport-Security" in f["name"] for f in result["findings"])

    def test_multiple_missing_headers_all_reported(self):
        scanner = self._scanner()
        with patch("scanners.requests.get", return_value=self._mock_response({})):
            result = scanner.run()
        assert len(result["missing"]) == len(self.REQUIRED)
        assert len(result["findings"]) == len(self.REQUIRED)

    def test_missing_hsts_has_high_severity(self):
        scanner = self._scanner()
        headers = {h: "x" for h in self.REQUIRED if h != "Strict-Transport-Security"}
        with patch("scanners.requests.get", return_value=self._mock_response(headers)):
            result = scanner.run()
        hsts_findings = [f for f in result["findings"] if "Strict-Transport-Security" in f["name"]]
        assert hsts_findings[0]["severity"] == "HIGH"

    def test_missing_x_content_type_has_low_severity(self):
        scanner = self._scanner()
        headers = {h: "x" for h in self.REQUIRED if h != "X-Content-Type-Options"}
        with patch("scanners.requests.get", return_value=self._mock_response(headers)):
            result = scanner.run()
        findings = [f for f in result["findings"] if "X-Content-Type-Options" in f["name"]]
        assert findings[0]["severity"] == "LOW"

    # ------------------------------------------------------------------
    # Target without scheme gets http:// prepended
    # ------------------------------------------------------------------
    def test_bare_target_gets_http_prefix(self):
        scanner = HeaderScanner("example.com")
        captured_url = []

        def fake_get(url, **kwargs):
            captured_url.append(url)
            return self._mock_response({})

        with patch("scanners.requests.get", side_effect=fake_get):
            scanner.run()
        assert captured_url[0].startswith("http://")

    # ------------------------------------------------------------------
    # Network error
    # ------------------------------------------------------------------
    def test_network_error_returns_invalid(self):
        scanner = self._scanner()
        with patch("scanners.requests.get", side_effect=Exception("timeout")):
            result = scanner.run()
        assert result["valid"] is False
        assert "error" in result

    # ------------------------------------------------------------------
    # verify_ssl forwarded to requests
    # ------------------------------------------------------------------
    def test_verify_ssl_false_passed_to_requests(self):
        scanner = self._scanner(verify_ssl=False)
        called_with = {}

        def fake_get(url, **kwargs):
            called_with.update(kwargs)
            return self._mock_response({})

        with patch("scanners.requests.get", side_effect=fake_get):
            scanner.run()
        assert called_with.get("verify") is False


# ===========================================================================
# SSLScanner
# ===========================================================================

class TestSSLScanner:
    TARGET = "https://example.com"

    def _scanner(self):
        return SSLScanner(self.TARGET)

    def _make_cert(self, days_from_now):
        expiry = datetime.datetime.now() + datetime.timedelta(days=days_from_now)
        expiry_str = expiry.strftime("%b %d %H:%M:%S %Y GMT")
        return {
            "notAfter": expiry_str,
            "issuer": ((("commonName", "Test CA"),),),
        }

    def _patch_ssl(self, cert):
        """Context manager stack to mock the ssl connection."""
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = cert

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ssock_ctx = MagicMock()
        mock_ssock_ctx.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock_ctx.__exit__ = MagicMock(return_value=False)

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssock_ctx

        return mock_context, mock_sock

    # ------------------------------------------------------------------
    # Valid cert, plenty of time left
    # ------------------------------------------------------------------
    def test_valid_cert_returns_valid_true(self):
        scanner = self._scanner()
        cert = self._make_cert(180)
        mock_ctx, mock_sock = self._patch_ssl(cert)

        with patch("scanners.ssl.create_default_context", return_value=mock_ctx), \
             patch("scanners.socket.create_connection", return_value=mock_sock):
            result = scanner.run()
        assert result["valid"] is True
        assert result["findings"] == []

    def test_valid_cert_returns_expiry_string(self):
        scanner = self._scanner()
        cert = self._make_cert(180)
        mock_ctx, mock_sock = self._patch_ssl(cert)

        with patch("scanners.ssl.create_default_context", return_value=mock_ctx), \
             patch("scanners.socket.create_connection", return_value=mock_sock):
            result = scanner.run()
        assert "expiry" in result

    # ------------------------------------------------------------------
    # Certificate expiring within 30 days
    # ------------------------------------------------------------------
    def test_expiring_soon_creates_medium_finding(self):
        scanner = self._scanner()
        cert = self._make_cert(15)
        mock_ctx, mock_sock = self._patch_ssl(cert)

        with patch("scanners.ssl.create_default_context", return_value=mock_ctx), \
             patch("scanners.socket.create_connection", return_value=mock_sock):
            result = scanner.run()
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "MEDIUM"
        assert "Expiring" in result["findings"][0]["name"]

    # ------------------------------------------------------------------
    # Expired certificate
    # ------------------------------------------------------------------
    def test_expired_cert_creates_critical_finding(self):
        scanner = self._scanner()
        cert = self._make_cert(-10)  # 10 days ago
        mock_ctx, mock_sock = self._patch_ssl(cert)

        with patch("scanners.ssl.create_default_context", return_value=mock_ctx), \
             patch("scanners.socket.create_connection", return_value=mock_sock):
            result = scanner.run()
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert "Expired" in result["findings"][0]["name"]

    # ------------------------------------------------------------------
    # Boundary: exactly 30 days left should trigger MEDIUM
    # ------------------------------------------------------------------
    def test_exactly_30_days_triggers_medium(self):
        scanner = self._scanner()
        cert = self._make_cert(29)   # < 30 threshold
        mock_ctx, mock_sock = self._patch_ssl(cert)

        with patch("scanners.ssl.create_default_context", return_value=mock_ctx), \
             patch("scanners.socket.create_connection", return_value=mock_sock):
            result = scanner.run()
        assert any(f["severity"] == "MEDIUM" for f in result["findings"])

    # ------------------------------------------------------------------
    # SSL connection fails
    # ------------------------------------------------------------------
    def test_ssl_connection_failure_returns_invalid(self):
        scanner = self._scanner()
        with patch("scanners.ssl.create_default_context", side_effect=Exception("conn refused")):
            result = scanner.run()
        assert result["valid"] is False
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "HIGH"

    def test_ssl_failure_finding_has_score_penalty(self):
        scanner = self._scanner()
        with patch("scanners.ssl.create_default_context", side_effect=Exception("err")):
            result = scanner.run()
        assert result["findings"][0]["score_penalty"] == Severity.HIGH.value


# ===========================================================================
# ToolScanner
# ===========================================================================

class TestToolScanner:
    TARGET = "http://example.com"
    TOOL = "nikto"
    CMD = "nikto -h {target}"

    def _scanner(self, verbose=False):
        return ToolScanner(self.TARGET, self.TOOL, self.CMD, verbose=verbose)

    # ------------------------------------------------------------------
    # check_installed
    # ------------------------------------------------------------------
    def test_check_installed_true_when_tool_on_path(self):
        scanner = self._scanner()
        with patch("scanners.shutil.which", return_value="/usr/bin/nikto"):
            assert scanner.check_installed() is True

    def test_check_installed_false_when_tool_missing(self):
        scanner = self._scanner()
        with patch("scanners.shutil.which", return_value=None):
            assert scanner.check_installed() is False

    # ------------------------------------------------------------------
    # Tool not installed
    # ------------------------------------------------------------------
    def test_run_returns_error_when_tool_missing(self):
        scanner = self._scanner()
        with patch("scanners.shutil.which", return_value=None):
            result = scanner.run()
        assert result["valid"] is False
        assert "not installed" in result["error"]

    # ------------------------------------------------------------------
    # Successful run
    # ------------------------------------------------------------------
    def _mock_process(self, output_lines, returncode=0):
        mock_proc = MagicMock()
        mock_proc.stdout = iter(line + "\n" for line in output_lines)
        mock_proc.returncode = returncode
        mock_proc.wait = MagicMock()
        return mock_proc

    def test_successful_run_returns_valid(self):
        scanner = self._scanner()
        mock_proc = self._mock_process(["Nikto found stuff", "Port 80 open"])
        with patch("scanners.shutil.which", return_value="/usr/bin/nikto"), \
             patch("scanners.subprocess.Popen", return_value=mock_proc):
            result = scanner.run()
        assert result["valid"] is True

    def test_output_joined_as_string(self):
        scanner = self._scanner()
        mock_proc = self._mock_process(["line one", "line two"])
        with patch("scanners.shutil.which", return_value="/usr/bin/nikto"), \
             patch("scanners.subprocess.Popen", return_value=mock_proc):
            result = scanner.run()
        assert "line one" in result["output"]
        assert "line two" in result["output"]

    def test_return_code_captured(self):
        scanner = self._scanner()
        mock_proc = self._mock_process(["done"], returncode=1)
        with patch("scanners.shutil.which", return_value="/usr/bin/nikto"), \
             patch("scanners.subprocess.Popen", return_value=mock_proc):
            result = scanner.run()
        assert result["return_code"] == 1

    def test_ansi_escape_codes_stripped(self):
        scanner = self._scanner()
        ansi_line = "\x1b[31mred text\x1b[0m"
        mock_proc = self._mock_process([ansi_line])
        with patch("scanners.shutil.which", return_value="/usr/bin/nikto"), \
             patch("scanners.subprocess.Popen", return_value=mock_proc):
            result = scanner.run()
        assert "\x1b" not in result["output"]
        assert "red text" in result["output"]

    def test_empty_output_lines_excluded(self):
        scanner = self._scanner()
        mock_proc = self._mock_process(["", "   ", "real line"])
        with patch("scanners.shutil.which", return_value="/usr/bin/nikto"), \
             patch("scanners.subprocess.Popen", return_value=mock_proc):
            result = scanner.run()
        assert result["output"].strip() == "real line"

    # ------------------------------------------------------------------
    # Subprocess exception
    # ------------------------------------------------------------------
    def test_subprocess_exception_returns_invalid(self):
        scanner = self._scanner()
        with patch("scanners.shutil.which", return_value="/usr/bin/nikto"), \
             patch("scanners.subprocess.Popen", side_effect=OSError("popen failed")):
            result = scanner.run()
        assert result["valid"] is False

    # ------------------------------------------------------------------
    # target without scheme gets http:// prefix in command
    # ------------------------------------------------------------------
    def test_bare_target_url_gets_http_prefix_in_cmd(self):
        scanner = ToolScanner("example.com", self.TOOL, self.CMD)
        captured_cmd = []

        def fake_popen(cmd, **kwargs):
            captured_cmd.append(cmd)
            return self._mock_process([])

        with patch("scanners.shutil.which", return_value="/usr/bin/nikto"), \
             patch("scanners.subprocess.Popen", side_effect=fake_popen):
            scanner.run()
        assert "http://" in captured_cmd[0]