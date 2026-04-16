"""
tests/test_reporter.py
======================
Unit tests for src/reporter.py

Covers:
  - Reporter initialisation (output_dir creation)
  - set_target / add_result
  - calculate_score - grading thresholds and deduction logic
  - generate_file_report - markdown content and filename sanitisation
  - generate_html_report - Jinja2 happy path and ImportError fallback
  - generate_cli_report - runs without raising (smoke test)
"""

import os

import pytest
from unittest.mock import MagicMock, patch


from reporter import Reporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(severity_name, penalty):
    return {"name": "Test", "severity": severity_name, "score_penalty": penalty}


def _make_reporter(tmp_path):
    r = Reporter(output_dir=str(tmp_path))
    r.set_target("http://example.com")
    return r


# ===========================================================================
# Initialisation
# ===========================================================================

class TestReporterInit:
    def test_creates_output_dir(self, tmp_path):
        output = tmp_path / "custom_reports"
        Reporter(output_dir=str(output))
        assert output.exists()

    def test_existing_output_dir_no_error(self, tmp_path):
        # Should not raise even if dir already exists
        Reporter(output_dir=str(tmp_path))
        Reporter(output_dir=str(tmp_path))

    def test_default_score_is_100(self, tmp_path):
        r = _make_reporter(tmp_path)
        assert r.score == 100

    def test_findings_initially_empty(self, tmp_path):
        r = _make_reporter(tmp_path)
        assert r.findings == []


# ===========================================================================
# set_target / add_result
# ===========================================================================

class TestAddResult:
    def test_set_target_stored(self, tmp_path):
        r = _make_reporter(tmp_path)
        assert r.target == "http://example.com"

    def test_add_result_stored_by_module_name(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.add_result("HeaderScanner", {"valid": True, "findings": []})
        assert "HeaderScanner" in r.results

    def test_add_result_extends_findings(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.add_result("HeaderScanner", {
            "valid": True,
            "findings": [_finding("HIGH", 15), _finding("LOW", 5)]
        })
        assert len(r.findings) == 2

    def test_add_result_without_findings_key(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.add_result("PortScanner", {"valid": False, "error": "nmap missing"})
        assert r.findings == []

    def test_add_multiple_modules_accumulates(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.add_result("HeaderScanner", {"findings": [_finding("HIGH", 15)]})
        r.add_result("SSLScanner",    {"findings": [_finding("CRITICAL", 25)]})
        assert len(r.findings) == 2


# ===========================================================================
# calculate_score
# ===========================================================================

class TestCalculateScore:
    """
    Grading thresholds from the implementation:
      >= 90 → A   >= 80 → B   >= 70 → C   >= 60 → D   else → F
    """

    def _score(self, tmp_path, penalties):
        r = _make_reporter(tmp_path)
        for p in penalties:
            r.findings.append(_finding("INFO", p))
        return r.calculate_score()

    def test_no_findings_gives_100_and_grade_A(self, tmp_path):
        grade, color = self._score(tmp_path, [])
        assert grade == "A"

    def test_score_is_clamped_at_zero(self, tmp_path):
        r = _make_reporter(tmp_path)
        # Add penalties that sum to more than 100
        for _ in range(10):
            r.findings.append(_finding("CRITICAL", 25))
        r.calculate_score()
        assert r.score == 0

    def test_grade_B_at_85(self, tmp_path):
        grade, _ = self._score(tmp_path, [15])  # 100 - 15 = 85
        assert grade == "B"

    def test_grade_C_at_75(self, tmp_path):
        grade, _ = self._score(tmp_path, [25])  # 100 - 25 = 75
        assert grade == "C"

    def test_grade_D_at_65(self, tmp_path):
        grade, _ = self._score(tmp_path, [25, 10])  # 100 - 35 = 65
        assert grade == "D"

    def test_grade_F_below_60(self, tmp_path):
        grade, _ = self._score(tmp_path, [25, 25, 15])  # 100 - 65 = 35
        assert grade == "F"

    def test_grade_A_at_exactly_90(self, tmp_path):
        grade, _ = self._score(tmp_path, [10])  # 100 - 10 = 90
        assert grade == "A"

    def test_grade_B_at_exactly_80(self, tmp_path):
        grade, _ = self._score(tmp_path, [20])  # 100 - 20 = 80
        assert grade == "B"

    def test_score_attribute_updated(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.findings.append(_finding("HIGH", 15))
        r.calculate_score()
        assert r.score == 85

    def test_returns_tuple_of_grade_and_color(self, tmp_path):
        r = _make_reporter(tmp_path)
        result = r.calculate_score()
        assert isinstance(result, tuple)
        assert len(result) == 2


# ===========================================================================
# generate_file_report (Markdown)
# ===========================================================================

class TestGenerateFileReport:
    def _run(self, tmp_path, findings=None):
        r = _make_reporter(tmp_path)
        if findings:
            r.findings = findings
        r.generate_file_report()
        files = list(tmp_path.glob("vapt_report_*.md"))
        assert len(files) == 1
        return files[0].read_text(encoding="utf-8")

    def test_file_created(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.generate_file_report()
        assert len(list(tmp_path.glob("*.md"))) == 1

    def test_target_in_report(self, tmp_path):
        content = self._run(tmp_path)
        assert "example.com" in content

    def test_score_section_present(self, tmp_path):
        content = self._run(tmp_path)
        assert "Security Score" in content

    def test_executive_summary_table(self, tmp_path):
        content = self._run(tmp_path)
        assert "Executive Summary" in content
        assert "CRITICAL" in content
        assert "HIGH" in content

    def test_findings_section_appears(self, tmp_path):
        findings = [
            {"name": "Missing HSTS", "severity": "HIGH",
             "description": "HSTS missing", "score_penalty": 15}
        ]
        content = self._run(tmp_path, findings)
        assert "Detailed Findings" in content
        assert "Missing HSTS" in content

    def test_header_scanner_section_rendered(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.add_result("HeaderScanner", {
            "missing": ["X-Frame-Options"],
            "present": {"Referrer-Policy": "no-referrer"},
            "findings": [],
            "valid": True,
        })
        r.generate_file_report()
        content = list(tmp_path.glob("*.md"))[0].read_text()
        assert "Header Analysis" in content
        assert "X-Frame-Options" in content

    def test_port_scanner_section_rendered(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.add_result("PortScanner", {
            "open_ports": [{"port": 80, "state": "open", "name": "http"}],
            "findings": [],
            "valid": True,
        })
        r.generate_file_report()
        content = list(tmp_path.glob("*.md"))[0].read_text()
        assert "Port Scan Results" in content

    def test_filename_sanitises_http_prefix(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.set_target("http://example.com/path")
        r.generate_file_report()
        files = list(tmp_path.glob("*.md"))
        assert "http" not in files[0].name

    def test_filename_sanitises_colon_and_slash(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.set_target("https://example.com:8443/app")
        r.generate_file_report()
        files = list(tmp_path.glob("*.md"))
        assert "/" not in files[0].name
        assert ":" not in files[0].name


# ===========================================================================
# generate_html_report
# ===========================================================================

class TestGenerateHtmlReport:
    def test_html_file_created_when_jinja2_available(self, tmp_path):
        r = _make_reporter(tmp_path)
        # Provide a minimal real template directory
        template_dir = os.path.join(
            os.path.dirname(__file__), '..', 'src', 'templates'
        )
        if not os.path.exists(template_dir):
            pytest.skip("Template directory not available")
        r.generate_html_report()
        html_files = list(tmp_path.glob("*.html"))
        assert len(html_files) == 1

    def test_html_report_contains_target(self, tmp_path):
        r = _make_reporter(tmp_path)
        template_dir = os.path.join(
            os.path.dirname(__file__), '..', 'src', 'templates'
        )
        if not os.path.exists(template_dir):
            pytest.skip("Template directory not available")
        r.generate_html_report()
        content = list(tmp_path.glob("*.html"))[0].read_text()
        assert "example.com" in content

    def test_import_error_does_not_raise(self, tmp_path):
        """If jinja2 is absent the method should print and return gracefully."""
        r = _make_reporter(tmp_path)
        with patch.dict("sys.modules", {"jinja2": None}):
            # Should not raise
            try:
                r.generate_html_report()
            except Exception:
                pytest.fail("generate_html_report raised when jinja2 unavailable")


# ===========================================================================
# generate_cli_report (smoke tests - output goes to console)
# ===========================================================================

class TestGenerateCliReport:
    def test_runs_without_raising_no_findings(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.generate_cli_report()  # should not raise

    def test_runs_without_raising_with_findings(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.findings = [
            _finding("CRITICAL", 25),
            _finding("HIGH", 15),
            _finding("LOW", 5),
        ]
        r.generate_cli_report()

    def test_score_updated_before_cli_report(self, tmp_path):
        r = _make_reporter(tmp_path)
        r.findings = [_finding("HIGH", 15)]
        r.generate_cli_report()
        assert r.score == 85