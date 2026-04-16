"""
tests/test_vapt.py
==================
Tests for src/vapt.py

Covers:
  - check_dependencies: all present, some missing, all missing
  - signal_handler: calls sys.exit(0)
  - main() integration: argument parsing, scanner wiring, report generation,
    --no-tool-check, --insecure, exit on missing tools with --full
"""

import signal

import pytest
from unittest.mock import MagicMock, patch

import vapt


# ===========================================================================
# check_dependencies
# ===========================================================================

class TestCheckDependencies:
    def test_all_tools_present_returns_empty_list(self):
        with patch("vapt.shutil.which", return_value="/usr/bin/tool"):
            missing = vapt.check_dependencies()
        assert missing == []

    def test_one_tool_missing(self):
        def which(tool):
            return None if tool == "nikto" else "/usr/bin/" + tool

        with patch("vapt.shutil.which", side_effect=which):
            missing = vapt.check_dependencies()
        assert missing == ["nikto"]

    def test_all_tools_missing(self):
        with patch("vapt.shutil.which", return_value=None):
            missing = vapt.check_dependencies()
        assert set(missing) == {"nmap", "nikto", "nuclei"}

    def test_returns_list_type(self):
        with patch("vapt.shutil.which", return_value="/usr/bin/tool"):
            result = vapt.check_dependencies()
        assert isinstance(result, list)


# ===========================================================================
# signal_handler
# ===========================================================================

class TestSignalHandler:
    def test_signal_handler_calls_sys_exit_0(self):
        with pytest.raises(SystemExit) as exc_info:
            vapt.signal_handler(signal.SIGINT, None)
        assert exc_info.value.code == 0


# ===========================================================================
# main() – argument wiring and scanner orchestration
# ===========================================================================

SAFE_SCAN_RESULT = {"valid": True, "findings": []}
PORT_RESULT      = {"valid": True, "open_ports": [], "findings": []}
HEADER_RESULT    = {"valid": True, "missing": [], "present": {}, "findings": []}
SSL_RESULT       = {"valid": True, "issuer": "Test CA", "expiry": "Jan 01 00:00:00 2030 GMT", "findings": []}


def _patch_main(argv, extra_patches=None):
    """
    Helper: run vapt.main() with argv substituted and all external I/O mocked.
    Returns the context managers so callers can inspect mocks if needed.
    """
    patches = {
        "vapt.PortScanner":   MagicMock(return_value=MagicMock(run=MagicMock(return_value=PORT_RESULT))),
        "vapt.HeaderScanner": MagicMock(return_value=MagicMock(run=MagicMock(return_value=HEADER_RESULT))),
        "vapt.SSLScanner":    MagicMock(return_value=MagicMock(run=MagicMock(return_value=SSL_RESULT))),
        "vapt.shutil.which":  MagicMock(return_value="/usr/bin/tool"),
    }
    if extra_patches:
        patches.update(extra_patches)

    ctx = {}
    for key, val in patches.items():
        ctx[key] = patch(key, val)

    return ctx


class TestMain:
    def _run(self, argv, extra=None, tmp_path=None):
        """Run main() with mocked scanners and a temp report directory."""
        base_argv = ["vapt.py"] + argv
        if tmp_path:
            base_argv += ["--output", str(tmp_path)]

        mock_port   = MagicMock(run=MagicMock(return_value=PORT_RESULT))
        mock_header = MagicMock(run=MagicMock(return_value=HEADER_RESULT))
        mock_ssl    = MagicMock(run=MagicMock(return_value=SSL_RESULT))

        mocks = {
            "PortScanner":   mock_port,
            "HeaderScanner": mock_header,
            "SSLScanner":    mock_ssl,
        }

        with patch("sys.argv", base_argv), \
             patch("vapt.PortScanner",   return_value=mock_port), \
             patch("vapt.HeaderScanner", return_value=mock_header), \
             patch("vapt.SSLScanner",    return_value=mock_ssl), \
             patch("vapt.shutil.which",  return_value="/usr/bin/tool"), \
             patch("reporter.Reporter.generate_html_report"), \
             patch("reporter.Reporter.generate_cli_report"), \
             patch("reporter.Reporter.generate_file_report"):
            vapt.main()

        return mocks

    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------
    def test_main_runs_three_core_scanners(self, tmp_path):
        mocks = self._run(["--target", "example.com", "--no-tool-check"], tmp_path=tmp_path)
        mocks["PortScanner"].run.assert_called_once()
        mocks["HeaderScanner"].run.assert_called_once()
        mocks["SSLScanner"].run.assert_called_once()

    def test_main_does_not_raise_on_valid_target(self, tmp_path):
        self._run(["--target", "http://example.com", "--no-tool-check"], tmp_path=tmp_path)

    # ------------------------------------------------------------------
    # --no-tool-check skips dependency check
    # ------------------------------------------------------------------
    def test_no_tool_check_skips_dependency_check(self, tmp_path):
        check_mock = MagicMock(return_value=["nmap"])

        with patch("sys.argv", ["vapt.py", "--target", "example.com", "--no-tool-check",
                                "--output", str(tmp_path)]), \
             patch("vapt.check_dependencies", check_mock), \
             patch("vapt.PortScanner",   return_value=MagicMock(run=MagicMock(return_value=PORT_RESULT))), \
             patch("vapt.HeaderScanner", return_value=MagicMock(run=MagicMock(return_value=HEADER_RESULT))), \
             patch("vapt.SSLScanner",    return_value=MagicMock(run=MagicMock(return_value=SSL_RESULT))), \
             patch("vapt.shutil.which",  return_value="/usr/bin/tool"), \
             patch("reporter.Reporter.generate_html_report"), \
             patch("reporter.Reporter.generate_cli_report"), \
             patch("reporter.Reporter.generate_file_report"):
            vapt.main()

        check_mock.assert_not_called()

    # ------------------------------------------------------------------
    # Missing tools + --full → sys.exit(1)
    # ------------------------------------------------------------------
    def test_full_flag_with_missing_tools_exits_1(self, tmp_path):
        with patch("sys.argv", ["vapt.py", "--target", "example.com",
                                "--full", "--output", str(tmp_path)]), \
             patch("vapt.check_dependencies", return_value=["nikto", "nuclei"]):
            with pytest.raises(SystemExit) as exc_info:
                vapt.main()
        assert exc_info.value.code == 1

    # ------------------------------------------------------------------
    # --insecure passes verify_ssl=False to HeaderScanner
    # ------------------------------------------------------------------
    def test_insecure_flag_disables_ssl_verification(self, tmp_path):
        captured = {}

        def fake_header_scanner(target, verify_ssl=True):
            captured["verify_ssl"] = verify_ssl
            m = MagicMock()
            m.run.return_value = HEADER_RESULT
            return m

        with patch("sys.argv", ["vapt.py", "--target", "example.com",
                                "--insecure", "--no-tool-check",
                                "--output", str(tmp_path)]), \
             patch("vapt.PortScanner",   return_value=MagicMock(run=MagicMock(return_value=PORT_RESULT))), \
             patch("vapt.HeaderScanner", side_effect=fake_header_scanner), \
             patch("vapt.SSLScanner",    return_value=MagicMock(run=MagicMock(return_value=SSL_RESULT))), \
             patch("vapt.shutil.which",  return_value="/usr/bin/tool"), \
             patch("reporter.Reporter.generate_html_report"), \
             patch("reporter.Reporter.generate_cli_report"), \
             patch("reporter.Reporter.generate_file_report"):
            vapt.main()

        assert captured.get("verify_ssl") is False

    # ------------------------------------------------------------------
    # --full runs Nikto and Nuclei scanners
    # ------------------------------------------------------------------
    def test_full_flag_runs_nikto_and_nuclei(self, tmp_path):
        tool_runs = []

        def fake_tool_scanner(target, tool_name, cmd, verbose=False):
            tool_runs.append(tool_name)
            m = MagicMock()
            m.run.return_value = {"valid": True, "output": "", "findings": []}
            return m

        with patch("sys.argv", ["vapt.py", "--target", "example.com",
                                "--full", "--no-tool-check",
                                "--output", str(tmp_path)]), \
             patch("vapt.PortScanner",   return_value=MagicMock(run=MagicMock(return_value=PORT_RESULT))), \
             patch("vapt.HeaderScanner", return_value=MagicMock(run=MagicMock(return_value=HEADER_RESULT))), \
             patch("vapt.SSLScanner",    return_value=MagicMock(run=MagicMock(return_value=SSL_RESULT))), \
             patch("vapt.ToolScanner",   side_effect=fake_tool_scanner), \
             patch("vapt.shutil.which",  return_value="/usr/bin/tool"), \
             patch("reporter.Reporter.generate_html_report"), \
             patch("reporter.Reporter.generate_cli_report"), \
             patch("reporter.Reporter.generate_file_report"):
            vapt.main()

        assert "nikto" in tool_runs
        assert "nuclei" in tool_runs

    # ------------------------------------------------------------------
    # Unexpected exception exits with code 1
    # ------------------------------------------------------------------
    def test_unexpected_exception_exits_1(self, tmp_path):
        with patch("sys.argv", ["vapt.py", "--target", "example.com",
                                "--no-tool-check", "--output", str(tmp_path)]), \
             patch("vapt.PortScanner", side_effect=RuntimeError("boom")):
            with pytest.raises(SystemExit) as exc_info:
                vapt.main()
        assert exc_info.value.code == 1