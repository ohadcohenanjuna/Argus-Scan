"""
tests/conftest.py
=================
Shared pytest fixtures for Argus-Scan tests.
"""

import os
import sys
import pytest

# Ensure src/ is importable from any working directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


# ---------------------------------------------------------------------------
# Generic fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_finding():
    """A pre-built finding dict that has already been through fify()."""
    return {
        "name": "Test Finding",
        "severity": "HIGH",
        "description": "Something is wrong.",
        "current": "Port 23 is OPEN",
        "recommendation": "Close it.",
        "score_penalty": 15,
    }


@pytest.fixture
def all_security_headers():
    return {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }


@pytest.fixture
def mock_port_result():
    return {
        "valid": True,
        "open_ports": [
            {"port": 80, "state": "open", "name": "http", "severity": "INFO"},
        ],
        "findings": [],
    }


@pytest.fixture
def mock_header_result(all_security_headers):
    return {
        "valid": True,
        "missing": [],
        "present": all_security_headers,
        "findings": [],
    }


@pytest.fixture
def mock_ssl_result():
    return {
        "valid": True,
        "issuer": "Let's Encrypt",
        "expiry": "Jan 01 00:00:00 2030 GMT",
        "findings": [],
    }