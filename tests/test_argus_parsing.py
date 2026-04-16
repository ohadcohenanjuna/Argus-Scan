"""Unit tests for Nuclei JSONL parsing, site manifest, and ZAP JSON aggregation."""
import json
import os
import sys
import tempfile
import unittest

# Repo root on path for `src` imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nuclei_parse import parse_nuclei_jsonl_file  # noqa: E402
from site_manifest import load_site_manifest, merge_primary_target, write_url_list_file  # noqa: E402
from zap_parse import parse_zap_traditional_json  # noqa: E402


class TestNucleiParse(unittest.TestCase):
    def test_parse_line(self):
        row = {
            "template-id": "test-template",
            "info": {
                "name": "Sample Finding",
                "severity": "high",
                "description": "Desc here",
            },
            "matched-at": "https://example.com/x",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(row) + "\n")
            path = f.name
        try:
            findings = parse_nuclei_jsonl_file(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "HIGH")
            self.assertIn("Nuclei:", findings[0]["name"])
        finally:
            os.unlink(path)


class TestSiteManifest(unittest.TestCase):
    def test_load_and_merge(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(
                """
base_url: https://ex.com/
urls:
  - /a
  - url: https://other.com/z
    category: api
"""
            )
            path = f.name
        try:
            urls, meta = load_site_manifest(path)
            self.assertIn("https://ex.com/a", urls)
            self.assertIn("https://other.com/z", urls)
            merged = merge_primary_target(urls, "https://ex.com/")
            self.assertEqual(merged[0], "https://ex.com/")
        finally:
            os.unlink(path)


class TestZapParse(unittest.TestCase):
    def test_minimal_json(self):
        doc = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Missing Header",
                            "riskcode": "1",
                            "riskdesc": "Low",
                            "desc": "Test",
                            "solution": "Add header",
                            "instances": [{"uri": "https://ex.com/"}],
                        }
                    ]
                }
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(doc, f)
            path = f.name
        try:
            findings = parse_zap_traditional_json(path)
            self.assertGreaterEqual(len(findings), 1)
            self.assertTrue(any("ZAP:" in x["name"] for x in findings))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
