"""
Parse Nuclei JSONL output into Argus finding dicts (compatible with scanners.Severity scoring).
"""
from __future__ import annotations

import json
import os
from typing import Any

# Align with scanners.Severity.value for score_penalty (avoid importing scanners/nmap in lightweight parsers).
_SEV = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}


def _map_nuclei_severity(raw: str | None) -> str:
    if not raw:
        return "INFO"
    s = str(raw).strip().lower()
    mapping = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
        "informational": "INFO",
        "unknown": "INFO",
    }
    return mapping.get(s, "INFO")


def _finding_from_row(row: dict[str, Any]) -> dict[str, Any] | None:
    info = row.get("info")
    if not isinstance(info, dict):
        info = {}
    template_id = row.get("template-id") or row.get("template_id") or "nuclei"
    name_hint = info.get("name") or template_id
    sev_name = _map_nuclei_severity(info.get("severity"))
    matched = row.get("matched-at") or row.get("matched_at") or row.get("host") or ""
    desc_parts = [
        info.get("description") or f"Nuclei template matched: {template_id}.",
    ]
    if matched:
        desc_parts.append(f"Matched at: {matched}")
    tags = info.get("tags")
    if tags:
        desc_parts.append(f"Tags: {tags}")
    description = " ".join(desc_parts)
    return {
        "name": f"Nuclei: {name_hint}",
        "severity": sev_name,
        "description": description,
        "current": str(matched) if matched else "See Nuclei JSONL output.",
        "recommendation": "Review the finding in context; validate false positives; apply vendor fixes or configuration hardening.",
        "score_penalty": _SEV.get(sev_name, 0),
        "source": "nuclei",
        "template_id": template_id,
    }


def parse_nuclei_jsonl_file(path: str) -> list[dict[str, Any]]:
    """Read Nuclei `-jsonl -o` file; return list of finding dicts with string severity for reporter."""
    if not path or not os.path.isfile(path):
        return []
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            fin = _finding_from_row(row)
            if fin:
                out.append(fin.copy())
    return out


def format_nuclei_jsonl_preview(path: str, max_lines: int = 500) -> str:
    """Human-readable preview for raw report sections (truncated)."""
    if not path or not os.path.isfile(path):
        return "(no Nuclei JSONL file)"
    lines: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                lines.append(f"... truncated after {max_lines} lines ...")
                break
            lines.append(line.rstrip())
    return "\n".join(lines) if lines else "(empty JSONL)"
