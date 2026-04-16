"""
Parse OWASP ZAP traditional JSON report (e.g. from zap-baseline.py -J) into Argus findings.
"""
from __future__ import annotations

import json
import os
from typing import Any

# Align with scanners.Severity.value (avoid importing scanners in this module).
_SEV = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 10, "LOW": 5, "INFO": 0}


def _riskcode_to_severity_name(code: str | int | None) -> str:
    try:
        c = int(code)
    except (TypeError, ValueError):
        return "INFO"
    # ZAP: 0=Informational, 1=Low, 2=Medium, 3=High
    if c >= 3:
        return "HIGH"
    if c == 2:
        return "MEDIUM"
    if c == 1:
        return "LOW"
    return "INFO"


def parse_zap_traditional_json(path: str) -> list[dict[str, Any]]:
    """
    Aggregate alerts by (name, riskcode) to avoid hundreds of duplicate rows.
    """
    if not path or not os.path.isfile(path):
        return []

    with open(path, encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    sites = data.get("site")
    if sites is None and isinstance(data, list) and data:
        sites = data[0].get("site") if isinstance(data[0], dict) else None
    if sites is None:
        return []

    if not isinstance(sites, list):
        sites = [sites]

    # (alert name, riskcode) -> count, example url, riskdesc
    agg: dict[tuple[str, str], dict[str, Any]] = {}
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts") or []
        if not isinstance(alerts, list):
            continue
        for al in alerts:
            if not isinstance(al, dict):
                continue
            name = al.get("alert") or al.get("name") or "ZAP alert"
            rc = str(al.get("riskcode", "0"))
            key = (name, rc)
            if key not in agg:
                agg[key] = {
                    "count": 0,
                    "riskdesc": al.get("riskdesc") or "",
                    "desc": al.get("desc") or al.get("description") or "",
                    "solution": al.get("solution") or "",
                    "instances": [],
                }
            inst = al.get("instances") or al.get("instance")
            if isinstance(inst, list):
                agg[key]["count"] += len(inst) if inst else 1
                for it in inst:
                    if isinstance(it, dict) and it.get("uri") and len(agg[key]["instances"]) < 8:
                        agg[key]["instances"].append(str(it["uri"]))
            elif isinstance(inst, dict):
                agg[key]["count"] += 1
                uri = inst.get("uri")
                if uri and len(agg[key]["instances"]) < 8:
                    agg[key]["instances"].append(str(uri))
            else:
                agg[key]["count"] += 1

    findings: list[dict[str, Any]] = []
    for (name, rc), info in sorted(agg.items(), key=lambda x: (-int(x[0][1] or 0), x[0][0])):
        sev_name = _riskcode_to_severity_name(rc)
        n = info["count"]
        parts = [
            f"ZAP reported {n} affected location(s).",
            info.get("riskdesc") or "",
        ]
        if info.get("desc"):
            parts.append(str(info["desc"])[:800])
        if info["instances"]:
            parts.append("Example URIs: " + ", ".join(info["instances"][:3]))
        description = " ".join(p for p in parts if p).strip()
        rec = info.get("solution") or "Review ZAP HTML report and remediate per OWASP guidance."
        fin = {
            "name": f"ZAP: {name}",
            "severity": sev_name,
            "description": description,
            "current": f"{n} instance(s) (risk code {rc})",
            "recommendation": str(rec)[:2000],
            "score_penalty": _SEV.get(sev_name, 0),
            "source": "zap",
        }
        findings.append(fin)

    return findings
