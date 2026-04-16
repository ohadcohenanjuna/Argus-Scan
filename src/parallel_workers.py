"""
Top-level functions for ProcessPoolExecutor workers (must be picklable).
Each worker runs in its own process (separate PID on Linux).
"""
from __future__ import annotations

import os
from typing import Any, Optional

from scanners import HeaderScanner, PortScanner, SSLScanner, ToolScanner
from nuclei_runner import run_nuclei_scan


def _ensure_parent(path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)


def run_port(target: str, log_path: Optional[str]) -> dict[str, Any]:
    r = PortScanner(target).run()
    if log_path:
        _ensure_parent(log_path)
        with open(log_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"# PortScanner (nmap)\n# target={target}\n\n")
            f.write(f"valid={r.get('valid')}\n")
            if r.get("error"):
                f.write(f"error: {r['error']}\n")
            for op in r.get("open_ports") or []:
                f.write(f"port={op.get('port')} state={op.get('state')} name={op.get('name')}\n")
    return r


def run_header(target: str, verify_ssl: bool, log_path: Optional[str]) -> dict[str, Any]:
    r = HeaderScanner(target, verify_ssl=verify_ssl).run()
    if log_path:
        _ensure_parent(log_path)
        with open(log_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"# HeaderScanner\n# target={target}\n\n")
            f.write(f"valid={r.get('valid')}\n")
            if r.get("error"):
                f.write(f"error: {r['error']}\n")
            f.write(f"missing: {r.get('missing')}\n")
    return r


def run_ssl(target: str, log_path: Optional[str]) -> dict[str, Any]:
    r = SSLScanner(target).run()
    if log_path:
        _ensure_parent(log_path)
        with open(log_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"# SSLScanner\n# target={target}\n\n")
            f.write(f"valid={r.get('valid')}\n")
            if r.get("error"):
                f.write(f"error: {r['error']}\n")
            if r.get("issuer"):
                f.write(f"issuer: {r['issuer']}\n")
            if r.get("expiry"):
                f.write(f"expiry: {r['expiry']}\n")
    return r


def run_nikto(
    target: str,
    verbose: bool,
    log_path: Optional[str],
    cgi_all: bool = False,
) -> dict[str, Any]:
    cmd = "nikto -h {target} -Tuning 123b"
    if cgi_all:
        cmd += " -C all"
    # When logging to file, do not duplicate lines to stdout (verbose only if no log)
    v = verbose and not log_path
    return ToolScanner(target, "nikto", cmd, verbose=v, log_file=log_path).run()


def run_nuclei(
    target: str,
    nuclei_secret_file: Optional[str],
    verbose: bool,
    url_list_file: Optional[str],
    output_dir: str,
    report_ts: str,
    log_file: Optional[str] = None,
) -> dict[str, Any]:
    v = verbose and not log_file
    return run_nuclei_scan(
        target,
        nuclei_secret_file,
        v,
        url_list_file,
        output_dir,
        report_ts,
        log_file=log_file,
    )
