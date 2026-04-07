"""
Top-level functions for ProcessPoolExecutor workers (must be picklable).
Each worker runs in its own process (separate PID on Linux).
"""
from __future__ import annotations

import shlex
from typing import Any, Optional

from scanners import HeaderScanner, PortScanner, SSLScanner, ToolScanner


def run_port(target: str) -> dict[str, Any]:
    return PortScanner(target).run()


def run_header(target: str, verify_ssl: bool) -> dict[str, Any]:
    return HeaderScanner(target, verify_ssl=verify_ssl).run()


def run_ssl(target: str) -> dict[str, Any]:
    return SSLScanner(target).run()


def run_nikto(target: str, verbose: bool) -> dict[str, Any]:
    cmd = "nikto -h {target} -Tuning 123b"
    return ToolScanner(target, "nikto", cmd, verbose=verbose).run()


def run_nuclei(target: str, nuclei_secret_file: Optional[str], verbose: bool) -> dict[str, Any]:
    if nuclei_secret_file:
        safe_secret = shlex.quote(nuclei_secret_file)
        nuclei_cmd = f"nuclei -u {{target}} -silent -nc -secret-file {safe_secret}"
    else:
        nuclei_cmd = "nuclei -u {target} -silent -nc"
    return ToolScanner(target, "nuclei", nuclei_cmd, verbose=verbose).run()
