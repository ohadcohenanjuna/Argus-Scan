"""
Run Nuclei with JSONL output and parse findings for Argus.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from typing import Any, Optional

from nuclei_parse import format_nuclei_jsonl_preview, parse_nuclei_jsonl_file


def _slug_from_target(target: str) -> str:
    s = target.replace("http://", "").replace("https://", "")
    s = re.sub(r"[^\w.\-]+", "_", s)
    return s[:120] or "target"


def run_nuclei_scan(
    target: str,
    nuclei_secret_file: Optional[str],
    verbose: bool,
    url_list_file: Optional[str],
    output_dir: str,
    report_ts: str,
    log_file: Optional[str] = None,
) -> dict[str, Any]:
    """
    Run nuclei; write JSONL to output_dir. If url_list_file is set, use `-list` (and ignore single -u).
    Otherwise use `-u target`.
    """
    target_url = target
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    slug = _slug_from_target(target)
    jsonl_path = os.path.join(output_dir, f"nuclei_raw_{slug}_{report_ts}.jsonl")

    # JSONL export file (see `nuclei -h`: -jle / --jsonl-export).
    # Omit -silent when writing a log file or when verbose: otherwise Nuclei prints almost nothing
    # to stdout and nuclei.log stays empty (findings still land in the JSONL from -jle).
    parts: list[str] = ["nuclei"]
    if not verbose and not log_file:
        parts.append("-silent")
    parts.extend(["-nc", "-jle", jsonl_path])
    if url_list_file:
        parts.extend(["-list", url_list_file])
    else:
        parts.extend(["-u", target_url])

    if nuclei_secret_file:
        parts.extend(["-secret-file", nuclei_secret_file])

    cmd = " ".join(shlex.quote(p) for p in parts)

    log_fp = None
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)) or ".", exist_ok=True)
        log_fp = open(log_file, "w", encoding="utf-8", errors="replace")
        log_fp.write(f"command: {cmd}\n---\n")
        log_fp.flush()
    elif verbose:
        print(f"  [Tool] Running: {cmd}")

    output_lines: list[str] = []
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in process.stdout or []:
            line_clean = line.strip()
            if line_clean:
                line_no_ansi = ansi_escape.sub("", line_clean)
                if log_fp:
                    log_fp.write(line_no_ansi + "\n")
                    log_fp.flush()
                elif verbose:
                    print(f"  [Tool] {line_no_ansi}")
                output_lines.append(line_no_ansi)
        process.wait()
        rc = process.returncode
        if log_fp:
            log_fp.write(f"---\nexit code: {rc}\n")
            log_fp.flush()
            log_fp.close()
            log_fp = None
    except Exception as e:
        if log_fp:
            try:
                log_fp.write(f"nuclei execution error: {e}\n")
            finally:
                log_fp.close()
        return {
            "output": f"nuclei execution error: {e}",
            "error_output": str(e),
            "return_code": -1,
            "findings": [],
            "valid": False,
            "jsonl_path": jsonl_path,
        }

    full_output = "\n".join(output_lines)
    if not full_output.strip():
        full_output = format_nuclei_jsonl_preview(jsonl_path, max_lines=500)

    raw_findings = parse_nuclei_jsonl_file(jsonl_path)
    return {
        "output": full_output,
        "error_output": "",
        "return_code": rc,
        "findings": raw_findings,
        "valid": True,
        "jsonl_path": jsonl_path,
    }
