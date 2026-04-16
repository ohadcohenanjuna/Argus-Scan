"""
Parallel worker job status: works in real TTYs and in non-TTY pipes (Docker logs, IDE terminals).

Rich ``Live`` updates in place on real TTYs. We only push a new renderable when job status
*changes*, so broken or limited terminals do not get a flood of duplicate tables.

When stdout is not a terminal, we **do not** re-print on a timer (that spammed logs every
second). We print once at start, again only when a job transitions (running → done, etc.),
and a final snapshot at exit.

Optional ``stop_event`` cooperates with SIGINT: the monitor loop exits without waiting for all
futures so the main thread can exit quickly; use a second Ctrl+C to ``os._exit`` from vapt.

Env:
- ``ARGUS_PARALLEL_ALT_SCREEN=1``: use Rich alternate screen for the live table (fewer
  stuck-line issues in some IDE terminals; hides scrollback while the table is up).
"""
from __future__ import annotations

import os
import sys
import threading
import time
from concurrent.futures import Future

from rich.console import Console
from rich.live import Live
from rich.table import Table


def monitor_parallel_jobs(
    console: Console,
    jobs: list[tuple[str, Future]],
    *,
    refresh_hz: float = 4.0,
    poll_interval: float = 0.2,
    stop_event: threading.Event | None = None,
) -> bool:
    """
    Block until all futures complete **or** ``stop_event`` is set.

    Returns True if all jobs finished normally, False if ``stop_event`` requested stop
    (callers should not block on ``.result()`` for unfinished futures).
    """
    if not jobs:
        return True

    def _interrupted() -> bool:
        return bool(stop_event and stop_event.is_set())

    def _per_job_state() -> tuple[tuple[str, str, str], ...]:
        """Stable tuple for change detection: (name, phase, err_or_empty)."""
        row: list[tuple[str, str, str]] = []
        for name, fut in jobs:
            if fut.cancelled():
                row.append((name, "cancelled", ""))
            elif not fut.done():
                row.append(
                    (name, "stopping" if _interrupted() else "running", "")
                )
            else:
                try:
                    fut.result()
                    row.append((name, "ok", ""))
                except Exception as e:
                    row.append((name, "fail", str(e)[:200]))
        return tuple(row)

    def _table() -> Table:
        t = Table(title=f"Parallel jobs ({len(jobs)})", show_header=True, header_style="bold")
        t.add_column("Job", style="cyan", no_wrap=True)
        t.add_column("Status")

        for name, fut in jobs:
            if fut.cancelled():
                status = "[dim]cancelled[/dim]"
            elif not fut.done():
                if _interrupted():
                    status = "[magenta]stopping[/magenta]"
                else:
                    status = "[yellow]running[/yellow]"
            else:
                try:
                    fut.result()
                    status = "[green]completed[/green]"
                except Exception as e:
                    err = str(e)[:120].replace("[", "\\[")
                    status = f"[red]failed[/red]: {err}"
            t.add_row(name, status)

        return t

    def _work_left() -> bool:
        return any(not f.done() for _, f in jobs)

    use_alt_screen = (
        console.is_terminal
        and os.environ.get("ARGUS_PARALLEL_ALT_SCREEN", "").strip() == "1"
    )

    # Docker / CI / piped stdout: no in-place refresh — print only when status changes.
    if not console.is_terminal:
        last_key = _per_job_state()
        console.print(_table())
        try:
            sys.stdout.flush()
        except Exception:
            pass
        while _work_left() and not _interrupted():
            time.sleep(poll_interval)
            key = _per_job_state()
            if key != last_key:
                last_key = key
                console.print(_table())
                try:
                    sys.stdout.flush()
                except Exception:
                    pass
        key = _per_job_state()
        if key != last_key:
            console.print(_table())
            try:
                sys.stdout.flush()
            except Exception:
                pass
        return not _interrupted()

    # Real terminal: Live refresh in place; update only when something changes.
    last_key = _per_job_state()
    with Live(
        _table(),
        console=console,
        screen=use_alt_screen,
        refresh_per_second=max(refresh_hz, 1.0),
        transient=False,
    ) as live:
        while _work_left() and not _interrupted():
            key = _per_job_state()
            if key != last_key:
                last_key = key
                live.update(_table())
            time.sleep(poll_interval)
        key = _per_job_state()
        if key != last_key:
            live.update(_table())
    return not _interrupted()
