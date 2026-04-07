#!/usr/bin/env python3
"""
Connect to Chrome DevTools (remote debugging) and export cookies for a URL
into a Nuclei v3.2+ Secret File (cookie static auth).

Requires: websocket-client, pyyaml (see requirements.txt)
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

try:
    import websocket
except ImportError:
    print(
        "Missing dependency: websocket-client. Install with:\n"
        "  pip install websocket-client pyyaml",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import yaml
except ImportError:
    print(
        "Missing dependency: pyyaml. Install with:\n"
        "  pip install pyyaml",
        file=sys.stderr,
    )
    sys.exit(1)


def _cdp_call(ws: websocket.WebSocket, method: str, params: dict, msg_id: int) -> dict:
    ws.send(json.dumps({"id": msg_id, "method": method, "params": params}))
    while True:
        raw = ws.recv()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        msg = json.loads(raw)
        if msg.get("id") == msg_id:
            if "error" in msg:
                raise RuntimeError(msg["error"])
            return msg.get("result", {})


def _page_websocket_url(debug_port: int, page_url: str) -> str:
    """
    Browser-level WS from /json/version does not expose Network.* — use a page tab's WS from /json/list.
    """
    list_url = f"http://127.0.0.1:{debug_port}/json/list"
    try:
        with urllib.request.urlopen(list_url, timeout=5) as resp:
            targets = json.load(resp)
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Could not reach Chrome DevTools at {list_url}. "
            f"Is Chrome running with --remote-debugging-port={debug_port}? ({e})"
        ) from e

    prefer_host = urlparse(page_url).hostname or ""
    pages = [
        t
        for t in targets
        if t.get("type") == "page" and t.get("webSocketDebuggerUrl")
    ]
    if not pages:
        raise RuntimeError(
            "No page targets in /json/list. Keep at least one tab open in the Chrome window and try again."
        )

    for t in pages:
        tab_url = t.get("url") or ""
        if prefer_host and urlparse(tab_url).hostname == prefer_host:
            return t["webSocketDebuggerUrl"]

    for t in pages:
        tab_url = t.get("url") or ""
        if tab_url.startswith("http://") or tab_url.startswith("https://"):
            return t["webSocketDebuggerUrl"]

    return pages[0]["webSocketDebuggerUrl"]


def fetch_cookies_via_cdp(debug_port: int, page_url: str) -> list[dict]:
    ws_url = _page_websocket_url(debug_port, page_url)

    ws = websocket.create_connection(ws_url, timeout=10)
    try:
        _cdp_call(ws, "Network.enable", {}, 1)
        result = _cdp_call(ws, "Network.getCookies", {"urls": [page_url]}, 2)
        return result.get("cookies", [])
    finally:
        ws.close()


def build_secret_yaml(hostname: str, cookies: list[dict]) -> str:
    cookie_entries = []
    for c in cookies:
        name = c.get("name")
        value = c.get("value")
        if not name or value is None:
            continue
        cookie_entries.append({"key": name, "value": value})

    doc = {
        "static": [
            {
                "type": "cookie",
                "domains": [hostname],
                "cookies": cookie_entries,
            }
        ]
    }
    return yaml.safe_dump(
        doc,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export Chrome cookies (CDP) to a Nuclei Secret File YAML"
    )
    parser.add_argument(
        "--port",
        type=int,
        required=True,
        help="Chrome --remote-debugging-port",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Page URL used for Network.getCookies (e.g. https://app.example/dashboard)",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output YAML path (Nuclei --secret-file)",
    )
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.hostname:
        print("URL must include scheme and host, e.g. https://docs.example.com/", file=sys.stderr)
        sys.exit(1)

    hostname = parsed.hostname
    cookies = fetch_cookies_via_cdp(args.port, args.url)
    if not cookies:
        print(
            "No cookies returned for this URL. Log in in Chrome, stay on a page "
            "under the same site, then try again.",
            file=sys.stderr,
        )
        sys.exit(2)

    text = build_secret_yaml(hostname, cookies)
    out_path = args.output
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        import os

        os.chmod(out_path, 0o600)
    except OSError:
        pass
    print(f"Wrote {out_path} ({len(cookies)} cookie(s) from CDP for host {hostname}).")


if __name__ == "__main__":
    main()
