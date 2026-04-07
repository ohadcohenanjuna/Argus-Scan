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
from urllib.parse import parse_qs, urlparse

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


_LOGIN_PATH_MARKERS = frozenset(
    ("login", "signin", "sign-in", "sign_in", "oauth", "authorize", "sso", "logout")
)


def _path_suggests_login_page(path: str) -> bool:
    parts = [p.lower() for p in path.split("/") if p]
    for seg in parts:
        if seg in _LOGIN_PATH_MARKERS:
            return True
        if seg.startswith("login") or seg.endswith("login"):
            return True
    return False


def _query_suggests_login_return(query: str) -> bool:
    if not query:
        return False
    q = query.lower()
    return any(
        x in q
        for x in (
            "return_to=",
            "returnurl=",
            "return_url=",
            "redirect_uri=",
            "relaystate=",
            "next=",
        )
    )


def _final_url_suggests_login_or_sso(final_url: str, app_hostname: str) -> bool:
    """
    True if the URL after redirects looks like a login/SSO page rather than in-app content.

    Many apps redirect anonymous users to /login (200) or to an IdP on another host—
    urllib follows those redirects, so status codes alone stay 200.
    """
    p = urlparse(final_url)
    host = (p.hostname or "").lower()
    if host and host != app_hostname.lower():
        return True
    if _path_suggests_login_page(p.path or ""):
        return True
    if _query_suggests_login_return(p.query):
        return True
    # OIDC/OAuth often exposes these query keys even on first party
    qs = parse_qs(p.query)
    if any(k.lower() in ("client_id", "response_type", "scope") for k in qs):
        if "openid" in (qs.get("scope", [""])[0] or "").lower():
            return True
    return False


def _cookie_header(cookies: list[dict]) -> str:
    parts: list[str] = []
    for c in cookies:
        name = c.get("name")
        value = c.get("value")
        if name is None or value is None:
            continue
        parts.append(f"{name}={value}")
    return "; ".join(parts)


def validate_cookies_http(url: str, cookies: list[dict], timeout: float = 30.0) -> tuple[bool, str]:
    """
    GET the URL twice from Python (not Chrome): first with no Cookie header, then with cookies.

    urllib's default opener does not use HTTPCookieProcessor, so Set-Cookie from the first
    response cannot be replayed on the second request—the anonymous call is truly cookieless.

    Redirects are followed (HTTPRedirectHandler). Apps that send anonymous users to /login or to
    an IdP with 302 then 200 are detected by comparing final URLs after redirects, not only status codes.

    Returns (ok, message). ok is False if the authenticated request returns 401/403.
    Many apps return 200 for both logged-in and public pages; in that case we warn but still pass.
    """
    cookie_header = _cookie_header(cookies)
    if not cookie_header:
        return False, "No cookie name=value pairs to validate."

    app_host = urlparse(url).hostname or ""
    if not app_host:
        return False, "Validation URL must include a hostname."

    ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    # Explicit opener: no HTTPCookieProcessor (defense in depth vs future urllib defaults).
    opener = urllib.request.build_opener(
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPRedirectHandler(),
        urllib.request.HTTPErrorProcessor(),
    )

    def fetch(with_cookies: bool) -> tuple[int | None, str, str | None]:
        headers = {"User-Agent": ua}
        if with_cookies:
            headers["Cookie"] = cookie_header
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.getcode(), resp.geturl(), None
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location") if e.headers else None
            return e.code, loc or url, None
        except urllib.error.URLError as e:
            return None, url, str(e.reason)

    # Anonymous first so no prior request could have influenced cookie state (there is no jar).
    code_anon, final_anon, err_anon = fetch(False)
    code_auth, final_auth, err_auth = fetch(True)

    if err_auth is not None:
        return False, f"{url}: GET with cookies failed: {err_auth}"
    assert code_auth is not None

    if code_auth in (401, 403):
        return False, (
            f"{url}: GET returned HTTP {code_auth} when sending captured cookies. "
            "Session may be invalid or cookies may not apply to this host/path."
        )

    if _final_url_suggests_login_or_sso(final_auth, app_host):
        return False, (
            f"{url}: with cookies, redirects ended at what looks like login/SSO ({final_auth}) — "
            "session may be invalid or expired."
        )

    if err_anon is not None:
        return True, (
            f"{url}: HTTP {code_auth} with cookies (anonymous GET had no usable response: {err_anon})."
        )
    assert code_anon is not None

    if code_anon in (401, 403) and code_auth not in (401, 403):
        return True, (
            f"{url}: HTTP {code_auth} with cookies vs HTTP {code_anon} without — session looks authenticated."
        )

    anon_blocked = _final_url_suggests_login_or_sso(final_anon, app_host)

    if anon_blocked:
        return True, (
            f"{url}: anonymous request followed redirects to login/SSO ({final_anon}); "
            f"with cookies reached app content ({final_auth}) — session looks authenticated."
        )

    if code_anon == code_auth == 200:
        return True, (
            f"{url}: HTTP 200 after redirects for both; final URLs did not clearly differ "
            f"(anonymous: {final_anon}). If this site uses login redirects, try --validate-url "
            "on a path that sends anonymous users to /login or an IdP."
        )

    return True, (
        f"{url}: HTTP {code_auth} with cookies (anonymous: {code_anon}; final URL: {final_auth})."
    )


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
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip HTTP GET sanity-check after writing the secret file",
    )
    parser.add_argument(
        "--validate-url",
        default=None,
        metavar="URL",
        help=(
            "URL used only for the HTTP validation GETs (default: same as --url). "
            "Set this to a protected path or API that returns 401/403 without a session "
            "when the public landing page always returns 200."
        ),
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

    if not args.no_validate:
        validate_url = args.validate_url or args.url
        if args.validate_url:
            vparsed = urlparse(args.validate_url)
            if not vparsed.scheme or not vparsed.hostname:
                print(
                    "--validate-url must include scheme and host, e.g. https://app.example/api/me",
                    file=sys.stderr,
                )
                sys.exit(1)
            if args.validate_url != args.url:
                print(f"Validation uses --validate-url: {validate_url}")

        ok, vmsg = validate_cookies_http(validate_url, cookies)
        print(f"Validation: {vmsg}")
        if not ok:
            print(
                "Secret file was still written; fix the session or use --no-validate to skip this check.",
                file=sys.stderr,
            )
            sys.exit(3)


if __name__ == "__main__":
    main()
