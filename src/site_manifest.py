"""
Load site scan YAML manifests and produce a flat URL list for Nuclei `-list`.
"""
from __future__ import annotations

import os
from typing import Any
from urllib.parse import urljoin, urlparse

import yaml


class SiteManifestError(ValueError):
    pass


def _normalize_base(url: str) -> str:
    url = url.strip()
    if not url:
        raise SiteManifestError("base_url is empty")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not url.endswith("/"):
        url = url + "/"
    return url


def load_site_manifest(
    path: str, fallback_base: str | None = None
) -> tuple[list[str], list[dict[str, Any]]]:
    """
    Returns (absolute_urls, metadata_rows for reporting).
    Each metadata row: url, category, note, requires_auth.
    """
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise SiteManifestError("manifest root must be a mapping")

    base = data.get("base_url") or data.get("base") or fallback_base
    if not base:
        raise SiteManifestError("Set base_url in the manifest or pass a --target URL")
    base = _normalize_base(str(base))

    entries = data.get("urls") or data.get("targets") or []
    if not isinstance(entries, list):
        raise SiteManifestError("'urls' must be a list")

    urls: list[str] = []
    meta: list[dict[str, Any]] = []

    for i, entry in enumerate(entries):
        if isinstance(entry, str):
            path_or_url = entry
            category = "other"
            note = ""
            requires_auth = False
        elif isinstance(entry, dict):
            path_or_url = entry.get("url") or entry.get("path") or entry.get("href")
            if not path_or_url:
                raise SiteManifestError(f"urls[{i}]: missing url or path")
            category = entry.get("category") or "other"
            note = entry.get("note") or ""
            requires_auth = bool(entry.get("requires_auth", False))
        else:
            raise SiteManifestError(f"urls[{i}]: must be string or mapping")

        path_or_url = str(path_or_url).strip()
        if path_or_url.startswith(("http://", "https://")):
            abs_url = path_or_url
        else:
            if not path_or_url.startswith("/"):
                path_or_url = "/" + path_or_url
            abs_url = urljoin(base, path_or_url.lstrip("/"))

        urls.append(abs_url)
        meta.append(
            {
                "url": abs_url,
                "category": category,
                "note": note,
                "requires_auth": requires_auth,
            }
        )

    # de-dupe preserving order
    seen: set[str] = set()
    deduped_urls: list[str] = []
    deduped_meta: list[dict[str, Any]] = []
    for u, m in zip(urls, meta):
        if u not in seen:
            seen.add(u)
            deduped_urls.append(u)
            deduped_meta.append(m)

    return deduped_urls, deduped_meta


def write_url_list_file(urls: list[str], dest_path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(dest_path)) or ".", exist_ok=True)
    with open(dest_path, "w", encoding="utf-8") as f:
        for u in urls:
            f.write(u + "\n")
    return dest_path


def merge_primary_target(urls: list[str], primary: str) -> list[str]:
    """Ensure --target URL appears in the list (first position) if missing."""
    primary = primary.strip()
    if not primary.startswith(("http://", "https://")):
        primary = "https://" + primary
    if primary in urls:
        return urls
    return [primary] + urls
