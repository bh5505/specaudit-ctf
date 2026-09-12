"""Stdlib-only Ivanti (RiskSense) REST client and data flattening.

Ports the durable core of the operator's Ivanti API extractor
(``api/ivantiAPI.py`` + ``api/ivanti_api_load.py``) to a hermetic stdlib
surface (``urllib``) so the sealed specaudit-ctf runtime can pull assets and
findings from the Ivanti VM platform without ``requests``/``pandas``/``duckdb``.

The upstream platform is the RiskSense/Neurons Ivanti VM API:
``{platform_url}/{api_ver}/client/{client_id}/{subject}/search`` with
``x-api-key`` auth. ``search`` returns pageable JSON; ``export`` creates a
server-side CSV (UI-identical field set) and downloads it after polling.

The two flatten helpers reproduce ``ivanti_api_load.flatten_record`` semantics
so an agent pulling via the arm can load the same shape the pack expects:
nested dict/list values become JSON strings, and finding rows lift
``host.hostId`` / ``host.ipAddress`` up to top-level ``host_id`` / ``host_ip``.
"""

from __future__ import annotations

import json
import math
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# RiskSense search rejects offsets past ~100k (page*size > 100000 -> HTTP 400),
# so callers that need more than this must split scope (see search_all).
PAGE_CAP = 99_000
# Ivanti per-page cap; 750 is the wrapper default.
DEFAULT_SIZE = 750

# Retried on the same statuses the upstream wrapper uses.
RETRY_STATUSES = frozenset({419, 429, 500, 502, 503, 504})


def _flatten_value(value: Any) -> Any:
    """JSON-encode nested dict/list values; coerce integral floats back to int
    and NaN/None stays JSON-valid (mirrors ``ivanti_api_load._clean``)."""
    if isinstance(value, dict) or isinstance(value, list):
        return json.dumps(value, default=str)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        if value.is_integer():
            return int(value)
    return value


def flatten_record(record: dict[str, Any], *, extract_host: bool = False) -> dict[str, Any]:
    """Flatten one Ivanti search record to a JSON-safe flat mapping.

    ``extract_host=True`` (findings) lifts ``host.hostId`` / ``host.ipAddress``
    to top-level ``host_id`` / ``host_ip`` and JSON-encodes the nested ``host``.
    """
    row: dict[str, Any] = {}
    if extract_host:
        host = record.get("host") or {}
        if isinstance(host, dict):
            row["host_id"] = _flatten_value(host.get("hostId"))
            row["host_ip"] = host.get("ipAddress")
    for key, value in record.items():
        row[key] = _flatten_value(value)
    return row


class IvantiError(Exception):
    """A non-retryable Ivanti API error (bad request, auth, transport)."""


class IvantiClient:
    """Minimal pure-stdlib Ivanti VM search/export client."""

    def __init__(
        self,
        url: str,
        api_ver: str,
        client_id: str,
        api_key: str,
        *,
        verify_ssl: bool = True,
        timeout: float = 600.0,
    ) -> None:
        base = url.rstrip("/") + api_ver.rstrip("/")
        self.url_base = f"{base}/client/{client_id}"
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._ssl_ctx: ssl.SSLContext | None = None
        if verify_ssl:
            self._ssl_ctx = ssl.create_default_context()
        else:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # -- low-level transport -------------------------------------------------
    def _open(self, method: str, path: str, body: dict[str, Any] | None) -> Any:
        url = f"{self.url_base}{path}"
        data = None
        headers = {
            "x-api-key": self.api_key,
            "content-type": "application/json",
            "accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        kwargs: dict[str, Any] = {}
        if self._ssl_ctx is not None and url.startswith("https://"):
            kwargs["context"] = self._ssl_ctx
        try:
            return urllib.request.urlopen(request, timeout=self.timeout, **kwargs)
        except urllib.error.HTTPError as exc:
            raise IvantiError(
                f"{method} {path} -> HTTP {exc.code}: {exc.read(2000).decode('utf-8', 'replace')}"
            ) from exc
        except urllib.error.URLError as exc:
            raise IvantiError(f"{method} {path} -> transport error: {exc.reason}") from exc

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None,
                 *, retries: int = 5, backoff: float = 0.5) -> dict[str, Any]:
        """Send one JSON request with retry/backoff on rate-limit / 5xx statuses."""
        last: str | None = None
        for attempt in range(retries):
            try:
                with self._open(method, path, body) as resp:
                    return json.loads(resp.read())
            except IvantiError as exc:
                last = str(exc)
                status = getattr(exc, "code", None)
                if status in RETRY_STATUSES or status is None:
                    time.sleep(min(120, backoff * (2 ** attempt)))
                    continue
                raise
        raise IvantiError(f"{method} {path} failed after {retries} retries: {last}")

    def _subject(self, endp: str) -> str:
        return f"{endp[:-1]}ies" if endp.endswith("y") else f"{endp}s"

    # -- discovery -----------------------------------------------------------
    def filters(self, endp: str) -> list[dict[str, Any]]:
        """Return the API's valid filter list for an endpoint (discovery only)."""
        resp = self._request("GET", f"/{endp}/filter")
        return resp if isinstance(resp, list) else []

    def fields(self, endp: str) -> list[dict[str, Any]]:
        """Return the API's exportable field set for an endpoint (discovery only)."""
        resp = self._request("GET", f"/{endp}/export/template")
        return resp.get("exportableFields", []) if isinstance(resp, dict) else []

    # -- search --------------------------------------------------------------
    def search_page(self, endp: str, *, page: int = 0, size: int = DEFAULT_SIZE,
                    projection: str = "basic",
                    filters: list[dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], int]:
        """Fetch one search page. Returns (records, total_elements)."""
        body: dict[str, Any] = {
            "projection": projection,
            "sort": [{"field": "id", "direction": "ASC"}],
            "page": page,
            "size": size,
        }
        if filters:
            body["filters"] = filters
        resp = self._request("POST", f"/{endp}/search", body)
        page_info = resp.get("page") or {}
        records = (resp.get("_embedded") or {}).get(self._subject(endp), []) or []
        return records, int(page_info.get("totalElements", 0))

    def search(self, endp: str, *, filters: list[dict[str, Any]] | None = None,
               projection: str = "basic", size: int = DEFAULT_SIZE,
               pages: int | None = None,
               extract_host: bool = False) -> list[dict[str, Any]]:
        """Pull all pages (or up to ``pages``) for an endpoint.

        Returns flattened, JSON-safe records. ``extract_host=True`` (findings)
        lifts ``host.hostId``/``host.ipAddress`` to ``host_id``/``host_ip``.
        This mirrors the upstream ``Ivanti.search`` but does not cap the total;
        callers with very large scopes should scope by CIDR/IP so no single
        pull exceeds PAGE_CAP.
        """
        def _flat(rec: dict[str, Any]) -> dict[str, Any]:
            return flatten_record(rec, extract_host=extract_host)
        records, _total = self.search_page(endp, size=size, projection=projection, filters=filters)
        out: list[dict[str, Any]] = [_flat(rec) for rec in records]
        page = 1
        while True:
            more, total = self.search_page(endp, page=page, size=size,
                                           projection=projection, filters=filters)
            if not more or (pages is not None and page >= pages):
                break
            out.extend(_flat(rec) for rec in more)
            page += 1
        return out

    # -- export (server-side CSV, UI-identical field set) --------------------
    def export(self, endp: str, *, filters: list[dict[str, Any]] | None = None,
               filename: str = "ivanti-export", save: str | None = None,
               poll: float = 6.0, timeout: float = 3600.0,
               verify: bool = True) -> bytes:
        """Create a server-side CSV export and download it (poll until ready)."""
        exportable = self.fields(endp)
        body: dict[str, Any] = {
            "fileType": "CSV",
            "comment": "specaudit-ctf ivanti arm export",
            "fileName": filename,
            "noOfRows": "All",
            "exportableFields": exportable,
        }
        if filters:
            body["filterRequest"] = {"filters": filters}
        resp = self._request("POST", f"/{endp}/export", body)
        export_id = (resp.get("id") or resp.get("exportId") or resp.get("exportGuid"))
        if not export_id:
            raise IvantiError(f"export create returned no export id: {str(resp)[:500]}")
        waited = 0.0
        while waited <= timeout:
            url = f"{self.url_base}/export/{export_id}"
            data = None
            headers = {"x-api-key": self.api_key, "accept": "*/*"}
            request = urllib.request.Request(url, data=None, headers=headers, method="GET")
            kwargs: dict[str, Any] = {}
            if self._ssl_ctx is not None and url.startswith("https://"):
                kwargs["context"] = self._ssl_ctx
            try:
                with urllib.request.urlopen(request, timeout=self.timeout, **kwargs) as r:
                    ctype = (r.headers.get("Content-Type") or "").lower()
                    content = r.read()
            except urllib.error.HTTPError as exc:
                if exc.code in RETRY_STATUSES:
                    time.sleep(poll)
                    waited += poll
                    continue
                raise IvantiError(f"export {export_id} poll -> HTTP {exc.code}") from exc
            if "json" not in ctype and content:
                # finished: non-JSON file bytes
                if save:
                    if content[:2] == b"PK" and save.lower().endswith(".csv"):
                        save = save[:-4] + ".zip"
                    with open(save, "wb") as fh:
                        fh.write(content)
                    return content
                return content
            time.sleep(poll)
            waited += poll
        raise IvantiError(f"export {export_id} not ready after {timeout}s")
