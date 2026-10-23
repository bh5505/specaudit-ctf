"""Bounded live client for the fixed OSV v1 query API.

Transport rules (campaign contract):

  * stdlib :mod:`urllib.request` only; the opener is built per call — no
    module-level sockets or openers — with a TLS-verifying context and
    ``ProxyHandler({})`` so environment proxies cannot reroute traffic;
  * the endpoint is the fixed official host: nothing caller-selectable about
    scheme, host, or path;
  * redirects are refused (any 3xx is an error carrying the code), and no
    response ever triggers an automatic retry;
  * one overall deadline bounds the whole paginated query, with page, record,
    and per-response byte caps enforced through bounded incremental reads
    (the body is never slurped before the cap check).

The transport is injectable: callers (and tests) pass a callable
``(request, timeout) -> response`` with ``.status``/``.code``, ``.headers``,
and ``.read(n)``. Tests never construct the default transport, so no test
opens a network socket.

Status model: ``complete`` (200, every page token consumed, caps respected —
including a complete zero-match), ``partial`` (a client-side cap ended
pagination mid-stream), ``unknown`` (200 parsed but the payload is not a
recognizable query response), ``error`` (transport, HTTP, timeout, JSON, or
pagination-loop failure). ``ok`` is true for ``complete`` only; that mapping
lives in :mod:`arm`.
"""

from __future__ import annotations

import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable

from ..mcp_client import redact
from .policy import (
    EVIDENCE_BODY_BYTES,
    LIVE_LIMITATIONS,
    LIVE_TIMEOUT_SECONDS,
    MAX_LIVE_RECORDS,
    MAX_PAGES,
    MAX_RESPONSE_BYTES,
    OSV_ADVISORY_BASE_URL,
    OSV_API_HOST,
    OSV_QUERY_PATH,
    USER_AGENT,
    _READ_CHUNK,
)

Transport = Callable[[urllib.request.Request, float], Any]


class _RedirectRefused(Exception):
    """A 3xx response reached the redirect handler; the target is withheld."""

    def __init__(self, code: int, msg: str) -> None:
        super().__init__(f"HTTP {code} {msg}")
        self.code = code
        self.msg = msg


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise _RedirectRefused(code, msg)


def default_transport(request: urllib.request.Request, timeout: float) -> Any:
    """Proxy-free, redirect-refusing, TLS-verifying opener built per call."""
    opener = urllib.request.build_opener(
        _RefuseRedirect(),
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    return opener.open(request, timeout=timeout)


def run_query(
    body: dict[str, Any],
    *,
    transport: Transport | None = None,
    timeout: float = LIVE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run one bounded paginated POST query; return the live envelope.

    ``body`` is the exact OSV query payload (already validated by the policy
    layer) and is echoed verbatim as the envelope's ``query``. The function
    never retries and never raises: every failure becomes a status.
    """
    send: Transport = transport if transport is not None else default_transport
    fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    deadline = time.monotonic() + timeout

    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_tokens: set[str] = set()
    page_outcomes: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    limitations: list[str] = list(LIVE_LIMITATIONS)

    status = "error"
    reason: str | None = "query_did_not_complete"
    token: str | None = None
    pages = 0
    prior_max_id: str | None = None
    noted_duplicates: set[str] = set()
    out_of_order_noted = False

    while True:
        if pages >= MAX_PAGES:
            status, reason = "partial", "page_cap"
            evidence.append({"kind": "page_cap", "pages": MAX_PAGES})
            break
        page_body = body if token is None else dict(body, page_token=token)
        payload = json.dumps(page_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request_digest = hashlib.sha256(payload).hexdigest()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            status, reason = "error", "timeout"
            evidence.append({"kind": "timeout", "deadline_seconds": timeout})
            break
        request = urllib.request.Request(
            OSV_API_HOST + OSV_QUERY_PATH,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        try:
            response = send(request, remaining)
        except _RedirectRefused as exc:
            status, reason = "error", f"redirect_refused_{exc.code}"
            evidence.append({"kind": "redirect_refused", "http_status": exc.code})
            break
        except urllib.error.HTTPError as exc:
            # The default opener surfaces 4xx/5xx (and unhandled 3xx) as
            # HTTPError; classify it exactly like a returned status.
            response = exc
        except TimeoutError:
            status, reason = "error", "timeout"
            evidence.append({"kind": "timeout", "deadline_seconds": timeout})
            break
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                status, reason = "error", "timeout"
                evidence.append({"kind": "timeout", "deadline_seconds": timeout})
            else:
                status, reason = "error", "transport_error"
                evidence.append({"kind": "transport_error", "detail": redact(str(exc.reason))[:200]})
            break
        except OSError as exc:
            status, reason = "error", "transport_error"
            evidence.append({"kind": "transport_error", "detail": redact(str(exc))[:200]})
            break

        http_status = getattr(response, "status", None) or getattr(response, "code", None)
        pages += 1
        headers = getattr(response, "headers", None)
        retry_after = None
        if headers is not None:
            raw_retry = headers.get("Retry-After")
            if raw_retry is not None:
                retry_after = str(raw_retry)[:64]

        if isinstance(http_status, int) and 300 <= http_status < 400:
            status, reason = "error", f"redirect_refused_{http_status}"
            evidence.append({"kind": "redirect_refused", "http_status": http_status})
            break
        if http_status != 200:
            body_excerpt, body_bytes = _bounded_excerpt(response)
            status, reason = "error", f"http_status_{http_status}"
            evidence.append(
                {
                    "kind": "http_status",
                    "http_status": http_status,
                    "retry_after": retry_after,
                    "body_bytes": body_bytes,
                    "body_excerpt": body_excerpt,
                }
            )
            break

        chunks: list[bytes] = []
        total = 0
        over_cap = False
        while True:
            try:
                chunk = response.read(_READ_CHUNK)
            except TimeoutError:
                status, reason = "error", "timeout"
                evidence.append({"kind": "timeout", "deadline_seconds": timeout})
                break
            except OSError as exc:
                status, reason = "error", "transport_error"
                evidence.append({"kind": "transport_error", "detail": redact(str(exc))[:200]})
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                over_cap = True
                break
        if reason in ("timeout", "transport_error"):
            break
        raw_body = b"".join(chunks)
        response_digest = hashlib.sha256(raw_body).hexdigest()
        page_outcomes.append(
            {
                "page": pages,
                "request_sha256": request_digest,
                "response_sha256": response_digest,
                "response_bytes": total,
                "http_status": http_status,
            }
        )
        if over_cap:
            status, reason = "partial", "byte_cap"
            evidence.append(
                {
                    "kind": "byte_cap",
                    "page": pages,
                    "response_bytes": total,
                    "cap": MAX_RESPONSE_BYTES,
                }
            )
            break

        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            status, reason = "error", "malformed_json"
            evidence.append(
                {
                    "kind": "malformed_json",
                    "page": pages,
                    "response_bytes": total,
                    "body_excerpt": redact(raw_body.decode("utf-8", errors="replace")[:EVIDENCE_BODY_BYTES]),
                }
            )
            break
        shape_problem = _shape_problem(parsed)
        if shape_problem is not None:
            status, reason = "unknown", "response_shape_unrecognized"
            evidence.append({"kind": "shape", "page": pages, "detail": shape_problem})
            break

        vulns = parsed.get("vulns") or []
        retained = 0
        overflowed = False
        for raw_record in vulns:
            if len(records) >= MAX_LIVE_RECORDS:
                overflowed = True
                break
            normalized = normalize_record(raw_record)
            records.append(normalized)
            retained += 1
        page_ids = [normalized["id"] for normalized in records[-retained:]] if retained else []
        if page_ids:
            # Duplicates within one page and repeats across pages are both
            # retained as received and noted; an alias-free id repeat means
            # upstream identity collided, so the caller must see it.
            within_page = sorted(
                {pid for pid in page_ids if page_ids.count(pid) > 1} - noted_duplicates
            )
            duplicates = sorted(set(page_ids) & seen_ids - noted_duplicates)
            noted = within_page or duplicates
            if noted:
                noted_duplicates.update(noted)
                limitations.append(
                    "duplicate OSV id(s) retained in the response stream: "
                    + ", ".join(noted[:8])
                )
            seen_ids.update(page_ids)
            if prior_max_id is not None and min(page_ids) < prior_max_id and not out_of_order_noted:
                out_of_order_noted = True
                limitations.append(
                    "OSV ids were not monotonically ordered across pages; "
                    "records retained in arrival order"
                )
            prior_max_id = max(prior_max_id, max(page_ids)) if prior_max_id else max(page_ids)
        page_outcomes[-1]["vulns_retained"] = retained

        next_token = parsed.get("next_page_token")
        if overflowed:
            status, reason = "partial", "record_cap"
            evidence.append(
                {"kind": "record_cap", "records": len(records), "cap": MAX_LIVE_RECORDS}
            )
            break
        if isinstance(next_token, str) and next_token:
            if next_token in seen_tokens:
                status, reason = "error", "repeated_page_token"
                evidence.append(
                    {
                        "kind": "repeated_page_token",
                        "page": pages,
                        "page_token_sha256": hashlib.sha256(next_token.encode("utf-8")).hexdigest(),
                    }
                )
                break
            seen_tokens.add(next_token)
            token = next_token
            page_outcomes[-1]["next_page_token_seen"] = True
            continue
        status, reason = "complete", None
        break

    source = {
        "host": OSV_API_HOST,
        "endpoint": OSV_QUERY_PATH,
        "fetched_at": fetched_at,
        "pages": pages,
        "page_outcomes": page_outcomes,
    }
    if status != "complete":
        # Evidence is what bounds the incomplete result; keep it non-empty so
        # partial/unknown/error results are never indistinguishable from a
        # clean zero-match.
        if not evidence:
            evidence.append({"kind": "incomplete", "reason": reason})
    return {
        "status": status,
        "query": body,
        "records": records,
        "source": source,
        "limitations": limitations,
        "reason": reason,
        "evidence": evidence,
    }


def normalize_record(raw: Any) -> dict[str, Any]:
    """Project an upstream OSV record onto the arm's bounded record shape.

    The OSV id is the identity; aliases (CVE or otherwise) are carried as
    plain strings. A withdrawn timestamp is preserved — a withdrawn record
    stays flagged, never flattened into an unqualified advisory.
    """
    if not isinstance(raw, dict):
        raw = {}
    record_id = raw.get("id")
    record_id = record_id if isinstance(record_id, str) else ""
    aliases = [value for value in raw.get("aliases", []) if isinstance(value, str)]
    affected: list[dict[str, Any]] = []
    for item in raw.get("affected", []) if isinstance(raw.get("affected"), list) else []:
        if not isinstance(item, dict):
            continue
        package_raw = item.get("package") if isinstance(item.get("package"), dict) else {}
        package: dict[str, Any] = {
            "ecosystem": package_raw.get("ecosystem"),
            "name": package_raw.get("name"),
        }
        if isinstance(package_raw.get("purl"), str):
            package["purl"] = package_raw["purl"]
        projected: dict[str, Any] = {"package": package}
        ranges = []
        for entry in item.get("ranges", []) if isinstance(item.get("ranges"), list) else []:
            if not isinstance(entry, dict):
                continue
            projected_range: dict[str, Any] = {
                "type": entry.get("type"),
                "events": [event for event in entry.get("events", []) if isinstance(event, dict)],
            }
            if isinstance(entry.get("repo"), str):
                projected_range["repo"] = entry["repo"]
            ranges.append(projected_range)
        if ranges:
            projected["ranges"] = ranges
        versions = item.get("versions")
        if isinstance(versions, list):
            projected["versions"] = [value for value in versions if isinstance(value, str)]
        affected.append(projected)
    references = raw.get("references") if isinstance(raw.get("references"), list) else []
    source_link = OSV_ADVISORY_BASE_URL + record_id
    for reference in references:
        if isinstance(reference, dict) and isinstance(reference.get("url"), str):
            source_link = reference["url"]
            break
    return {
        "id": record_id,
        "aliases": aliases,
        "modified": raw.get("modified"),
        "summary": raw.get("summary") if isinstance(raw.get("summary"), str) else None,
        "withdrawn": raw.get("withdrawn"),
        "affected": affected,
        "source_link": source_link,
    }


def _shape_problem(parsed: Any) -> str | None:
    if not isinstance(parsed, dict):
        return "response is not a JSON object"
    if "vulns" in parsed and not isinstance(parsed["vulns"], list):
        return "vulns is not a list"
    if "vulns" in parsed:
        for item in parsed["vulns"]:
            if not isinstance(item, dict):
                return "vulns contains a non-object record"
            # id + modified are the OSV-required identity fields; a record
            # without them cannot be retained under a trustworthy identity.
            if not isinstance(item.get("id"), str) or not item["id"]:
                return "vulns record is missing its id"
            if not isinstance(item.get("modified"), str) or not item["modified"]:
                return f"vulns record {item['id']} is missing modified"
    if "next_page_token" in parsed and not isinstance(parsed["next_page_token"], str):
        return "next_page_token is not a string"
    return None


def _bounded_excerpt(response: Any) -> tuple[str, int]:
    """Read at most EVIDENCE_BODY_BYTES+1 bytes of an error body."""
    data = b""
    try:
        data = response.read(EVIDENCE_BODY_BYTES + 1)
    except Exception:  # noqa: BLE001 - the excerpt is best-effort evidence
        data = b""
    text = data.decode("utf-8", errors="replace")[:EVIDENCE_BODY_BYTES]
    return redact(text), len(data)
