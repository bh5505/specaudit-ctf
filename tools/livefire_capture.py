#!/usr/bin/env python3
"""ASM/VM live-fire banner / TLS / cert capture - lab and loopback only.

Reads a target list (one target per line: "ip proto/port [note]"; '#' lines are
comments and are NEVER probed), performs one bounded observation per endpoint
and writes receipts.

Discipline enforced here (not just in the docstring):
  * fixed endpoint list, no port sweep, no range, no fuzzer
  * TCP: one connect + one banner read; TLS: one handshake + cert capture
  * HTTP(S): one GET (never POST/PUT/DELETE), tiny read cap
  * UDP: one request (DNS query on port 53), one response read
  * hard socket timeouts; nothing retries more than once
  * aborts if a target is not in the lab/loopback/RFC1918/CGNAT space, so a
    stray public IP in the file cannot turn this into public-space scanning

Outputs (in --out-dir):
  livefire_receipts.csv    one row per probed endpoint (evidence-shaped)
  livefire_receipts.jsonl  same, with full detail
  livefire_summary.json    counts, tool versions, aborts

No evidence tables are written here - that is livefire_overlay.py.

The DNS lanes ask about a name the operator owns (default asmvm-livecheck.local, override
with --dns-name or ASMVM_DNS_PROBE_NAME); nothing here resolves or connects
outside the address space the target file names, and the classifier still aborts
on public addresses.
"""
import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os

# Name the DNS lanes ask about. Owner-configurable; nothing in this tool
# resolves a name it was not told to use.
DNS_PROBE_NAME = os.environ.get("ASMVM_DNS_PROBE_NAME",
                                "asmvm-livecheck.local")
import socket
import ssl
import subprocess
import sys

CGNAT = ipaddress.ip_network("100.64.0.0/10")
BANNER_CAP = 512
HTTP_CAP = 4096


def lab_scoped(ip):
    """True only for space this lab owns (loopback/RFC1918/link-local/CGNAT)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 4 and addr in CGNAT:
        return True
    return bool(addr.is_loopback or addr.is_private or addr.is_link_local)


def parse_targets(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            ip = parts[0]
            spec = parts[1] if len(parts) > 1 else ""
            note = " ".join(parts[2:]) if len(parts) > 2 else ""
            if "/" not in spec:
                continue
            proto, port = spec.split("/", 1)
            proto = "udp" if proto.lower().startswith("u") else "tcp"
            out.append({"ip": ip, "proto": proto, "port": int(port), "note": note})
    return out


def grab_tcp(ip, port, timeout):
    """One connect, one banner read. Returns (sock, banner bytes, err)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        sock.close()
        return None, b"", type(exc).__name__
    banner = b""
    try:
        banner = sock.recv(BANNER_CAP)
    except socket.timeout:
        pass
    except OSError:
        pass
    return sock, banner, ""


def tls_capture(sock, ip, port, timeout):
    """One unverified TLS handshake for protocol/cipher (we are capturing, not
    trusting), then a second openssl capture for the certificate itself."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # socket timeout already set by grab_tcp
    try:
        wrapped = ctx.wrap_socket(sock, server_hostname=ip)
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return None, "%s" % type(exc).__name__
    try:
        der = wrapped.getpeercert(binary_form=True)
        info = {
            "tls_protocol": wrapped.version() or "",
            "tls_cipher": (wrapped.cipher() or ("", "", ""))[0],
            "cert_sha256": hashlib.sha256(der).hexdigest() if der else "",
            "cert_bytes": len(der or b""),
        }
        try:
            parsed = wrapped.getpeercert()
        except (ValueError, ssl.SSLError):
            parsed = {}
        info["cert_subject"] = "; ".join(
            v for kv in (parsed.get("subject") or ()) for v in kv)
        info["cert_issuer"] = "; ".join(
            v for kv in (parsed.get("issuer") or ()) for v in kv)
        info["cert_not_before"] = parsed.get("notBefore", "")
        info["cert_not_after"] = parsed.get("notAfter", "")
        info["cert_san"] = "; ".join(
            "%s=%s" % kv for kv in (parsed.get("subjectAltName") or ()))
        info["self_signed"] = bool(info["cert_subject"]
                                   and info["cert_subject"] == info["cert_issuer"])
        info["capture_detail"] = "python-ssl handshake;"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    # second, independent capture of the certificate with openssl
    py_proto, py_cipher = info.get("tls_protocol", ""), info.get("tls_cipher", "")
    oinfo, oerr = tls_cert_openssl(ip, port, timeout)
    if oinfo:
        for key, value in oinfo.items():
            if value or not info.get(key):
                info[key] = value
        # keep the python handshake as a cross-check, not as the certificate
        info["capture_detail"] += (" python_ssl_protocol=%s python_ssl_cipher=%s"
                                   % (py_proto, py_cipher))
    else:
        info["capture_detail"] += " openssl_cert_capture_error=%s;" % oerr
    return info, ""


def tls_cert_openssl(ip, port, timeout):
    """Certificate capture via openssl s_client + x509 (verifiable tooling).

    Python's SSLSocket returns no parsed peer certificate under CERT_NONE on
    TLS 1.3 before application data is exchanged, so the certificate fields are
    captured with openssl (the tool an analyst would cite) and the Python
    handshake is kept only as the protocol/cipher cross-check.
    """
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", "%s:%d" % (ip, port),
             "-servername", ip, "-showcerts", "-brief"],
            input="", capture_output=True, text=True, timeout=timeout + 12)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except FileNotFoundError:
        return None, "openssl_not_installed"
    except subprocess.TimeoutExpired as exc:
        # s_server (and some stacks) keep the connection open after stdin EOF;
        # whatever the handshake printed before the timeout is still evidence.
        def _dec(value):
            if isinstance(value, bytes):
                return value.decode("utf-8", "replace")
            return value or ""
        out = _dec(exc.stdout) + "\n" + _dec(exc.stderr)
        out += "\ncon_note=s_client did not exit before timeout\n"
    if "BEGIN CERTIFICATE" not in out:
        err = "no_cert"
        for line in out.splitlines():
            if "errno" in line or "error" in line.lower():
                err = line.strip()[:120]
                break
        return None, err
    info = {"tls_protocol": "", "tls_cipher": "", "cert_sha256": "",
            "cert_subject": "", "cert_issuer": "", "cert_san": "",
            "cert_not_before": "", "cert_not_after": "",
            "tls_verify_return_code": "", "capture_detail": "openssl s_client;"}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Protocol :"):
            info["tls_protocol"] = s.split(":", 1)[1].strip()
        elif s.startswith("New,") and "TLSv" in s:
            info["tls_protocol"] = info["tls_protocol"] or s.split(",")[1].strip()
        elif s.startswith("Cipher is"):
            info["tls_cipher"] = s.split("is", 1)[1].strip()
        elif s.startswith("Verify return code:"):
            info["tls_verify_return_code"] = s.split(":", 1)[1].strip()
    # leaf certificate = the first PEM block s_client printed
    pem_lines, seen = [], False
    for line in out.splitlines():
        if "BEGIN CERTIFICATE" in line:
            seen, pem_lines = True, []
        if seen:
            pem_lines.append(line.strip())
        if seen and "END CERTIFICATE" in line:
            break
    pem = "\n".join(pem_lines)
    if not pem:
        return info, "no_leaf_pem"
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as fh:
        fh.write(pem + "\n")
        fh.flush()
        try:
            x509 = subprocess.run(
                ["openssl", "x509", "-in", fh.name, "-noout",
                 "-subject", "-issuer", "-startdate", "-enddate",
                 "-fingerprint", "-sha256", "-ext", "subjectAltName"],
                capture_output=True, text=True, timeout=15)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return info, "x509_parse_failed:%s" % type(exc).__name__
    for line in (x509.stdout or "").splitlines():
        s = line.strip()
        if s.startswith("subject="):
            info["cert_subject"] = s.split("=", 1)[1].strip()
        elif s.startswith("issuer="):
            info["cert_issuer"] = s.split("=", 1)[1].strip()
        elif s.startswith("notBefore="):
            info["cert_not_before"] = s.split("=", 1)[1].strip()
        elif s.startswith("notAfter="):
            info["cert_not_after"] = s.split("=", 1)[1].strip()
        elif "Fingerprint=" in s:
            info["cert_sha256"] = s.split("=", 1)[1].replace(":", "").strip().lower()
        elif s.startswith("X509v3 Subject Alternative Name"):
            continue
        elif "DNS:" in s and not info["cert_san"]:
            info["cert_san"] = s.strip()
    info["self_signed"] = bool(info["cert_subject"]
                               and info["cert_subject"] == info["cert_issuer"])
    info["capture_detail"] += "leaf_pem_bytes=%d;" % len(pem)
    return info, ""


def http_get(sock, ip, port, proto, timeout):
    """One GET. Never a mutating verb."""
    scheme = "https" if proto == "tls" else "http"
    req = ("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: asmvm-livefire/1.0 "
           "(pre-test verification)\r\nAccept: */*\r\nConnection: close\r\n\r\n"
           % ip)
    try:
        sock.settimeout(timeout)
        sock.sendall(req.encode())
        data = sock.recv(HTTP_CAP)
    except (socket.timeout, OSError) as exc:
        return None, type(exc).__name__
    finally:
        try:
            sock.close()
        except OSError:
            pass
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    status = ""
    server = ""
    if lines and lines[0].upper().startswith("HTTP/"):
        bits = lines[0].split(" ")
        status = bits[1] if len(bits) > 1 else ""
    for ln in lines[1:]:
        if ln.lower().startswith("server:"):
            server = ln.split(":", 1)[1].strip()
    return {"http_status": status, "http_server_header": server,
            "http_bytes_read": len(data), "http_url": "%s://%s:%d/" % (scheme, ip, port)}, ""


def dns_probe_dig(ip, port, timeout, name=None):
    """One DNS A query over UDP via dig (deterministic client, parsed rcode).

    Returns None when dig is missing so the caller can fall back to the raw
    packet path. A parsed rcode is real protocol evidence; a raw timeout is not
    the same observation as NOERROR/NODATA.
    """
    name = name or DNS_PROBE_NAME
    try:
        proc = subprocess.run(
            ["dig", "+time=2", "+tries=1", "+noall", "+comments", "+stats",
             "+answer", "@%s" % ip, "-p", str(port), name, "A"],
            capture_output=True, text=True, timeout=timeout + 8)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return {"dns_rcode": "timeout", "dns_answers": "0",
                "dns_server": "%s:%s" % (ip, port), "dns_query_name": name,
                "udp_response_bytes": 0}
    out = proc.stdout or ""
    rcode, answers, server = "", "", ""
    for line in out.splitlines():
        if "status:" in line:
            rcode = line.split("status:", 1)[1].split(",")[0].strip()
        if "ANSWER:" in line:
            answers = line.split("ANSWER:", 1)[1].split(",")[0].strip()
        elif line.startswith(";; SERVER:"):
            server = line.split("SERVER:", 1)[1].strip()
    return {"dns_rcode": rcode or "no_response", "dns_answers": answers,
            "dns_server": server, "dns_query_name": name,
            "udp_response_bytes": len(out.encode()),
            "capture_detail": "dig +time=2 +tries=1;"}


def ntp_probe_udp(ip, port, timeout):
    """One NTP mode-3 client packet (48 bytes), one response read."""
    import struct
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    pkt = struct.pack("!BbbbII", 0x23, 3, 0, 0, 0, 0) + b"\0" * 36
    try:
        sock.sendto(pkt, (ip, port))
        data, _ = sock.recvfrom(64)
    except (socket.timeout, OSError) as exc:
        sock.close()
        return None, type(exc).__name__
    sock.close()
    return {"udp_response_bytes": len(data),
            "ntp_stratum": (data[0] >> 4) & 0xF if len(data) >= 1 else "",
            "ntp_mode": data[0] & 0xF if len(data) >= 1 else "",
            "ntp_packet_ok": len(data) == 48}, ""


def dns_query_udp(ip, port, timeout, name=None):
    """One DNS A query for a name we own, over UDP."""
    name = name or DNS_PROBE_NAME
    qid = 0x5747
    wire = (bytes.fromhex("%04x" % qid) + b"\x01\x00\x00\x01\x00\x00\x00\x00"
            + b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
            + b"\x00\x00\x01\x00\x01")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(wire, (ip, port))
        data, _ = sock.recvfrom(1024)
    except (socket.timeout, OSError) as exc:
        sock.close()
        return None, type(exc).__name__
    sock.close()
    ancount = int.from_bytes(data[6:8], "big") if len(data) >= 12 else 0
    return {"udp_response_bytes": len(data), "udp_answer_count": ancount,
            "udp_query_name": name, "udp_opcode": data[2] >> 3 if len(data) > 2 else None}, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--run-id", default="gw-livefire")
    ap.add_argument("--engagement-id", default="asmvm-rehearsal-2026")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--dns-name", default=DNS_PROBE_NAME,
                    help="name to ask the resolver for; must be a name the "
                         "operator owns (default %s)" % DNS_PROBE_NAME)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    targets = parse_targets(args.targets)
    hosts = sorted({t["ip"] for t in targets})
    print("targets: %d endpoint(s) over %d host(s)" % (len(targets), len(hosts)))
    if len(hosts) > 20:
        print("REFUSING: more than 20 hosts in scope (%d)" % len(hosts))
        return 2

    tools = {"python": sys.version.split()[0], "socket": "stdlib"}
    try:
        tools["openssl"] = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True,
            timeout=10).stdout.strip()
    except Exception as exc:  # noqa: BLE001 - capture tool inventory only
        tools["openssl"] = "unavailable (%s)" % type(exc).__name__
    try:
        tools["kernel"] = " ".join(subprocess.run(
            ["uname", "-srm"], capture_output=True, text=True,
            timeout=10).stdout.split())
    except Exception:  # noqa: BLE001
        tools["kernel"] = "unknown"
    try:
        local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        local.connect((hosts[0], 53))
        tools["source_addr"] = local.getsockname()[0]
        local.close()
    except OSError:
        tools["source_addr"] = "unknown"

    fields = ["observed_at", "run_id", "engagement_id", "target_ip", "proto", "port",
              "endpoint_status", "banner", "tls_protocol", "tls_cipher",
              "cert_subject", "cert_issuer", "cert_san", "cert_not_before",
              "cert_not_after", "cert_sha256", "self_signed", "http_status",
              "http_server_header", "http_url", "cert_bytes", "http_bytes_read",
              "udp_response_bytes", "udp_answer_count", "udp_query_name",
              "udp_opcode", "dns_rcode", "dns_answers", "dns_server",
              "dns_query_name", "ntp_stratum",
              "ntp_mode", "ntp_packet_ok", "tls_verify_return_code",
              "capture_detail",
              "note", "source_addr", "capture_host", "tool"]
    rows, skipped = [], []
    for t in targets:
        rec = {k: "" for k in fields}
        rec.update({"observed_at": dt.datetime.now(dt.timezone.utc)
                    .replace(microsecond=0).isoformat(sep=" "),
                    "run_id": args.run_id, "engagement_id": args.engagement_id,
                    "target_ip": t["ip"], "proto": t["proto"], "port": t["port"],
                    "note": t["note"], "source_addr": tools.get("source_addr", ""),
                    "capture_host": socket.gethostname(), "tool": "python-stdlib-socket/1.0"})
        if not lab_scoped(t["ip"]):
            rec["endpoint_status"] = "skipped_not_lab_space"
            skipped.append(t["ip"])
            rows.append(rec)
            continue
        print("  probe %-15s %s/%-5s" % (t["ip"], t["proto"], t["port"]), end=" ")
        if t["proto"] == "udp":
            info, err = None, ""
            if t["port"] == 53:
                info = dns_probe_dig(t["ip"], t["port"], args.timeout)
                if info:
                    rec["tool"] = "dig (udp dns query, +tries=1)"
            if info is None and t["port"] in (123, 323):
                info, err = ntp_probe_udp(t["ip"], t["port"], args.timeout)
                if info:
                    rec["tool"] = "python-stdlib-socket ntp mode-3"
            if info is None:
                info, err = dns_query_udp(t["ip"], t["port"], args.timeout,
                                          args.dns_name)
            if info:
                rec["endpoint_status"] = "answered"
                for key, value in info.items():
                    if key in fields:
                        rec[key] = value
                    else:
                        rec["capture_detail"] += "%s=%s;" % (key, value)
                if rec["dns_rcode"]:
                    rec["banner"] = "dns rcode=%s answers=%s server=%s name=%s" % (
                        rec["dns_rcode"], rec["dns_answers"], rec["dns_server"],
                        rec["dns_query_name"])
                elif rec["ntp_stratum"] != "":
                    rec["banner"] = "ntp answer bytes=%s stratum=%s mode=%s" % (
                        rec["udp_response_bytes"], rec["ntp_stratum"],
                        rec["ntp_mode"])
                else:
                    rec["banner"] = "udp answer bytes=%s" % rec["udp_response_bytes"]
            else:
                rec["endpoint_status"] = "no_answer(%s)" % err
            print(rec["endpoint_status"] + (" | %s" % rec["banner"][:70]
                                            if rec["banner"] else ""))
            rows.append(rec)
            continue

        sock, banner, err = grab_tcp(t["ip"], t["port"], args.timeout)
        if sock is None:
            rec["endpoint_status"] = "refused" if err == "ConnectionRefusedError" \
                else "unreachable(%s)" % err
            print(rec["endpoint_status"])
            rows.append(rec)
            continue
        rec["endpoint_status"] = "open"
        rec["banner"] = banner[:BANNER_CAP].decode("latin-1", "replace") \
            .replace("\r", "\\r").replace("\n", "\\n")
        # service classification drives what we try next; banner is never forged
        banner_low = banner[:64].lower()
        wants_tls = (t["port"] in (443, 465, 993, 995, 8443, 14443)
                     or banner_low.startswith((b"\x16\x03", b"tls", b"ssl")))
        is_http = banner_low.startswith((b"http/", b"get", b"post")) or t["port"] in (
            80, 443, 4000, 5040, 7680, 8080, 14443)
        if banner_low.startswith((b"ssh-", b"ftp", b"smtp", b"220", b"220-")) or \
                t["port"] in (21, 22, 25, 139, 445, 135):
            # banner protocols: close after the banner, do not speak further
            try:
                sock.close()
            except OSError:
                pass
            if t["port"] == 22 and banner_low.startswith(b"ssh-"):
                rec["tls_protocol"] = ""  # ssh transport, not TLS; banner is the evidence
            print("open banner=%r" % rec["banner"][:48])
            rows.append(rec)
            continue
        if wants_tls:
            try:
                sock.close()  # one connection per protocol attempt, no fd leak
            except OSError:
                pass
            sock2, banner2, _ = grab_tcp(t["ip"], t["port"], args.timeout)
            if sock2 is not None:
                info, tls_err = tls_capture(sock2, t["ip"], t["port"], args.timeout)
                if info:
                    rec.update(info)
                    rec["tls_protocol"] = info["tls_protocol"] or rec["tls_protocol"]
                else:
                    rec["tls_protocol"] = ""
                    rec["banner"] = (rec["banner"] + " tls_handshake_error="
                                     + tls_err)[:BANNER_CAP]
        if is_http:
            sock3, banner3, _ = grab_tcp(t["ip"], t["port"], args.timeout)
            if sock3 is not None:
                info, http_err = http_get(sock3, t["ip"], t["port"],
                                          "tls" if rec.get("tls_protocol") else "http",
                                          args.timeout)
                if info:
                    rec.update(info)
                else:
                    rec["banner"] = (rec["banner"] + " http_error=" + http_err)[:BANNER_CAP]
        else:
            try:
                sock.close()
            except OSError:
                pass
        print(rec["endpoint_status"] + (" tls=%s" % rec.get("tls_protocol", ""))
              + (" http=%s" % rec.get("http_status", "")))
        rows.append(rec)

    csv_path = os.path.join(args.out_dir, "livefire_receipts.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(args.out_dir, "livefire_receipts.jsonl"), "w",
              encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")

    summary = {
        "run_id": args.run_id, "engagement_id": args.engagement_id,
        "started_utc": rows[0]["observed_at"] if rows else "",
        "finished_utc": rows[-1]["observed_at"] if rows else "",
        "hosts": len(hosts), "endpoints": len(targets),
        "skipped_not_lab_space": sorted(set(skipped)),
        "status_tally": {}, "tools": tools,
    }
    for r in rows:
        key = r["endpoint_status"].split("(")[0]
        summary["status_tally"][key] = summary["status_tally"].get(key, 0) + 1
    summary["observed_with_banner"] = sum(
        1 for r in rows if r["banner"] and r["endpoint_status"] == "open")
    summary["observed_with_tls_cert"] = sum(1 for r in rows if r["cert_sha256"])
    summary["observed_with_http_status"] = sum(1 for r in rows if r["http_status"])
    with open(os.path.join(args.out_dir, "livefire_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, sort_keys=True)
    print("\nwrote %s (%d endpoint rows)" % (csv_path, len(rows)))
    print(json.dumps(summary["status_tally"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
