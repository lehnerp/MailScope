"""Routing trace (Received chain), authentication results and sender identity."""
from __future__ import annotations

import concurrent.futures
import re
import socket
from datetime import timezone
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from .common import (EMAIL_RE, classify_ip, domain_of, find_ips, get_all, get_header,
                     is_ip, org_domain, org_label)
from .config import BRANDS, FREE_MAIL

RECV_FROM = re.compile(r"^\s*from\s+(.*?)(?=\s+by\s|\s+via\s|\s+with\s|\s+id\s|\s+for\s|;|$)", re.I | re.S)
RECV_BY = re.compile(r"\bby\s+(.*?)(?=\s+via\s|\s+with\s|\s+id\s|\s+for\s|;|$)", re.I | re.S)
RECV_WITH = re.compile(r"\bwith\s+([^\s;()]+)", re.I)
RECV_ID = re.compile(r"\bid\s+([^\s;()]+)", re.I)
RECV_FOR = re.compile(r"\bfor\s+<?([^\s;>]+)>?", re.I)


def _parse_date(value: str):
    try:
        dt = parsedate_to_datetime(value.strip())
    except Exception:
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ip_list(text):
    return [{"ip": ip, "class": classify_ip(ip)} for ip in find_ips(text)]


def parse_received(headers) -> list[dict]:
    raws = get_all(headers, "Received")
    hops = []
    for idx, raw in enumerate(reversed(raws), 1):  # chronological: origin first
        body, _, date_part = raw.rpartition(";")
        if not body:
            body, date_part = raw, ""
        m_from = RECV_FROM.search(body)
        m_by = RECV_BY.search(body)
        from_sec = m_from.group(1).strip() if m_from else ""
        by_sec = m_by.group(1).strip() if m_by else ""
        rdns = re.search(r"\(\s*([^\s\[\)]+)", from_sec)
        ts = _parse_date(date_part) if date_part else None
        hops.append({
            "index": idx,
            "from_host": from_sec.split()[0] if from_sec else "",
            "from_rdns": rdns.group(1) if rdns else "",
            "from_detail": from_sec,
            "by_host": by_sec.split()[0] if by_sec else "",
            "protocol": (RECV_WITH.search(body).group(1) if RECV_WITH.search(body) else ""),
            "smtp_id": (RECV_ID.search(body).group(1) if RECV_ID.search(body) else ""),
            "for": (RECV_FOR.search(body).group(1) if RECV_FOR.search(body) else ""),
            "ips": _ip_list(from_sec),
            "by_ips": _ip_list(by_sec),
            "timestamp": ts.astimezone(timezone.utc).isoformat() if ts else None,
            "_dt": ts,
            "delay_seconds": None,
            "tls": bool(re.search(r"ESMTPS|TLS|SMTPSA|ESMTPSA", body)),
            "raw": raw,
        })
    prev = None
    for h in hops:
        if h["_dt"] and prev is not None:
            h["delay_seconds"] = int((h["_dt"] - prev).total_seconds())
        if h["_dt"]:
            prev = h["_dt"]
    return hops


def _reverse_dns(ip: str, timeout: float = 3.0) -> str:
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(socket.gethostbyaddr, ip)
        try:
            return fut.result(timeout=timeout)[0]
        except Exception:
            return ""


def _parse_kv(value: str, sep=";", kv=":") -> dict:
    out = {}
    for item in value.split(sep):
        if kv in item:
            k, v = item.split(kv, 1)
            out[k.strip().upper()] = v.strip()
    return out


def gateway_verdicts(headers) -> list[dict]:
    """Spam/AV verdicts stamped by gateways (Microsoft 365, SpamAssassin, ...)."""
    out = []
    ff = get_header(headers, "X-Forefront-Antispam-Report")
    if ff:
        d = _parse_kv(ff)
        out.append({"source": "Microsoft 365 (Forefront)", "fields": d,
                    "spam": d.get("SFV", "").upper() in ("SPM", "BLK") or _int(d.get("SCL")) >= 5,
                    "summary": f"SCL={d.get('SCL', '?')} SFV={d.get('SFV', '?')} CTRY={d.get('CTRY', '?')} "
                               f"CIP={d.get('CIP', '?')} PTR={d.get('PTR', '?')}"})
    scl = get_header(headers, "X-MS-Exchange-Organization-SCL")
    if scl and not ff:
        out.append({"source": "Exchange SCL", "fields": {"SCL": scl}, "spam": _int(scl) >= 5, "summary": f"SCL={scl}"})
    msa = get_header(headers, "X-Microsoft-Antispam")
    if msa:
        d = _parse_kv(msa)
        out.append({"source": "Microsoft Antispam", "fields": d, "spam": False,
                    "summary": f"BCL={d.get('BCL', '?')}"})
    flag = get_header(headers, "X-Spam-Flag")
    status = get_header(headers, "X-Spam-Status")
    score = get_header(headers, "X-Spam-Score")
    if flag or status or score:
        out.append({"source": "SpamAssassin / gateway", "fields": {"flag": flag, "status": status[:300], "score": score},
                    "spam": flag.strip().upper() == "YES" or status.strip().lower().startswith("yes"),
                    "summary": f"flag={flag or '-'} score={score or (re.search(r'score=([\d.\-]+)', status).group(1) if re.search(r'score=([\d.\-]+)', status) else '-')}"})
    return out


def _int(v) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return -1


def build_trace(headers, rdns: bool = False) -> dict:
    hops = parse_received(headers)
    anomalies = []

    origin = None
    for h in hops:
        pub = [i["ip"] for i in h["ips"] if i["class"] == "public"]
        if pub:
            origin = {"ip": pub[0], "hop": h["index"], "helo": h["from_host"],
                      "rdns_claimed": h["from_rdns"], "rdns_live": "", "country": ""}
            break

    originating = []
    for name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP", "X-Client-IP", "X-Real-IP", "X-Forwarded-For"):
        for v in get_all(headers, name):
            for ip in find_ips(v):
                originating.append({"ip": ip, "class": classify_ip(ip), "header": name})

    gw = gateway_verdicts(headers)
    for g in gw:
        ctry = g["fields"].get("CTRY")
        if origin and ctry:
            origin["country"] = ctry

    if origin:
        if origin["rdns_claimed"].lower() == "unknown":
            anomalies.append({"code": "no_rdns", "text": f"Origin {origin['ip']} has no reverse DNS (logged as 'unknown')."})
        if rdns:
            origin["rdns_live"] = _reverse_dns(origin["ip"])
            if not origin["rdns_live"]:
                anomalies.append({"code": "no_rdns", "text": f"Live reverse DNS lookup for {origin['ip']} returned nothing."})

    for h in hops:
        if h["delay_seconds"] is not None and h["delay_seconds"] < -300:
            anomalies.append({"code": "time_travel",
                              "text": f"Hop {h['index']} is timestamped {abs(h['delay_seconds'])//60} min before the previous hop "
                                      "(clock skew or forged Received header)."})
        elif h["delay_seconds"] is not None and h["delay_seconds"] > 3600:
            anomalies.append({"code": "delay", "text": f"Hop {h['index']} took {h['delay_seconds']//60} min (queued / greylisted?)."})
        if not h["timestamp"]:
            anomalies.append({"code": "no_ts", "text": f"Hop {h['index']} has no parsable timestamp."})

    date_hdr = get_header(headers, "Date")
    date_dt = _parse_date(date_hdr) if date_hdr else None
    stamped = [h["_dt"] for h in hops if h["_dt"]]
    if date_dt and stamped:
        first, last = stamped[0], stamped[-1]
        if (first - date_dt).total_seconds() > 86400:
            anomalies.append({"code": "date_anomaly", "text": "Date header is more than 24 h older than the first Received hop."})
        if (date_dt - last).total_seconds() > 3600:
            anomalies.append({"code": "date_anomaly", "text": "Date header is later than final delivery (future-dated)."})

    total = int((stamped[-1] - stamped[0]).total_seconds()) if len(stamped) >= 2 else None
    for h in hops:
        h.pop("_dt", None)
    return {"hops": hops, "hop_count": len(hops), "origin": origin, "originating_ips": originating,
            "gateway_verdicts": gw, "anomalies": anomalies, "total_transit_seconds": total,
            "date": date_dt.isoformat() if date_dt else None}


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
METHOD_RE = re.compile(r"^\s*(spf|dkim|dmarc|arc|compauth|bimi|iprev|auth)\s*=\s*([A-Za-z]+)", re.I)
PROP_RE = re.compile(r"\b((?:smtp|header|policy)\.[a-z\-]+)\s*=\s*\"?([^\s;\"]+)", re.I)


def _parse_ar(value: str) -> dict:
    results = {}
    clauses = value.split(";")
    for clause in clauses[1:] if len(clauses) > 1 else clauses:
        m = METHOD_RE.search(clause)
        if not m:
            continue
        method, result = m.group(1).lower(), m.group(2).lower()
        if method in results:
            continue
        comment = re.search(r"\(([^)]*)\)", clause)
        results[method] = {"result": result,
                           "props": {k.lower(): v for k, v in PROP_RE.findall(clause)},
                           "comment": comment.group(1) if comment else ""}
    return results


def parse_auth(headers) -> dict:
    ar = get_all(headers, "Authentication-Results")
    arc = get_all(headers, "ARC-Authentication-Results")
    primary_src = "Authentication-Results" if ar else ("ARC-Authentication-Results" if arc else "")
    primary = _parse_ar((ar or arc or [""])[0]) if (ar or arc) else {}

    out = {"source": primary_src, "raw": ar + arc}
    for method in ("spf", "dkim", "dmarc", "arc", "compauth"):
        out[method] = primary.get(method)
    rspf = get_header(headers, "Received-SPF")
    out["received_spf"] = rspf
    if not out["spf"] and rspf:
        out["spf"] = {"result": rspf.split()[0].lower(), "props": {}, "comment": rspf[:200]}
        out["spf_source"] = "Received-SPF"
    sigs = []
    for v in get_all(headers, "DKIM-Signature"):
        d = re.search(r"\bd=([^;\s]+)", v)
        s = re.search(r"\bs=([^;\s]+)", v)
        a = re.search(r"\ba=([^;\s]+)", v)
        sigs.append({"d": d.group(1).lower() if d else "", "s": s.group(1) if s else "", "a": a.group(1) if a else ""})
    out["dkim_signatures"] = sigs
    return out


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
_GLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _deglyph(domain: str) -> str:
    """Undo common typosquat substitutions: paypa1 -> paypal, rnicrosoft -> microsoft."""
    return domain.lower().translate(_GLYPHS).replace("rn", "m").replace("vv", "w").replace("-", "")


def build_identity(headers, auth) -> dict:
    g = lambda n: get_header(headers, n)  # noqa: E731
    from_name, from_addr = parseaddr(g("From"))
    from_addr = from_addr.lower()
    from_domain = domain_of(from_addr)
    rp_addr = parseaddr(g("Return-Path"))[1].lower()
    reply = [a.lower() for _, a in getaddresses([g("Reply-To")]) if a] if g("Reply-To") else []
    sender = parseaddr(g("Sender"))[1].lower()
    msgid = g("Message-ID")
    m = re.search(r"@([^>\s]+)", msgid)
    msgid_domain = m.group(1).lower() if m else ""
    dkim_domains = [s["d"] for s in auth.get("dkim_signatures", []) if s.get("d")]

    checks = []

    def check(label, a, b, code):
        if a and b:
            checks.append({"label": label, "a": a, "b": b, "aligned": org_domain(a) == org_domain(b), "code": code})

    for r in reply:
        check("Reply-To vs From", domain_of(r), from_domain, "replyto")
    check("Return-Path (envelope) vs From", domain_of(rp_addr), from_domain, "returnpath")
    check("Sender vs From", domain_of(sender), from_domain, "sender")
    check("Message-ID vs From", msgid_domain, from_domain, "msgid")
    for d in dkim_domains:
        check("DKIM d= vs From", d, from_domain, "dkim")

    display_email = ""
    em = EMAIL_RE.search(from_name or "")
    if em and em.group(0).lower() != from_addr:
        display_email = em.group(0).lower()

    name_l = re.sub(r"[^a-z0-9]", "", (from_name or "").lower())
    impersonated = [b for b in BRANDS if b in name_l and b not in from_domain.replace("-", "").replace(".", "")]
    lookalike = []
    for dom in {from_domain, domain_of(rp_addr), *[domain_of(r) for r in reply]} - {""}:
        label = org_label(dom)
        if org_domain(dom) in FREE_MAIL:
            continue
        norm = _deglyph(dom)
        for b in BRANDS:
            if label == b:
                continue
            if b in dom or b in norm:
                lookalike.append(f"{dom} (~{b})")
                break

    return {
        "from_name": from_name, "from_addr": from_addr, "from_domain": from_domain,
        "return_path": rp_addr, "reply_to": reply, "sender": sender,
        "message_id": msgid, "msgid_domain": msgid_domain, "dkim_domains": dkim_domains,
        "free_mail": org_domain(from_domain) in FREE_MAIL,
        "display_name_email": display_email, "impersonated_brands": impersonated,
        "lookalike_brands": lookalike, "checks": checks,
        "x_mailer": g("X-Mailer") or g("User-Agent"),
    }
