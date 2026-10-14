"""URLs, HTML features, attachments, body keywords and IOC collection."""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .common import EMAIL_RE, classify_ip, domain_of, find_ips, is_ip, org_domain, org_label
from .config import (ARCHIVE_EXT, BRANDS, DANGEROUS_EXT, FREE_HOSTING, HTML_EXT, KEYWORDS,
                     LEGACY_OFFICE_EXT, MACRO_EXT, PE_EXT, SUSPICIOUS_TLDS, URL_SHORTENERS,
                     ZIP_CONTAINER_EXT)

URL_RE = re.compile(r"""(?i)\b(?:(?:https?|hxxps?|ftp)://|www\.)[^\s<>"'`{}|\\^\[\]]+""")
DOMAIN_IN_TEXT = re.compile(r"(?:https?://)?((?:[a-z0-9\-]+\.)+[a-z]{2,})", re.I)

URL_FLAGS = {
    "js_scheme": "javascript:/data: link",
    "ip_host": "Raw IP address as host",
    "punycode": "Punycode / IDN host (homograph risk)",
    "userinfo": "'@' in URL authority (hides real host)",
    "mismatch": "Link text shows a different domain",
    "shortener": "URL shortener",
    "susp_tld": "High-abuse TLD",
    "free_hosting": "Free / abusable hosting platform",
    "brand_host": "Brand name in non-brand domain",
    "cred_keywords": "Login/verify keywords in path",
    "no_tls": "Plain HTTP",
    "many_subdomains": "Deep subdomain nesting",
    "long": "Very long URL",
}


class _HTMLScan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.resources, self.meta_refresh = [], [], [], []
        self.text, self.pixels = [], 0
        self._a = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self._a = {"href": a["href"].strip(), "text": ""}
        if tag == "form":
            self.forms.append(a.get("action", "") or "(no action – posts to itself)")
        if tag in ("img", "iframe", "script", "embed", "source") and a.get("src"):
            self.resources.append({"tag": tag, "src": a["src"].strip()})
            if tag == "img" and a.get("width") in ("1", "0") and a.get("height") in ("1", "0"):
                self.pixels += 1
        if tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self.meta_refresh.append(m.group(1).strip())
        if tag in ("style", "script"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag == "a" and self._a is not None:
            self.links.append(self._a)
            self._a = None
        if tag in ("style", "script") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if self._a is not None:
            self._a["text"] += data
        if not self._skip:
            self.text.append(data)


def scan_html(html: str) -> dict:
    p = _HTMLScan()
    try:
        p.feed(html or "")
        p.close()
    except Exception:
        pass
    hidden = len(re.findall(r"display\s*:\s*none|font-size\s*:\s*0(?:px|pt)?\s*[;\"']|visibility\s*:\s*hidden", html or "", re.I))
    text = re.sub(r"[ \t\r\f\v]+", " ", " ".join(p.text))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return {"links": p.links, "forms": p.forms, "resources": p.resources, "meta_refresh": p.meta_refresh,
            "tracking_pixels": p.pixels, "hidden_elements": hidden, "text": text}


def _norm_url(url: str) -> str:
    u = url.strip().rstrip(".,;:!?)'\"")
    if u.lower().startswith("hxxp"):
        u = "http" + u[4:]
    if u.lower().startswith("www."):
        u = "http://" + u
    return u


def analyze_url(url: str, display_texts=()) -> dict:
    norm = _norm_url(url)
    flags = []
    try:
        p = urlsplit(norm)
        scheme, host, netloc = p.scheme.lower(), (p.hostname or "").lower(), p.netloc
        path = (p.path or "") + ("?" + p.query if p.query else "")
    except ValueError:
        scheme, host, netloc, path = "", "", "", norm
    if scheme in ("javascript", "data", "vbscript"):
        flags.append("js_scheme")
    if host and is_ip(host):
        flags.append("ip_host")
    if "xn--" in host:
        flags.append("punycode")
    if "@" in netloc:
        flags.append("userinfo")
    if host in URL_SHORTENERS:
        flags.append("shortener")
    if host and host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        flags.append("susp_tld")
    if host and any(host == h or host.endswith("." + h) for h in FREE_HOSTING):
        flags.append("free_hosting")
    label = org_label(host)
    if host and any(b in host for b in BRANDS) and label not in BRANDS:
        flags.append("brand_host")
    if re.search(r"(login|log-in|signin|sign-in|verify|verification|account|password|passwd|secure|"
                 r"update|confirm|webscr|banking|wallet|unlock|auth)", path, re.I):
        flags.append("cred_keywords")
    if scheme == "http":
        flags.append("no_tls")
    if host.count(".") >= 4:
        flags.append("many_subdomains")
    if len(norm) > 200:
        flags.append("long")
    shown = []
    for t in display_texts:
        m = DOMAIN_IN_TEXT.search((t or "").strip())
        if m and host and org_domain(m.group(1)) != org_domain(host) and "." in m.group(1):
            if "mismatch" not in flags:
                flags.append("mismatch")
            shown.append(m.group(1).lower())
    return {"url": norm, "scheme": scheme, "host": host, "org_domain": org_domain(host),
            "flags": flags, "flag_labels": [URL_FLAGS[f] for f in flags], "shown_domains": shown}


def extract_urls(text: str, html_info: dict) -> list[dict]:
    found: dict[str, dict] = {}

    def add(u, source, display=None):
        u = (u or "").strip()
        low = u.lower()
        if not u or low.startswith(("mailto:", "cid:", "#", "tel:", "sms:")):
            return
        if not low.startswith(("http", "hxxp", "www.", "ftp", "javascript:", "data:", "vbscript:")):
            return
        key = _norm_url(u)
        rec = found.setdefault(key, {"raw": u, "sources": set(), "texts": []})
        rec["sources"].add(source)
        if display and display.strip() and display.strip() not in rec["texts"]:
            rec["texts"].append(display.strip()[:200])

    for link in html_info.get("links", []):
        add(link["href"], "html <a>", link["text"])
    for r in html_info.get("resources", []):
        add(r["src"], f"html <{r['tag']}>")
    for f in html_info.get("forms", []):
        add(f, "html <form>")
    for u in html_info.get("meta_refresh", []):
        add(u, "meta refresh")
    for m in URL_RE.finditer(text or ""):
        add(m.group(0), "text")

    out = []
    for key, rec in found.items():
        a = analyze_url(rec["raw"], rec["texts"])
        a["sources"] = sorted(rec["sources"])
        a["display_texts"] = rec["texts"][:3]
        out.append(a)
    out.sort(key=lambda x: -len(x["flags"]))
    return out


# --------------------------------------------------------------------------- #
# Attachments
# --------------------------------------------------------------------------- #
def magic_type(data: bytes) -> str:
    head = data[:16]
    low = data[:512].lstrip().lower()
    if head.startswith(b"MZ"):
        return "PE executable"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "ZIP container"
    if head.startswith(b"%PDF"):
        return "PDF"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE compound (legacy Office / MSG)"
    if head.startswith(b"Rar!"):
        return "RAR"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip"
    if head.startswith(b"\x1f\x8b"):
        return "GZIP"
    if head.startswith(b"{\\rtf"):
        return "RTF"
    if head.startswith(b"\x7fELF"):
        return "ELF executable"
    if head.startswith(b"\x89PNG"):
        return "PNG"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if head.startswith(b"GIF8"):
        return "GIF"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "Windows shortcut (LNK)"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "ISO 9660 image"
    if low.startswith((b"<!doctype html", b"<html", b"<head", b"<script", b"<body")) or b"<html" in low:
        return "HTML"
    if low.startswith(b"<svg") or (low.startswith(b"<?xml") and b"<svg" in data[:2048].lower()):
        return "SVG"
    return "unknown"


def _ext(name: str) -> str:
    name = (name or "").lower().strip().rstrip(".")
    return name.rsplit(".", 1)[-1] if "." in name else ""


def analyze_attachment(att: dict) -> dict:
    data, name = att.get("data") or b"", att.get("filename") or "unnamed"
    ext = _ext(name)
    mt = magic_type(data)
    flags, notes, archive = [], [], None

    if "‮" in name or "‭" in name:
        flags.append("rtlo")
    if ext in DANGEROUS_EXT:
        flags.append("dangerous")
    if ext in MACRO_EXT:
        flags.append("macro")
    if ext in HTML_EXT or mt in ("HTML", "SVG"):
        flags.append("html")
    if re.search(r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|csv|zip|html?)[\s_]*\.[a-z0-9]{2,5}$", name, re.I) \
            and (ext in DANGEROUS_EXT or ext in HTML_EXT or ext in MACRO_EXT):
        flags.append("double_ext")
    if re.search(r"\s{4,}\.\w+$", name):
        flags.append("double_ext")

    mismatch = None
    if mt == "PE executable" and ext not in PE_EXT:
        mismatch = f"content is a Windows executable but extension is .{ext or '(none)'}"
    elif mt == "ZIP container" and ext not in ZIP_CONTAINER_EXT:
        mismatch = f"content is a ZIP archive but extension is .{ext or '(none)'}"
    elif mt == "PDF" and ext != "pdf":
        mismatch = f"content is PDF but extension is .{ext or '(none)'}"
    elif mt in ("HTML", "SVG") and ext not in HTML_EXT and ext not in ("txt", "xml"):
        mismatch = f"content is {mt} but extension is .{ext or '(none)'}"
    elif mt == "ISO 9660 image" and ext not in ("iso", "img"):
        mismatch = f"content is a disk image but extension is .{ext or '(none)'}"
    if mismatch:
        flags.append("magic_mismatch")
        notes.append(mismatch)

    if mt == "ZIP container":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()[:500]
                names = [i.filename for i in infos]
                encrypted = any(i.flag_bits & 0x1 for i in infos)
                inner_bad = [n for n in names if _ext(n) in DANGEROUS_EXT | MACRO_EXT | HTML_EXT
                             or _ext(n) in ARCHIVE_EXT]
                if any("vbaproject.bin" in n.lower() for n in names):
                    if "macro" not in flags:
                        flags.append("macro")
                    notes.append("OOXML document contains vbaProject.bin (VBA macros)")
                if ext not in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "xltx", "potx",
                               "odt", "ods", "odp", "epub", "vsdx"):
                    archive = {"entries": names[:50], "entry_count": len(zf.infolist()),
                               "encrypted": encrypted, "risky_entries": inner_bad[:20]}
                    if encrypted:
                        flags.append("encrypted_archive")
                    if any(_ext(n) in DANGEROUS_EXT | MACRO_EXT | HTML_EXT for n in inner_bad):
                        flags.append("archive_dangerous")
        except zipfile.BadZipFile:
            notes.append("ZIP header present but archive is corrupt / truncated")
    elif ext in ARCHIVE_EXT or mt in ("RAR", "7-Zip", "GZIP"):
        archive = {"entries": [], "entry_count": None, "encrypted": None, "risky_entries": []}
        notes.append(f"{mt if mt != 'unknown' else ext.upper()} archive — contents not inspected (only ZIP is)")

    if archive is not None and "archive" not in flags:
        flags.append("archive")

    if mt.startswith("OLE") and (ext in LEGACY_OFFICE_EXT or ext == ""):
        if "_VBA_PROJECT".encode("utf-16-le") in data or b"_VBA_PROJECT" in data:
            flags.append("macro")
            notes.append("Legacy Office file contains a VBA project stream")
        else:
            notes.append("Legacy Office (OLE) format — macros possible; no VBA stream marker found")

    return {
        "filename": name, "extension": ext, "content_type": att.get("content_type", ""),
        "inline": att.get("inline", False), "size": len(data), "magic": mt,
        "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "flags": sorted(set(flags)), "notes": notes, "archive": archive,
    }


# --------------------------------------------------------------------------- #
# Body
# --------------------------------------------------------------------------- #
def analyze_body(text: str) -> dict:
    low = (text or "").lower()
    hits = {}
    for group, words in KEYWORDS.items():
        found = [w for w in words if re.search(r"(?<!\w)" + re.escape(w.lower()) + r"(?!\w)", low)]
        hits[group] = found
    return {"keyword_hits": hits, "length": len(text or ""), "word_count": len(re.findall(r"\w+", text or ""))}


# --------------------------------------------------------------------------- #
# IOCs
# --------------------------------------------------------------------------- #
def collect_iocs(identity, trace, urls, attachments, body_text) -> list[dict]:
    iocs, seen = [], set()

    def add(t, v, ctx):
        v = (v or "").strip()
        if not v:
            return
        key = (t, v.lower())
        if key in seen:
            return
        seen.add(key)
        iocs.append({"type": t, "value": v, "context": ctx})

    if trace.get("origin"):
        add("ip", trace["origin"]["ip"], f"Origin (hop {trace['origin']['hop']})")
        h = trace["origin"].get("helo", "")
        if h and "." in h and not h.startswith("[") and not is_ip(h):
            add("domain", h.lower(), "Origin HELO")
    for h in trace.get("hops", []):
        for i in h["ips"]:
            if i["class"] == "public":
                add("ip", i["ip"], f"Received hop {h['index']}")
    for i in trace.get("originating_ips", []):
        if i["class"] == "public":
            add("ip", i["ip"], i["header"])

    for addr, ctx in [(identity.get("from_addr"), "From"), (identity.get("return_path"), "Return-Path"),
                      (identity.get("sender"), "Sender")] + [(r, "Reply-To") for r in identity.get("reply_to", [])]:
        if addr:
            add("email", addr, ctx)
            add("domain", domain_of(addr), f"{ctx} domain")
    if identity.get("display_name_email"):
        add("email", identity["display_name_email"], "Display name")

    for u in urls:
        add("url", u["url"], ", ".join(u["sources"]))
        if u["host"]:
            add("ip" if is_ip(u["host"]) else "domain", u["host"], "URL host")

    for a in attachments:
        add("filename", a["filename"], "Attachment")
        add("sha256", a["sha256"], a["filename"])
        add("md5", a["md5"], a["filename"])
        add("sha1", a["sha1"], a["filename"])

    for e in EMAIL_RE.findall(body_text or "")[:50]:
        add("email", e.lower(), "Body")
    for ip in find_ips(body_text or "")[:50]:
        if classify_ip(ip) == "public":
            add("ip", ip, "Body")
    return iocs
