"""Small shared helpers."""
from __future__ import annotations

import ipaddress
import re

from .config import MULTI_LABEL_TLDS

IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
)
IPV6_CAND_RE = re.compile(r"(?<![0-9A-Za-z:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")


def get_header(headers, name, default=""):
    n = name.lower()
    for k, v in headers:
        if k.lower() == n:
            return v
    return default


def get_all(headers, name):
    n = name.lower()
    return [v for k, v in headers if k.lower() == n]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip("[]"))
        return True
    except ValueError:
        return False


def classify_ip(ip: str) -> str:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if obj.is_loopback:
        return "loopback"
    if obj.is_private or obj.is_link_local:
        return "private"
    if obj.is_global:
        return "public"
    return "reserved"


def find_ips(text: str) -> list[str]:
    out: list[str] = []
    for m in IPV4_RE.finditer(text or ""):
        if m.group(0) not in out:
            out.append(m.group(0))
    for m in IPV6_CAND_RE.finditer(text or ""):
        cand = m.group(1)
        if cand.count(":") < 2:
            continue
        try:
            norm = str(ipaddress.IPv6Address(cand))
        except ValueError:
            continue
        if norm not in out:
            out.append(norm)
    return out


def domain_of(addr: str) -> str:
    addr = (addr or "").strip().strip("<>").lower()
    return addr.rsplit("@", 1)[1].strip(" >.") if "@" in addr else ""


def org_domain(host: str) -> str:
    """Naive registrable-domain extraction (no network / PSL download needed)."""
    host = (host or "").lower().strip(" .[]")
    if not host or is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_LABEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def org_label(host: str) -> str:
    """'mail.paypal-secure.com' -> 'paypal-secure'"""
    od = org_domain(host)
    return od.split(".")[0] if od and not is_ip(od) else ""


def defang(value: str) -> str:
    v = re.sub(r"^http", "hxxp", value or "", flags=re.I)
    return v.replace(".", "[.]").replace("://", "[://]").replace("@", "[@]")
