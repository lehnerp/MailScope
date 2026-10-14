"""MailScope analysis engine: analyze(bytes, filename) -> report dict (JSON-serialisable)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from .common import get_header
from .indicators import analyze_attachment, analyze_body, collect_iocs, extract_urls, scan_html
from .parser import load_mail
from .scoring import score_report
from .trace import build_identity, build_trace, parse_auth

__version__ = "1.0.0"

MAX_TEXT = 200_000
MAX_HTML = 750_000


def analyze(data: bytes, filename: str = "message.eml", rdns: bool = False) -> dict:
    mail = load_mail(data, filename)
    headers = mail["headers"]
    g = lambda n: get_header(headers, n)  # noqa: E731

    html_info = scan_html(mail["body_html"]) if mail["body_html"] else scan_html("")
    text = mail["body_text"] or html_info["text"]
    analysis_text = "\n".join(t for t in (mail["body_text"], html_info["text"]) if t)

    trace = build_trace(headers, rdns=rdns)
    auth = parse_auth(headers)
    identity = build_identity(headers, auth)
    urls = extract_urls(mail["body_text"], html_info)
    attachments = [analyze_attachment(a) for a in mail["attachments"]]
    body = analyze_body(analysis_text + "\n" + g("Subject"))

    report = {
        "engine_version": __version__,
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "file": {"filename": filename, "size": len(data), "format": mail["format"],
                 "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest()},
        "summary": {
            "subject": g("Subject"), "from": g("From"), "to": g("To"), "cc": g("Cc"),
            "date": g("Date"), "message_id": g("Message-ID"), "in_reply_to": g("In-Reply-To"),
            "references": g("References"), "x_mailer": g("X-Mailer") or g("User-Agent"),
            "content_language": g("Content-Language"),
        },
        "headers": [{"name": k, "value": v} for k, v in headers],
        "trace": trace,
        "auth": auth,
        "identity": identity,
        "urls": urls,
        "html": {k: v for k, v in html_info.items() if k not in ("text", "links")},
        "attachments": attachments,
        "body": {**body, "text": text[:MAX_TEXT], "html": mail["body_html"][:MAX_HTML],
                 "has_html": bool(mail["body_html"])},
        "notes": mail["notes"],
    }
    report["iocs"] = collect_iocs(identity, trace, urls, attachments, analysis_text)
    report["scoring"] = score_report(report)
    return report
