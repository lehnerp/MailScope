"""Load .eml and Outlook .msg files into one normalised structure.

Normalised mail dict:
    format       "EML" | "MSG"
    headers      [(name, decoded value), ...]  in original order (top = newest)
    body_text    str
    body_html    str
    attachments  [{filename, content_type, data(bytes), inline(bool)}]
    notes        [str]   parser remarks shown in the report
"""
from __future__ import annotations

import os
import re
import tempfile
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _clean(value) -> str:
    value = "" if value is None else str(value)
    try:
        value = str(make_header(decode_header(value)))
    except Exception:
        pass
    return re.sub(r"\r?\n[ \t]+", " ", value).replace("\r", "").replace("\n", " ").strip()


def _base(fmt: str) -> dict:
    return {"format": fmt, "headers": [], "body_text": "", "body_html": "", "attachments": [], "notes": []}


def load_mail(data: bytes, filename: str = "") -> dict:
    is_ole = data[:8] == OLE_MAGIC
    if filename.lower().endswith(".msg") and not is_ole:
        # Some tools save RFC-822 text with a .msg extension
        mail = _load_eml(data)
        mail["notes"].append("File has a .msg extension but is plain RFC-822 text; parsed as EML.")
        return mail
    if is_ole:
        return _load_msg(data)
    return _load_eml(data)


# --------------------------------------------------------------------------- #
# EML
# --------------------------------------------------------------------------- #
def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")


def _iter_parts(part):
    """Like walk(), but does not descend into attached messages."""
    if part.get_content_type() == "message/rfc822" and part.is_multipart():
        yield part
        return
    if part.is_multipart():
        for sub in part.iter_parts():
            yield from _iter_parts(sub)
    else:
        yield part


def _load_eml(data: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    mail = _base("EML")
    mail["headers"] = [(k, _clean(v)) for k, v in msg.raw_items()]
    if not mail["headers"]:
        mail["notes"].append("No RFC-822 headers found — is this really an email file?")

    texts, htmls = [], []
    for part in _iter_parts(msg):
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        try:
            fname = part.get_filename()
        except Exception:
            fname = None
        fname = _clean(fname) if fname else None

        if ctype == "message/rfc822":
            try:
                inner = part.get_payload()[0]
                payload = inner.as_bytes()
                subj = _clean(inner.get("Subject", "attached message"))
            except Exception:
                payload, subj = b"", "attached message"
            mail["attachments"].append({
                "filename": fname or (re.sub(r"[^\w\- ]", "_", subj)[:60] + ".eml"),
                "content_type": ctype, "data": payload, "inline": False,
            })
            continue

        if ctype in ("text/plain", "text/html") and disp != "attachment" and not fname:
            (texts if ctype == "text/plain" else htmls).append(_part_text(part))
            continue

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        mail["attachments"].append({
            "filename": fname or f"unnamed.{ctype.split('/')[-1]}",
            "content_type": ctype, "data": payload, "inline": disp == "inline",
        })

    mail["body_text"] = "\n".join(texts)
    mail["body_html"] = "\n".join(htmls)
    if msg.defects:
        mail["notes"].append("MIME defects: " + ", ".join(type(d).__name__ for d in msg.defects[:6]))
    return mail


# --------------------------------------------------------------------------- #
# MSG (Outlook)
# --------------------------------------------------------------------------- #
def _try(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _load_msg(data: bytes) -> dict:
    try:
        import extract_msg  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Outlook .msg support needs the 'extract-msg' package: pip install extract-msg") from exc

    fd, path = tempfile.mkstemp(suffix=".msg")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        m = extract_msg.openMsg(path)
        try:
            mail = _base("MSG")
            hdr = _try(lambda: m.header)
            if hdr is not None and len(hdr.keys()) > 0:
                mail["headers"] = [(k, _clean(v)) for k, v in hdr.items()]
            else:
                mail["notes"].append(
                    "MSG has no transport headers (draft, sent-items copy or internal Exchange message) — "
                    "routing trace and SPF/DKIM/DMARC cannot be evaluated."
                )

            def ensure(name, value):
                if value and not any(h[0].lower() == name.lower() for h in mail["headers"]):
                    mail["headers"].append((name, _clean(value)))

            ensure("Subject", _try(lambda: m.subject))
            ensure("From", _try(lambda: m.sender))
            ensure("To", _try(lambda: m.to))
            ensure("Cc", _try(lambda: m.cc))
            ensure("Date", _try(lambda: str(m.date) if m.date else ""))
            ensure("Message-ID", _try(lambda: m.messageId))

            mail["body_text"] = _try(lambda: m.body, "") or ""
            html = _try(lambda: m.htmlBody, "")
            if isinstance(html, bytes):
                html = html.decode("utf-8", errors="replace")
            mail["body_html"] = html or ""

            for att in _try(lambda: m.attachments, []) or []:
                name = (_try(lambda: att.longFilename) or _try(lambda: att.shortFilename)
                        or _try(lambda: att.name) or "attachment.bin")
                payload = _try(lambda: att.data)
                if isinstance(payload, bytes):
                    blob = payload
                else:  # embedded .msg or OLE object
                    blob = b""
                    if payload is not None and hasattr(payload, "exportBytes"):
                        blob = _try(payload.exportBytes, b"") or b""
                    if not str(name).lower().endswith(".msg"):
                        name = f"{name}.msg"
                mail["attachments"].append({
                    "filename": str(name),
                    "content_type": _try(lambda: att.mimetype) or "application/octet-stream",
                    "data": blob, "inline": False,
                })
        finally:
            _try(m.close)
    finally:
        _try(lambda: os.unlink(path))
    return mail
