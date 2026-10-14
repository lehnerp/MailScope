"""MailScope – local MSG/EML analyser dashboard.

    pip install -r requirements.txt
    python app.py            -> http://127.0.0.1:5000
"""
from __future__ import annotations

import csv
import io
import json
import os
from urllib.parse import quote

import sys

# Always import MailScope's own modules from this folder, never from site-packages.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_REQUIRED = ["mailscope_core/__init__.py", "mailscope_core/parser.py", "mailscope_core/trace.py",
             "mailscope_core/indicators.py", "mailscope_core/scoring.py", "mailscope_core/config.py",
             "mailscope_core/common.py", "storage.py", "templates/report.html", "static/style.css"]
_missing = [f for f in _REQUIRED if not os.path.isfile(os.path.join(_HERE, f))]
if _missing:
    sys.exit("MailScope files are missing from " + _HERE + ":\n  " + "\n  ".join(_missing)
             + "\nRe-extract the full mailscope.zip into this folder.")

from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template, request,  # noqa: E402
                   send_file, url_for)

from mailscope_core import __version__, analyze  # noqa: E402
from mailscope_core.common import defang  # noqa: E402
from mailscope_core.config import NOISY_DOMAINS, URL_SHORTENERS  # noqa: E402
from mailscope_core.scoring import CATEGORIES  # noqa: E402
from storage import Store  # noqa: E402

NOISY = set(NOISY_DOMAINS) | set(URL_SHORTENERS)

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("MAILSCOPE_DATA", os.path.join(BASE, "data"))
UPLOADS = os.path.join(DATA, "originals")
os.makedirs(UPLOADS, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "60")) * 1024 * 1024
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
store = Store(os.path.join(DATA, "mailscope.db"))
ALLOWED = (".eml", ".msg", ".txt", ".mht")


# --------------------------------------------------------------------------- #
# Template helpers
# --------------------------------------------------------------------------- #
def lookups(kind: str, value: str):
    v = quote(value or "", safe="")
    if kind == "ip":
        return [("AbuseIPDB", f"https://www.abuseipdb.com/check/{v}"),
                ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{v}"),
                ("Shodan", f"https://www.shodan.io/host/{v}"),
                ("GreyNoise", f"https://viz.greynoise.io/ip/{v}"),
                ("ipinfo", f"https://ipinfo.io/{v}")]
    if kind == "domain":
        return [("VirusTotal", f"https://www.virustotal.com/gui/domain/{v}"),
                ("urlscan", f"https://urlscan.io/search/#domain:{v}"),
                ("Whois", f"https://who.is/whois/{v}"),
                ("MXToolbox", f"https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a{v}")]
    if kind == "url":
        return [("VirusTotal", f"https://www.virustotal.com/gui/search/{quote(quote(value, safe=''), safe='')}"),
                ("urlscan", f"https://urlscan.io/search/#page.url:{v}")]
    if kind in ("sha256", "md5", "sha1"):
        out = [("VirusTotal", f"https://www.virustotal.com/gui/file/{v}"),
               ("Hybrid Analysis", f"https://www.hybrid-analysis.com/search?query={v}")]
        if kind == "sha256":
            out.append(("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{v}"))
        return out
    if kind == "email":
        dom = value.split("@")[-1]
        return [("Domain on VT", f"https://www.virustotal.com/gui/domain/{quote(dom)}")]
    return []


def fmt_bytes(n):
    n = n or 0
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_delay(s):
    if s is None:
        return "–"
    sign = "-" if s < 0 else ""
    s = abs(s)
    if s < 60:
        return f"{sign}{s}s"
    if s < 3600:
        return f"{sign}{s // 60}m {s % 60}s"
    return f"{sign}{s // 3600}h {(s % 3600) // 60}m"


app.jinja_env.globals.update(lookups=lookups, CATEGORIES=CATEGORIES, version=__version__)
app.jinja_env.filters.update(fmt_bytes=fmt_bytes, fmt_delay=fmt_delay, defang=defang)


@app.after_request
def security_headers(resp):
    # img-src 'self' data: means the sandboxed HTML preview cannot fetch remote
    # images / tracking pixels, so opening a report never "phones home".
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    return resp


def _get_or_404(aid):
    rec = store.get(aid)
    if not rec:
        abort(404)
    return rec


def _original_path(sha256):
    return os.path.join(UPLOADS, sha256)  # no extension: never directly executable


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    q = request.args.get("q", "").strip()
    level = request.args.get("level", "")
    return render_template("index.html", rows=store.list(q, level), stats=store.stats(NOISY), q=q, level=level)


@app.post("/upload")
def upload():
    files = [f for f in request.files.getlist("files") if f and f.filename]
    rdns = bool(request.form.get("rdns"))
    force = bool(request.form.get("force"))
    if not files:
        flash("Choose at least one .eml or .msg file.", "error")
        return redirect(url_for("index"))
    ids = []
    for f in files:
        name = os.path.basename(f.filename)
        if not name.lower().endswith(ALLOWED):
            flash(f"{name}: unsupported file type (use .eml or .msg).", "error")
            continue
        data = f.read()
        if not data:
            flash(f"{name}: file is empty.", "error")
            continue
        try:
            report = analyze(data, name, rdns=rdns)
        except Exception as exc:  # noqa: BLE001
            flash(f"{name}: could not be parsed – {exc}", "error")
            continue
        sha = report["file"]["sha256"]
        existing = store.find_by_sha(sha)
        if existing and not force:
            flash(f"{name} was already analysed – showing the existing report (tick 'Re-analyse duplicates' to redo).", "info")
            ids.append(existing)
            continue
        path = _original_path(sha)
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(data)
        ids.append(store.save(report, existing if (existing and force) else None))
    if len(ids) == 1:
        return redirect(url_for("report", aid=ids[0]))
    if ids:
        flash(f"Analysed {len(ids)} files.", "info")
    return redirect(url_for("index"))


@app.get("/report/<aid>")
def report(aid):
    rec = _get_or_404(aid)
    related = store.related(aid, NOISY)
    return render_template("report.html", rec=rec, r=rec["report"], related=related)


@app.post("/report/<aid>/reanalyze")
def reanalyze(aid):
    rec = _get_or_404(aid)
    path = _original_path(rec["sha256"])
    if not os.path.exists(path):
        flash("Original file is no longer stored; upload it again.", "error")
        return redirect(url_for("report", aid=aid))
    with open(path, "rb") as fh:
        data = fh.read()
    report_ = analyze(data, rec["filename"], rdns=bool(request.form.get("rdns")))
    store.save(report_, aid)
    flash("Re-analysed with the current rules.", "info")
    return redirect(url_for("report", aid=aid))


@app.post("/report/<aid>/delete")
def delete(aid):
    rec = _get_or_404(aid)
    store.delete(aid)
    if not store.find_by_sha(rec["sha256"]):
        try:
            os.remove(_original_path(rec["sha256"]))
        except OSError:
            pass
    flash(f"Deleted {rec['filename']}.", "info")
    return redirect(url_for("index"))


@app.get("/search")
def search():
    q = request.args.get("q", "").strip()
    rows = store.search_iocs(q) if len(q) >= 3 else []
    return render_template("search.html", q=q, rows=rows)


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #
@app.get("/report/<aid>/report.json")
def export_json(aid):
    rec = _get_or_404(aid)
    body = json.dumps(rec["report"], indent=2, ensure_ascii=False)
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="mailscope_{aid}.json"'})


@app.get("/report/<aid>/iocs.csv")
def export_iocs(aid):
    rec = _get_or_404(aid)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "defanged", "context", "source_file", "score", "verdict"])
    for i in rec["report"]["iocs"]:
        w.writerow([i["type"], i["value"], defang(i["value"]) if i["type"] in ("url", "domain", "ip", "email") else i["value"],
                    i["context"], rec["filename"], rec["score"], rec["verdict"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="iocs_{aid}.csv"'})


@app.get("/report/<aid>/headers.txt")
def export_headers(aid):
    rec = _get_or_404(aid)
    text = "\n".join(f"{h['name']}: {h['value']}" for h in rec["report"]["headers"])
    return Response(text, mimetype="text/plain; charset=utf-8")


@app.get("/report/<aid>/original")
def download_original(aid):
    rec = _get_or_404(aid)
    path = _original_path(rec["sha256"])
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=rec["filename"] + ".quarantine",
                     mimetype="application/octet-stream")


@app.get("/export/all.csv")
def export_all():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "uploaded_at", "filename", "subject", "sender", "origin_ip", "score", "verdict"])
    for r in store.list(limit=100000):
        w.writerow([r["id"], r["uploaded_at"], r["filename"], r["subject"], r["sender"], r["origin_ip"],
                    r["score"], r["verdict"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="mailscope_cases.csv"'})


# --------------------------------------------------------------------------- #
# JSON API (for scripts / SOAR):  curl -F file=@mail.eml http://127.0.0.1:5000/api/analyze?save=1
# --------------------------------------------------------------------------- #
@app.post("/api/analyze")
def api_analyze():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="send the email as multipart field 'file'"), 400
    data = f.read()
    try:
        rep = analyze(data, os.path.basename(f.filename), rdns=request.args.get("rdns") == "1")
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=str(exc)), 422
    if request.args.get("save") == "1":
        path = _original_path(rep["file"]["sha256"])
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(data)
        rep["id"] = store.save(rep)
    rep["body"].pop("html", None)
    return jsonify(rep)


@app.errorhandler(413)
def too_large(_):
    flash("File too large (raise MAX_UPLOAD_MB).", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    print(f" MailScope {__version__}  ->  http://{host}:{port}")
    app.run(host=host, port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
