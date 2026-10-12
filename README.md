# MailScope — local MSG/EML analyser

A Flask dashboard for triaging suspicious emails. Drop in `.eml` or Outlook `.msg`
files and get a **0–100 risk score** in which every point is explained by a finding, a
**delivery-path trace** back to the originating IP, SPF/DKIM/DMARC and sender-alignment
checks, link and attachment analysis, extracted **IOCs**, and **cross-case correlation**
so you can see campaigns forming. Everything runs locally; nothing is uploaded anywhere.

## Quick start

**Windows:** double-click `run_mailscope.bat`. The first run creates a `.venv`, installs
the dependencies (internet needed once) and opens the dashboard in your browser. Use
`run_mailscope.bat 8080` for another port. Requires Python 3.9+ on PATH.

**Any OS, manually:**

```bash
cd mailscope
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python samples/make_samples.py                          # optional: creates two test emails
python app.py                                           # → http://127.0.0.1:5000
```

Command line (no server): `python cli.py samples/phishing_sample.eml` — exit code 0/1/2 =
low / suspicious / high, so it can be used in scripts.

## What it analyses

| Area | Checks |
|---|---|
| **Trace** | Parses every `Received` header oldest→newest: HELO, logged rDNS, IPs (public/private), protocol, TLS, per-hop delay (UTC), total transit. Finds the **origin IP**, `X-Originating-IP`-style client IPs, backwards timestamps (forged headers), Date-vs-delivery anomalies, missing rDNS. Reads gateway verdicts (Microsoft 365 SCL/SFV/country, SpamAssassin). Optional live reverse-DNS. |
| **Authentication** | SPF / DKIM / DMARC / ARC / compauth from `Authentication-Results` (falls back to ARC and `Received-SPF`), DKIM signing domains, third-party DKIM. |
| **Identity** | Reply-To, Return-Path, Sender, Message-ID and DKIM domain alignment with From; address hidden in the display name; brand impersonation in display name; look-alike / typosquat domains (`paypa1`, `rnicrosoft`); corporate names on free webmail; script mailers (PHPMailer…). |
| **Links** | Text + HTML (`<a>`, forms, meta-refresh, resources). Link text ≠ destination, raw-IP hosts, punycode, `@` tricks, shorteners, high-abuse TLDs, free hosting (firebaseapp, pages.dev…), brand in foreign domain, credential keywords, plain HTTP. Shown defanged, never fetched. |
| **Attachments** | MD5/SHA1/SHA256, magic-byte detection vs extension, executables/scripts/LNK/ISO/OneNote, double extensions, RTLO filename tricks, macro Office files (incl. `vbaProject.bin` inside `.docx` and VBA streams in legacy `.doc`), HTML/SVG lures, ZIP listing + encrypted-archive detection. |
| **Content** | Urgency, credential, financial and generic-greeting phrases (English + Czech), fake `RE:` without a thread, hidden HTML text, attachment with no message. |

## Tracing workflow features

- **IOC tab** – IPs, domains, URLs, addresses, hashes, filenames with one-click copy, defanged bulk copy, CSV export, and lookup links (AbuseIPDB, VirusTotal, Shodan, GreyNoise, urlscan, MalwareBazaar, Hybrid Analysis…).
- **Pivot search** (top bar) – find every stored email containing an IP, domain, hash or address.
- **Related tab** – other cases sharing non-trivial indicators (free-mail and big-platform domains are ignored).
- **Recurring infrastructure** on the home page – origin IPs and domains seen in more than one suspicious case.
- **Re-analyse** – originals are kept (stored without extension) so you can re-score after tuning rules.
- **JSON API** – `curl -F file=@mail.eml "http://127.0.0.1:5000/api/analyze?save=1"`.

## Tuning the score

All weights, thresholds, brand names, keyword lists, shorteners, TLDs and hosting platforms
are in `analyzer/config.py`. Levels: 0–19 low, 20–44 suspicious, 45–69 likely phishing,
70+ malicious. Passing SPF+DKIM+DMARC subtracts 10 (it proves the sender, not that the
sender is benign). After changing weights, press **Re-analyse** on a case.

## Safety notes

- Binds to `127.0.0.1` by default. Set `HOST=0.0.0.0` only on a trusted network — there is no login.
- The HTML preview is a fully sandboxed iframe under a CSP that blocks scripts, forms and **remote images**, so viewing a report never triggers tracking pixels.
- Attachments are never written to disk individually; the original email downloads as `<name>.quarantine`.
- `.msg` files with no transport headers (drafts, Sent Items copies, internal Exchange mail) can't be traced; the report says so and doesn't penalise missing authentication.

## Settings (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Listen address |
| `MAILSCOPE_DATA` | `./data` | SQLite DB + stored originals |
| `MAX_UPLOAD_MB` | `60` | Upload size limit |
| `FLASK_DEBUG` | off | `1` for auto-reload while developing |

## Layout

```
app.py              Flask routes, exports, API
storage.py          SQLite (cases + IOC index for pivot/correlation)
cli.py              command-line analyser
analyzer/
  parser.py         EML (stdlib) and MSG (extract-msg) → one structure
  trace.py          Received chain, auth results, identity/alignment, gateway verdicts
  indicators.py     URLs, HTML, attachments, keywords, IOC extraction
  scoring.py        rule engine → score, verdict, explained findings
  config.py         weights and lists — edit this to tune
templates/ static/  dashboard UI
samples/            test-email generator
```
