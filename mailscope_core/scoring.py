"""Rule-based risk scoring. Every point in the score is explained by a finding."""
from __future__ import annotations

import re

from .common import org_domain
from .config import LEVELS, SUSPICIOUS_MAILERS, WEIGHTS

CATEGORIES = ["Authentication", "Sender identity", "Routing", "Links", "Attachments", "Content"]


def _sev(w):
    if w < 0:
        return "positive"
    if w >= 20:
        return "high"
    if w >= 10:
        return "medium"
    if w > 0:
        return "low"
    return "info"


def score_report(r: dict) -> dict:
    F = []

    def add(key, cat, title, detail="", evidence=None):
        w = WEIGHTS.get(key, 0)
        F.append({"id": key, "category": cat, "title": title, "detail": detail,
                  "weight": w, "severity": _sev(w), "evidence": (evidence or [])[:8]})

    auth, ident, trace = r["auth"], r["identity"], r["trace"]
    urls, atts, body, html = r["urls"], r["attachments"], r["body"], r["html"]

    # ---------------- Authentication ----------------
    evaluable = bool(auth["raw"] or auth.get("received_spf") or trace["hop_count"])
    res = lambda m: ((auth.get(m) or {}).get("result") or "").lower()  # noqa: E731
    spf, dkim, dmarc = res("spf"), res("dkim"), res("dmarc")
    if not evaluable:
        add("info_noauth", "Authentication", "Authentication not evaluable",
            "No transport headers present, so SPF/DKIM/DMARC could not be checked.")
    else:
        if spf in ("fail", "hardfail"):
            add("spf_fail", "Authentication", "SPF failed", "Sending IP is not authorised by the envelope domain.")
        elif spf == "softfail":
            add("spf_softfail", "Authentication", "SPF softfail", "Sending IP is probably not authorised (~all).")
        elif spf == "neutral":
            add("spf_neutral", "Authentication", "SPF neutral")
        elif spf in ("temperror", "permerror"):
            add("spf_error", "Authentication", f"SPF {spf}", "Broken or unreachable SPF record.")
        elif not spf or spf == "none":
            add("spf_missing", "Authentication", "No SPF result", "No SPF record or no verdict recorded.")

        if dkim in ("fail", "permerror", "neutral", "policy"):
            add("dkim_fail", "Authentication", f"DKIM {dkim}", "Signature invalid — body or headers changed, or forged.")
        elif not dkim or dkim == "none":
            add("dkim_missing", "Authentication", "No valid DKIM signature")

        if dmarc == "fail":
            add("dmarc_fail", "Authentication", "DMARC failed",
                "The visible From domain is not aligned with a passing SPF or DKIM — classic spoofing signal.")
        elif not dmarc or dmarc == "none":
            add("dmarc_missing", "Authentication", "No DMARC result")

        if dkim == "pass" and ident["dkim_domains"] and ident["from_domain"] and \
                not any(org_domain(d) == org_domain(ident["from_domain"]) for d in ident["dkim_domains"]):
            add("dkim_unaligned", "Authentication", "DKIM signed by a third-party domain",
                "Signature is valid but belongs to another domain (ESP or attacker infrastructure).",
                ident["dkim_domains"])

        if spf == "pass" and dkim == "pass" and dmarc in ("pass", "bestguesspass"):
            add("auth_all_pass", "Authentication", "SPF, DKIM and DMARC all pass",
                "Strong evidence the mail really comes from the From domain (not that the domain is benign).")

    # ---------------- Sender identity ----------------
    for c in ident["checks"]:
        if c["aligned"]:
            continue
        if c["code"] == "replyto":
            add("replyto_mismatch", "Sender identity", "Reply-To goes to a different domain",
                "Replies are diverted away from the apparent sender.", [f"{c['a']} ≠ {c['b']}"])
        elif c["code"] == "returnpath":
            add("returnpath_mismatch", "Sender identity", "Envelope sender differs from From",
                "Common with ESPs/newsletters, but also with spoofing.", [f"{c['a']} ≠ {c['b']}"])
        elif c["code"] == "msgid":
            add("msgid_mismatch", "Sender identity", "Message-ID domain differs from From", "",
                [f"{c['a']} ≠ {c['b']}"])
    if ident["display_name_email"]:
        add("display_name_email_spoof", "Sender identity", "Display name contains a different address",
            "The display name shows an address that is not the real sender.",
            [f"shown: {ident['display_name_email']}", f"real: {ident['from_addr']}"])
    if ident["impersonated_brands"]:
        add("brand_impersonation", "Sender identity", "Display name impersonates a brand",
            f"Display name mentions a brand that the sending domain ({ident['from_domain']}) does not belong to.",
            ident["impersonated_brands"])
    if ident["lookalike_brands"]:
        add("lookalike_domain", "Sender identity", "Look-alike sender domain",
            "A sender/envelope/reply domain embeds or typosquats a brand inside a different registrable domain.",
            ident["lookalike_brands"])
    if ident["free_mail"] and (ident["impersonated_brands"] or re.search(
            r"(support|security|billing|account|service|team|admin|helpdesk|it dept|payroll|hr)",
            ident["from_name"] or "", re.I)):
        add("freemail_brand", "Sender identity", "Corporate-looking sender on free webmail", "",
            [f"{ident['from_name']} <{ident['from_addr']}>"])

    # ---------------- Routing ----------------
    if not ident["message_id"]:
        add("missing_message_id", "Routing", "Missing Message-ID", "Legitimate MTAs always add one.")
    if not r["summary"].get("date"):
        add("missing_date", "Routing", "Missing Date header")
    codes = [a["code"] for a in trace["anomalies"]]
    if "time_travel" in codes:
        add("time_travel", "Routing", "Received timestamps go backwards",
            "", [a["text"] for a in trace["anomalies"] if a["code"] == "time_travel"])
    if "date_anomaly" in codes:
        add("date_anomaly", "Routing", "Date header inconsistent with delivery",
            "", [a["text"] for a in trace["anomalies"] if a["code"] == "date_anomaly"])
    if "no_rdns" in codes:
        add("no_rdns", "Routing", "Origin IP has no reverse DNS", "Typical of compromised hosts and botnets.",
            [trace["origin"]["ip"]] if trace.get("origin") else [])
    if evaluable and trace["hop_count"] == 0:
        add("no_received", "Routing", "No Received headers", "Headers look hand-crafted or stripped.")
    mailer = (ident.get("x_mailer") or "").lower()
    bad = [m for m in SUSPICIOUS_MAILERS if m in mailer]
    if bad:
        add("suspicious_mailer", "Routing", "Bulk / script mailer", "", [ident["x_mailer"]])
    spam_gw = [g for g in trace.get("gateway_verdicts", []) if g.get("spam")]
    if spam_gw:
        add("gateway_spam", "Routing", "A mail gateway already marked this as spam", "",
            [f"{g['source']}: {g['summary']}" for g in spam_gw])

    # ---------------- Links ----------------
    url_rules = [("mismatch", "url_mismatch", "Link text points somewhere else",
                  "The visible text shows one domain, the link goes to another."),
                 ("js_scheme", "url_js_scheme", "Script / data URI links", ""),
                 ("ip_host", "url_ip_host", "Links to raw IP addresses", ""),
                 ("punycode", "url_punycode", "Punycode (IDN) domains", "Possible homograph attack."),
                 ("userinfo", "url_userinfo", "URL uses '@' to hide the real host", ""),
                 ("free_hosting", "url_free_hosting", "Links to free hosting platforms",
                  "Frequently abused for credential-phishing pages."),
                 ("brand_host", "url_brand_host", "Brand name inside a non-brand domain", ""),
                 ("shortener", "url_shortener", "URL shorteners hide the destination", ""),
                 ("susp_tld", "url_susp_tld", "High-abuse top-level domains", ""),
                 ("cred_keywords", "url_cred_keywords", "Login / verify keywords in links", ""),
                 ("no_tls", "url_no_tls", "Unencrypted HTTP links", "")]
    for flag, key, title, detail in url_rules:
        hit = [u for u in urls if flag in u["flags"]]
        if hit:
            ev = [(u["url"] + (f"  (text shows {', '.join(u['shown_domains'])})" if flag == "mismatch" else ""))
                  for u in hit]
            add(key, "Links", f"{title} ({len(hit)})", detail, ev)
    if html.get("forms"):
        add("html_form", "Links", "HTML form inside the email",
            "Forms in email bodies are used to harvest credentials directly.", html["forms"])
    if html.get("meta_refresh"):
        add("meta_refresh", "Links", "Meta-refresh redirect", "", html["meta_refresh"])

    # ---------------- Attachments ----------------
    att_rules = [("dangerous", "att_dangerous", "Executable / script attachment"),
                 ("double_ext", "att_double_ext", "Double or padded file extension"),
                 ("rtlo", "att_rtlo", "Right-to-left override in filename"),
                 ("archive_dangerous", "att_archive_dangerous", "Archive contains risky files"),
                 ("macro", "att_macro", "Macro-enabled Office document"),
                 ("html", "att_html", "HTML / SVG attachment (common phishing lure)"),
                 ("encrypted_archive", "att_encrypted_archive", "Password-protected archive (evades scanning)"),
                 ("magic_mismatch", "att_magic_mismatch", "File content does not match its extension"),
                 ("archive", "att_archive", "Archive attachment")]
    for flag, key, title in att_rules:
        hit = [a for a in atts if flag in a["flags"]]
        if hit:
            ev = []
            for a in hit:
                extra = ""
                if flag == "magic_mismatch":
                    extra = " — " + "; ".join(n for n in a["notes"] if "content is" in n)
                if flag == "archive_dangerous" and a.get("archive"):
                    extra = " → " + ", ".join(a["archive"]["risky_entries"][:5])
                ev.append(a["filename"] + extra)
            add(key, "Attachments", title, "", ev)

    # ---------------- Content ----------------
    kh = body["keyword_hits"]
    if len(kh.get("credential", [])) >= 1 and (urls or html.get("forms")):
        add("kw_credential", "Content", "Asks for credentials / verification", "", kh["credential"])
    if len(kh.get("urgency", [])) >= 2 or (kh.get("urgency") and kh.get("credential")):
        add("kw_urgency", "Content", "Urgency / threat language", "", kh["urgency"])
    if len(kh.get("financial", [])) >= 2:
        add("kw_financial", "Content", "Payment / financial pressure", "", kh["financial"])
    if kh.get("generic_greeting"):
        add("kw_generic_greeting", "Content", "Generic greeting", "", kh["generic_greeting"])
    subj = (r["summary"].get("subject") or "").strip()
    if re.match(r"^(re|fw|fwd|aw|wg|odp|sv|vs)\s*:", subj, re.I) and not r["summary"].get("in_reply_to") \
            and not r["summary"].get("references"):
        add("fake_reply", "Content", "Fake reply / forward",
            "Subject claims to be a reply but there is no In-Reply-To / References thread.", [subj])
    if atts and body["word_count"] < 15 and any(not a["inline"] for a in atts):
        add("attachment_no_body", "Content", "Attachment with (almost) no message text")
    if html.get("hidden_elements", 0) >= 3:
        add("hidden_text", "Content", "Hidden HTML elements",
            "Hidden text is used to poison spam filters.", [f"{html['hidden_elements']} hidden elements"])

    raw = sum(f["weight"] for f in F)
    score = max(0, min(100, raw))
    level, label = "low", "Low risk"
    for threshold, lvl, lab in LEVELS:
        if score >= threshold:
            level, label = lvl, lab
            break
    totals = {c: sum(f["weight"] for f in F if f["category"] == c and f["weight"] > 0) for c in CATEGORIES}
    order = {"high": 0, "medium": 1, "low": 2, "info": 3, "positive": 4}
    F.sort(key=lambda f: (order[f["severity"]], -abs(f["weight"])))
    return {"score": score, "raw_points": raw, "level": level, "verdict": label,
            "findings": F, "category_totals": totals}
