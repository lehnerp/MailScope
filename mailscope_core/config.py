"""Tunable lists and scoring weights.

Everything that decides *how suspicious* something is lives here so you can
adapt MailScope to your environment without touching the analysis code.
"""

# --------------------------------------------------------------------------- #
# Scoring weights (points added to the 0-100 risk score; negative = trust)
# --------------------------------------------------------------------------- #
WEIGHTS = {
    # Authentication
    "spf_fail": 15, "spf_softfail": 8, "spf_neutral": 4, "spf_missing": 4, "spf_error": 3,
    "dkim_fail": 15, "dkim_missing": 4,
    "dmarc_fail": 20, "dmarc_missing": 4,
    "dkim_unaligned": 5,
    "auth_all_pass": -10,
    # Sender identity
    "replyto_mismatch": 12,
    "returnpath_mismatch": 8,
    "msgid_mismatch": 3,
    "display_name_email_spoof": 15,
    "brand_impersonation": 12,
    "lookalike_domain": 10,
    "freemail_brand": 8,
    # Routing / headers
    "missing_message_id": 5,
    "missing_date": 3,
    "date_anomaly": 5,
    "time_travel": 6,
    "no_received": 4,
    "no_rdns": 4,
    "suspicious_mailer": 6,
    "gateway_spam": 12,
    # URLs / HTML
    "url_mismatch": 18,
    "url_js_scheme": 15,
    "url_ip_host": 12,
    "url_punycode": 12,
    "url_userinfo": 10,
    "url_free_hosting": 8,
    "url_brand_host": 8,
    "url_shortener": 6,
    "url_susp_tld": 6,
    "url_cred_keywords": 4,
    "url_no_tls": 2,
    "html_form": 12,
    "meta_refresh": 6,
    # Attachments
    "att_dangerous": 35,
    "att_double_ext": 30,
    "att_rtlo": 30,
    "att_archive_dangerous": 30,
    "att_macro": 25,
    "att_html": 20,
    "att_encrypted_archive": 20,
    "att_magic_mismatch": 20,
    "att_archive": 4,
    # Content
    "kw_credential": 10,
    "kw_urgency": 8,
    "kw_financial": 6,
    "kw_generic_greeting": 4,
    "fake_reply": 6,
    "attachment_no_body": 5,
    "hidden_text": 3,
}

# Score thresholds -> (minimum score, level key, label)
LEVELS = [
    (70, "critical", "Malicious"),
    (45, "high", "Likely phishing / malicious"),
    (20, "suspicious", "Suspicious"),
    (0, "low", "Low risk"),
]

# --------------------------------------------------------------------------- #
# Domain knowledge
# --------------------------------------------------------------------------- #
MULTI_LABEL_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "co.jp", "ne.jp",
    "or.jp", "co.kr", "co.in", "co.za", "com.br", "com.cn", "com.mx", "com.tr",
    "com.sg", "com.hk", "com.tw", "com.ar", "co.il", "com.pl", "com.ua",
}

FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com",
    "me.com", "mail.com", "gmx.com", "gmx.net", "gmx.de", "web.de", "proton.me",
    "protonmail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "seznam.cz",
    "email.cz", "centrum.cz", "atlas.cz", "post.cz", "volny.cz", "tutanota.com",
}

# Domains so common that sharing them says nothing about two emails being related
NOISY_DOMAINS = FREE_MAIL | {
    "google.com", "microsoft.com", "office.com", "office365.com", "outlook.com",
    "protection.outlook.com", "apple.com", "amazonaws.com", "w3.org", "facebook.com",
    "twitter.com", "x.com", "linkedin.com", "youtube.com", "instagram.com",
}

# Brand tokens used for display-name impersonation and look-alike domains
BRANDS = [
    "paypal", "microsoft", "office365", "outlook", "onedrive", "sharepoint", "apple",
    "icloud", "amazon", "google", "netflix", "dhl", "fedex", "ups", "usps", "docusign",
    "adobe", "dropbox", "linkedin", "facebook", "instagram", "whatsapp", "wellsfargo",
    "chase", "citibank", "hsbc", "revolut", "binance", "coinbase", "booking", "airbnb",
    "zasilkovna", "csob", "airbank", "moneta", "raiffeisen", "unicredit", "ceskaposta",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "bl.ink", "s.id", "lnkd.in",
    "qrco.de", "v.gd", "shorte.st", "adf.ly",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "work", "gq", "ml", "cf", "tk", "ga",
    "country", "kim", "loan", "men", "date", "racing", "review", "stream", "download",
    "icu", "rest", "cyou", "cfd", "sbs", "buzz", "monster", "quest", "support", "live",
    "online", "site", "shop", "best", "lol",
}

# Hosting platforms often abused to host phishing pages (legit too -> moderate weight)
FREE_HOSTING = (
    "firebaseapp.com", "web.app", "pages.dev", "workers.dev", "github.io", "ngrok.io",
    "ngrok-free.app", "blogspot.com", "weebly.com", "wixsite.com", "000webhostapp.com",
    "glitch.me", "netlify.app", "vercel.app", "herokuapp.com", "r2.dev", "ipfs.io",
    "azurewebsites.net", "web.core.windows.net", "storage.googleapis.com",
    "s3.amazonaws.com", "sites.google.com", "forms.gle", "typedream.app",
    "webflow.io", "framer.app", "godaddysites.com", "square.site", "replit.app",
)

SUSPICIOUS_MAILERS = ["phpmailer", "swiftmailer", "python", "mass mailer", "sendblaster",
                      "atomic mail", "bulk", "leaf phpmailer", "gammadyne"]

# --------------------------------------------------------------------------- #
# Attachments
# --------------------------------------------------------------------------- #
DANGEROUS_EXT = {
    "exe", "scr", "pif", "com", "cpl", "msi", "msp", "dll", "bat", "cmd", "ps1", "psm1",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "reg", "iso", "img",
    "vhd", "vhdx", "one", "chm", "scf", "url", "appx", "msix", "application", "gadget",
    "xll", "inf", "sct", "settingcontent-ms", "library-ms", "apk",
}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"}
LEGACY_OFFICE_EXT = {"doc", "dot", "xls", "xlt", "ppt", "pps"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "ace", "cab", "arj", "lzh", "bz2", "xz", "z"}
HTML_EXT = {"htm", "html", "shtml", "xhtml", "svg", "mht", "mhtml", "xht"}
ZIP_CONTAINER_EXT = {
    "zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "xltx", "potx", "jar",
    "apk", "odt", "ods", "odp", "epub", "xpi", "vsdx", "appx", "msix", "kmz", "ipa",
}
PE_EXT = {"exe", "dll", "scr", "com", "sys", "cpl", "ocx", "drv", "efi", "msi"}

# --------------------------------------------------------------------------- #
# Content keywords (English + Czech). Matching is case-insensitive.
# --------------------------------------------------------------------------- #
KEYWORDS = {
    "urgency": [
        "urgent", "immediately", "as soon as possible", "within 24 hours", "within 48 hours",
        "action required", "final notice", "suspended", "will be closed", "will be deleted",
        "expires today", "last warning", "act now", "limited time", "unusual activity",
        "unusual sign-in", "account locked", "deactivated",
        "naléhavé", "okamžitě", "ihned", "do 24 hodin", "poslední upozornění",
        "zablokován", "pozastaven",
    ],
    "credential": [
        "password", "verify your", "confirm your identity", "update your account",
        "reset your password", "login details", "sign in to", "log in to",
        "credentials", "security code", "one-time code", "validate your",
        "heslo", "přihlašovací údaje", "ověřte", "přihlaste se",
    ],
    "financial": [
        "invoice", "wire transfer", "bank details", "bank account", "iban", "swift code",
        "gift card", "bitcoin", "crypto wallet", "overdue", "remittance", "purchase order",
        "refund", "payment failed", "outstanding payment",
        "faktura", "platba", "bankovní účet", "převod", "doplatek", "nezaplacen",
    ],
    "generic_greeting": [
        "dear customer", "dear user", "dear client", "dear account holder", "dear sir/madam",
        "valued customer", "dear member", "dear beneficiary",
        "vážený zákazníku", "vážený kliente", "vážený uživateli",
    ],
}
