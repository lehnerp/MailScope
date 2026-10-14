"""Generate two test emails: a phishing sample and a benign one.

    python samples/make_samples.py
The ZIP 'payload' only contains a harmless text stub renamed to .exe (starts with MZ).
"""
import io
import os
import zipfile
from email.message import EmailMessage

HERE = os.path.dirname(os.path.abspath(__file__))


def phishing():
    m = EmailMessage()
    received = [
        "from mx-in.example.cz (mx-in.example.cz [10.0.0.25]) by mailstore.example.cz with LMTP id a1b2; "
        "Mon, 12 Oct 2026 09:14:40 +0200",
        "from smtp.paypa1-secure-login.com (unknown [185.234.219.77]) by mx-in.example.cz (Postfix) "
        "with ESMTP id 4F2C11A0 for <jan.novak@example.cz>; Mon, 12 Oct 2026 09:14:31 +0200",
        "from localhost (localhost [127.0.0.1]) by smtp.paypa1-secure-login.com (Postfix) with ESMTP id 77AB; "
        "Mon, 12 Oct 2026 07:20:02 +0000",
    ]
    for r in received:
        m["Received"] = r
    m["Authentication-Results"] = ("mx-in.example.cz; spf=softfail (domain of transitioning "
                                   "service@paypal.com does not designate 185.234.219.77 as permitted sender) "
                                   "smtp.mailfrom=paypa1-secure-login.com; dkim=none; "
                                   "dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com")
    m["Return-Path"] = "<bounce@paypa1-secure-login.com>"
    m["From"] = '"PayPal Security service@paypal.com" <service@paypal.com>'
    m["Reply-To"] = "paypal.resolution.center@gmail.com"
    m["To"] = "jan.novak@example.cz"
    m["Subject"] = "RE: Action required: your account has been suspended"
    m["Date"] = "Mon, 12 Oct 2026 09:20:00 +0200"
    m["X-Mailer"] = "PHPMailer 6.1.4 (https://github.com/PHPMailer/PHPMailer)"
    m["X-Originating-IP"] = "[185.234.219.77]"
    m.set_content("Dear customer,\n\nWe noticed unusual activity. Your account has been suspended. "
                  "Verify your identity immediately at https://paypal.com/verify\n\nPayPal")
    m.add_alternative("""<html><body><p>Dear customer,</p>
<p>We noticed <b>unusual activity</b> on your account. It has been <b>suspended</b>.
Please verify your identity <b>within 24 hours</b> or it will be closed.</p>
<p><a href="http://185.234.219.77/paypal/login.php?id=8812">https://www.paypal.com/signin</a></p>
<p><a href="https://bit.ly/3xYz9Qp">Resolution centre</a></p>
<p><a href="https://xn--pypal-4ve.com/account/update">Update billing</a></p>
<form action="https://paypal-verify.firebaseapp.com/collect" method="post">
  <input name="email"><input name="password" type="password"><button>Sign in</button></form>
<div style="display:none">invoice refund newsletter</div>
<div style="display:none">hello world</div><div style="display:none">lorem</div>
<img src="https://tracker.paypa1-secure-login.com/p.gif" width="1" height="1">
</body></html>""", subtype="html")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Statement_Oct2026.pdf.exe", b"MZ" + b"\x00" * 64 + b"harmless test stub")
        zf.writestr("readme.txt", "open the statement")
    m.add_attachment(buf.getvalue(), maintype="application", subtype="zip", filename="Statement_Oct2026.zip")
    m.add_attachment(b"<html><script>location='https://paypal-verify.firebaseapp.com'</script></html>",
                     maintype="text", subtype="html", filename="PayPal_Secure_Message.html")
    m.add_attachment(b"MZ\x90\x00 fake", maintype="application", subtype="pdf", filename="invoice_8812.pdf")
    return m


def benign():
    m = EmailMessage()
    m["Received"] = ("from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.example.cz "
                     "(Postfix) with ESMTPS id 9A1B2C for <jan.novak@example.cz>; Mon, 12 Oct 2026 10:02:11 +0200")
    m["Received"] = ("by mail-sor-f41.google.com with SMTP id abc123 for <jan.novak@example.cz>; "
                     "Mon, 12 Oct 2026 01:02:09 -0700 (PDT)")
    m["Authentication-Results"] = ("mx.example.cz; dkim=pass header.i=@gmail.com header.s=20230601 "
                                   "header.b=Ab12; spf=pass (mx.example.cz: domain of petra.svoboda@gmail.com "
                                   "designates 209.85.220.41 as permitted sender) smtp.mailfrom=petra.svoboda@gmail.com; "
                                   "dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com")
    m["DKIM-Signature"] = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601; h=from:to; bh=x; b=y"
    m["Return-Path"] = "<petra.svoboda@gmail.com>"
    m["From"] = "Petra Svobodová <petra.svoboda@gmail.com>"
    m["To"] = "Jan Novák <jan.novak@example.cz>"
    m["Subject"] = "Fotky z víkendu"
    m["Date"] = "Mon, 12 Oct 2026 10:02:05 +0200"
    m["Message-ID"] = "<CAF1x2y3z@mail.gmail.com>"
    m.set_content("Ahoj Honzo,\n\nposílám fotky z výletu, album je tady: https://photos.google.com/share/abc\n\nPetra")
    return m


if __name__ == "__main__":
    for name, msg in (("phishing_sample.eml", phishing()), ("benign_sample.eml", benign())):
        with open(os.path.join(HERE, name), "wb") as fh:
            fh.write(bytes(msg))
        print("wrote", name)
