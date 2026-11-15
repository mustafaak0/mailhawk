#!/usr/bin/env python3
"""
MailHawk — email header forensics & phishing detection. Zero dependencies.

Parses an .eml file (or a whole mailbox directory), reconstructs who really
sent the message, and hunts the classic forgery tricks: spoofed From domains,
Reply-To redirection, homoglyph lookalikes, failed SPF/DKIM/DMARC, forged
Received chains, script-mailer fingerprints, deceptive links and weaponized
attachments.

For defensive analysis of email YOU received. Authorized use only.
"""

import argparse
import email
import email.policy
import ipaddress
import json
import os
import re
import sys
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlparse

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# knowledge bases
# --------------------------------------------------------------------------

# well-known brand SLDs (registered-domain second-level labels)
BRAND_DOMAINS = {
    "paypal", "apple", "icloud", "microsoft", "outlook", "office", "live",
    "google", "gmail", "amazon", "aws", "github", "facebook", "instagram",
    "whatsapp", "linkedin", "netflix", "spotify", "twitter", "dropbox",
    "ebay", "aliexpress", "dhl", "ups", "fedex", "coinbase", "binance",
    "metamask", "discord", "steam", "trendyol", "hepsiburada", "sahibinden",
    "turkcell", "superonline", "garantibbva", "isbank", "ziraatbank", "akbank",
    "yapikredi", "halkbank", "vakifbank", "denizbank", "teb", "ptt", "turkiye",
    "turkishairlines", "thy", "gasbuddy", "netflix", "booking", "airbnb",
}

# display-name keywords → brand SLD
BRAND_NAMES = {
    "paypal", "apple", "icloud", "microsoft", "outlook", "office 365",
    "google", "gmail", "amazon", "aws", "github", "facebook", "instagram",
    "whatsapp", "linkedin", "netflix", "spotify", "dhl", "ups", "fedex",
    "coinbase", "binance", "metamask", "steam", "trendyol", "hepsiburada",
    "turkcell", "turk telekom", "garanti", "garanti bbva", "işbankası",
    "ziraat", "akbank", "yapı kredi", "halkbank", "vakıfbank", "denizbank",
    "e-devlet", "ptt", "turkish airlines", "türk hava yolları",
}

RISKY_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "link",
    "work", "country", "loan", "men", "party", "review", "stream", "gdn",
    "mom", "zip", "surf", "bar", "kim", "icu", "cam", "rest", "quest",
}

MULTI_TLDS = {
    "com.tr", "co.uk", "com.au", "co.jp", "com.br", "org.uk", "gov.uk",
    "com.mx", "co.in", "com.cn", "gov.tr", "edu.tr", "co.za", "com.sg",
}

FREE_MAIL = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "yandex.com",
    "yandex.ru", "protonmail.com", "proton.me", "icloud.com", "aol.com",
    "mail.com", "gmx.com", "zoho.com", "mail.ru", "inbox.lv", "mynet.com",
}

# bulk senders / ESPs — legitimate infrastructure, report only
ESP_MAILERS = (
    "sendgrid", "mailgun", "mailchimp", "mandrill", "postmark", "amazon ses",
    "constant contact", "hubspot", "klaviyo", "zoho", "campaign monitor",
    "brevo", "sendinblue", "mailjet", "sparkpost", "exacttarget",
)
# normal mail clients — not interesting
MUA_MAILERS = (
    "outlook", "apple mail", "thunderbird", "iphone mail", "ipad", "mac",
    "yahoo", "gmail", "samsung", "android", "heymail", "webmail", "roundcube",
)
# script/tool fingerprints — nobody's grandma sends PHP from a terminal
SCRIPT_MAILERS = (
    "php", "gophish", "laravel", "python", "curl", "swaks", "msmtp",
    "mass mailer", "bulk mailer", "emailer", "the bat", "fake mailer",
    "smtp", "mailer",
)

URGENCY_PATTERNS = [
    r"urgent", r"immediately", r"act now", r"\bfinal notice\b",
    r"verify your (account|identity|email)", r"confirm your (account|identity)",
    r"account (has been |is )?(suspended|locked|disabled|limited|compromised)",
    r"unusual (activity|sign[- ]?in)", r"password.{0,20}expire",
    r"wire transfer", r"invoice attached", r"billing (failure|problem)",
    r"\bwinner\b", r"prize", r"acil", r"hemen", r"\bonay\b",
    r"hesab(ınız|iniz).{0,25}(ask|kapat|bloke|don|iptal|dondur)",
    r"doğrulama", r"şifreniz", r"son \d+ saat", r"son \d+ gün",
    r"\bhavale\b", r"\beft\b", r"\bfatura\b", r"\bkargo\b", r"\bödeme\b",
]

DANGEROUS_EXTS = {
    "exe", "scr", "js", "jse", "vbs", "vbe", "ps1", "bat", "cmd", "hta",
    "jar", "lnk", "iso", "img", "py", "wsf", "sh", "com", "pif", "cpl",
    "docm", "xlsm", "pptm",
}
BENIGN_DOUBLE_EXTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg",
    "png", "gif", "txt", "csv",
}

SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEV_WEIGHT = {"INFO": 0, "LOW": 5, "MEDIUM": 12, "HIGH": 25, "CRITICAL": 40}
SEV_ICON = {
    "INFO": "⚪", "LOW": "🔵", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴",
}
VERDICT_ICON = {
    "PHISHING": "🚨", "SUSPICIOUS": "⚠️ ", "REVIEW": "👀", "CLEAN": "✅",
}

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

class C:
    """ANSI colors, auto-disabled when not a tty / NO_COLOR."""
    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    @classmethod
    def _c(cls, code, text):
        return f"\033[{code}m{text}\033[0m" if cls.enabled else str(text)

    @classmethod
    def red(cls, t): return cls._c("91", t)
    @classmethod
    def orange(cls, t): return cls._c("38;5;208", t)
    @classmethod
    def yellow(cls, t): return cls._c("93", t)
    @classmethod
    def blue(cls, t): return cls._c("94", t)
    @classmethod
    def green(cls, t): return cls._c("92", t)
    @classmethod
    def cyan(cls, t): return cls._c("96", t)
    @classmethod
    def dim(cls, t): return cls._c("90", t)
    @classmethod
    def bold(cls, t): return cls._c("1", t)

    @classmethod
    def sev(cls, level, t):
        return {
            "CRITICAL": cls.red, "HIGH": cls.orange, "MEDIUM": cls.yellow,
            "LOW": cls.blue, "INFO": cls.dim,
        }[level](t)


def registered_domain(domain):
    """akbank-giris.xyz.com → xyz.com; garanti.co.uk-style suffixes aware."""
    if not domain:
        return ""
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


def sld(domain):
    """Second-level label: mail.paypal.com → paypal; garantibbva.com.tr → garantibbva."""
    rd = registered_domain(domain)
    return rd.split(".")[0] if rd else ""


def normalize_confusable(text):
    """Undo classic lookalike substitutions: paypa1 → paypal."""
    text = text.lower().replace("rn", "m").replace("vv", "w")
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a",
                           "5": "s", "7": "t", "8": "b", "$": "s"})
    return text.translate(table)


def domain_brand_match(domain):
    """Classify a From domain against the brand list.

    Returns one of:
      ('exact', brand)     — domain IS a brand domain (paypal.com)
      ('lookalike', brand) — confusable/branded-token domain (paypa1-secure.com)
      (None, None)         — unrelated
    """
    if not domain:
        return None, None
    d = domain.lower().strip(".")
    if "xn--" in d:
        return ("lookalike", "punycode")  # IDN homograph, treat as lookalike
    labels = d.split(".")
    for i, label in enumerate(labels[:-1]):          # ignore the TLD itself
        tokens = re.split(r"[-_.]", label)
        for token in tokens:
            norm = normalize_confusable(token)
            if norm in BRAND_DOMAINS or token in BRAND_DOMAINS:
                # exact only if this label + everything after == registered domain
                if f"{token}." + ".".join(labels[i + 1:]) == registered_domain(d) \
                        and token == labels[i] and "-" not in labels[i]:
                    return ("exact", norm)
                return ("lookalike", norm)
    return None, None


def parse_eml(path):
    with open(path, "rb") as fh:
        data = fh.read()
    return email.message_from_bytes(data, policy=email.policy.compat32)


def hdecode(value):
    """RFC 2047 decode a raw header value; never raises."""
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def strip_html(html_text):
    html_text = re.sub(r"<style.*?</style>", " ", html_text,
                       flags=re.S | re.I)
    html_text = re.sub(r"<script.*?</script>", " ", html_text,
                       flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", html_text)
    return re.sub(r"\s+", " ", text)


DOMAIN_TOKEN_RE = re.compile(
    r"\b(?:[a-z0-9][a-z0-9-]*\.)+"
    r"(?:com\.tr|org\.tr|gov\.tr|edu\.tr|co\.uk|com\.au|[a-z]{2,})\b",
    re.I)


# --------------------------------------------------------------------------
# header reconstruction
# --------------------------------------------------------------------------

class Mail:
    """Everything MailHawk needs to know about one message."""

    def __init__(self, path):
        self.path = path
        self.msg = parse_eml(path)
        m = self.msg

        self.subject_raw = m.get("Subject", "")
        self.subject = hdecode(self.subject_raw)

        from_raw = m.get("From", "")
        self.from_raw = from_raw
        self.from_name, self.from_addr = parseaddr(hdecode(from_raw))
        self.from_domain = self.from_addr.rsplit("@", 1)[-1].lower() \
            if "@" in self.from_addr else ""

        def addr_of(header):
            raw = m.get(header, "")
            if not raw:
                return "", ""
            name, a = parseaddr(hdecode(raw))
            return name, a.lower()

        self.replyto_name, self.replyto_addr = addr_of("Reply-To")
        self.replyto_domain = self.replyto_addr.rsplit("@", 1)[-1] \
            if "@" in self.replyto_addr else ""
        self.return_path = addr_of("Return-Path")[1]
        self.return_path_domain = self.return_path.rsplit("@", 1)[-1] \
            if "@" in self.return_path else ""
        self.sender_addr = addr_of("Sender")[1]

        self.mailer = (m.get("X-Mailer") or m.get("User-Agent") or "").strip()
        self.mailer_l = hdecode(self.mailer).lower()
        self.has_date = bool(m.get("Date"))
        self.message_id = (m.get("Message-ID") or "").strip()
        self.list_unsub = bool(m.get("List-Unsubscribe"))

        # ---- authentication results -----------------------------------
        self.auth_raw = " ; ".join(m.get_all("Authentication-Results", []))
        self.spf, self.dkim, self.dmarc = "missing", "missing", "missing"
        self.spf_mailfrom = self.dkim_domain = ""
        ar = " ; ".join(str(x) for x in m.get_all("Authentication-Results", []))
        for mech in ("spf", "dkim", "dmarc"):
            mt = re.search(rf"\b{mech}\s*=\s*([a-z]+)", ar, re.I)
            if mt:
                setattr(self, mech, mt.group(1).lower())
        if not ar and m.get("Received-SPF"):
            self.spf = m.get("Received-SPF").strip().split(" ", 1)[0].lower()
        mm = re.search(r"smtp\.mailfrom=(?:<?)([^\s>;]+)", ar, re.I)
        if mm:
            self.spf_mailfrom = mm.group(1).rsplit("@", 1)[-1].strip(">").lower()
        md = re.search(r"header\.d=([^\s;>]+)", ar, re.I) or \
             re.search(r"header\.i=@?([^\s;>]+)", ar, re.I)
        if md:
            self.dkim_domain = md.group(1).lower()
        if not self.dkim_domain and m.get("DKIM-Signature"):
            dd = re.search(r"\bd=([^\s;]+)", m.get("DKIM-Signature", ""))
            if dd:
                self.dkim_domain = dd.group(1).lower()

        # ---- Received chain --------------------------------------------
        # get_all()[0] is the NEWEST hop; reverse for chronological order
        rcvd = [str(x) for x in m.get_all("Received", [])]
        self.received = []
        for raw in rcvd:
            # un-fold continuation lines → flat string for reliable parsing
            flat = " ".join(raw.split())
            hop = {"raw": raw, "helo": "", "ip": "", "by": "", "dt": None}
            fm = re.search(r"from\s+([^\s(]+)", flat)
            if fm:
                hop["helo"] = fm.group(1).strip(";")
            bm = re.search(r"\bby\s+([^\s;(]+)", flat)
            if bm:
                hop["by"] = bm.group(1).rstrip(";")
            ips = re.findall(
                r"(?:\d{1,3}\.){3}\d{1,3}"
                r"|[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2,7}", flat)
            for cand in ips:
                try:
                    ipaddress.ip_address(cand)
                    hop["ip"] = cand
                    break
                except ValueError:
                    continue
            dm = re.search(r";\s*(.+?)\s*$", flat)
            if dm:
                try:
                    hop["dt"] = parsedate_to_datetime(dm.group(1).strip())
                except Exception:
                    pass
            self.received.append(hop)
        self.received_chrono = list(reversed(self.received))

        # ---- body & attachments ----------------------------------------
        self.html_body = ""
        self.attachments = []
        if m.is_multipart():
            for part in m.walk():
                ctype = part.get_content_type()
                disp = (part.get("Content-Disposition") or "").lower()
                fname = part.get_filename() or ""
                if ctype == "text/html" and "attachment" not in disp and not self.html_body:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        self.html_body += payload.decode(charset, "replace")
                    except LookupError:
                        self.html_body += payload.decode("utf-8", "replace")
                if fname:
                    self.attachments.append(fname)
        else:
            payload = m.get_payload(decode=True) or b""
            charset = m.get_content_charset() or "utf-8"
            try:
                body = payload.decode(charset, "replace")
            except LookupError:
                body = payload.decode("utf-8", "replace")
            if m.get_content_type() == "text/html":
                self.html_body = body

        # encoded-word tricks
        self.from_encoded_hidden = ("=?" in str(self.from_raw)
                                    and bool(re.search(
                                        r"@|https?://", hdecode(str(self.from_raw)).replace(self.from_addr, "", 1)
                                        if self.from_addr else "")))

    # -- convenience -----------------------------------------------------
    @property
    def auth_all_pass(self):
        return self.spf == "pass" and self.dkim == "pass" and self.dmarc == "pass"

    def alignment_ok(self):
        """Relaxed DMARP-style alignment: DKIM d= org-domain == From org-domain."""
        if not self.dkim_domain or not self.from_domain:
            return False
        return registered_domain(self.dkim_domain) == registered_domain(self.from_domain)


# --------------------------------------------------------------------------
# rules — each returns a list of finding dicts
# --------------------------------------------------------------------------

def finding(rule_id, severity, title, evidence, detail=""):
    return {"id": rule_id, "severity": severity, "title": title,
            "evidence": evidence, "detail": detail}


def check_identity(mail):
    out = []
    fdom, rdom = mail.from_domain, mail.replyto_domain

    # R1 reply-to redirection
    if rdom and rdom != fdom:
        if registered_domain(rdom) == registered_domain(fdom):
            pass  # subdomain of the same org — fine
        elif registered_domain(fdom) not in FREE_MAIL and \
                registered_domain(rdom) in FREE_MAIL:
            out.append(finding(
                "replyto_freemail", "HIGH",
                "Reply-To redirects to a free-mail account",
                f"From @{fdom} → Reply-To {mail.replyto_addr}",
                "Corporate display address + free-mail collection account is "
                "the classic BEC/phishing collection pattern."))
        else:
            out.append(finding(
                "replyto_mismatch", "MEDIUM",
                "Reply-To domain differs from From domain",
                f"From @{fdom} → Reply-To @{rdom}",
                "Replies silently travel to another organization. Sometimes "
                "legit (support desks), sometimes the whole scam."))

    # R2 envelope mismatch (Return-Path)
    if mail.return_path_domain and \
            registered_domain(mail.return_path_domain) != registered_domain(fdom):
        if mail.dkim == "pass" and mail.alignment_ok():
            out.append(finding(
                "envelope_esp", "INFO",
                "Envelope sender differs (signed ESP relay)",
                f"Return-Path @{mail.return_path_domain} vs From @{fdom}",
                "DKIM-signed on behalf of the From domain — typical bulk "
                "sender (SendGrid/Mailgun) bounce handling."))
        else:
            out.append(finding(
                "envelope_mismatch", "MEDIUM",
                "Envelope sender (Return-Path) differs from From",
                f"Return-Path @{mail.return_path_domain} vs From @{fdom}",
                "The SMTP envelope claims a different origin than the header "
                "the user sees."))

    # R3 display-name email injection
    name = (mail.from_name or "")
    hidden = re.findall(r"[\w.+-]+@[\w.-]+", name)
    if hidden and hidden[0].lower() != mail.from_addr:
        out.append(finding(
            "displayname_injection", "HIGH",
            "Display name hides a different email address",
            f'"{name}" <{mail.from_addr}>',
            "The name the victim reads is itself an address — and not the "
            "one that will receive the reply."))

    # R4 brand display-name vs non-brand domain
    for brand in BRAND_NAMES:
        if re.search(rf"(?<![\w]){re.escape(brand)}(?![\w])", name, re.I):
            status, dom_brand = domain_brand_match(mail.from_domain)
            if status != "exact":
                out.append(finding(
                    "brand_displayname", "HIGH",
                    f"Brand name in display, domain is not the brand",
                    f'"{name}" <{mail.from_addr}>',
                    f"Talks like {brand}, delivers from @{fdom or 'nowhere'}."))
            break

    # R5 exact brand domain without passing authentication = envelope spoof
    status, brand = domain_brand_match(mail.from_domain)
    if status == "exact" and not mail.auth_all_pass:
        failed = ", ".join(f"{k}={getattr(mail, k)}"
                           for k in ("spf", "dkim", "dmarc"))
        out.append(finding(
            "brand_domain_unverified", "CRITICAL",
            f"Brand domain @{mail.from_domain} fails authentication",
            failed,
            f"Real {brand} infrastructure always publishes SPF/DKIM/DMARC. "
            "Anyone can WRITE a From address; only these checks prove it."))

    # R6 homoglyph / lookalike domain
    if status == "lookalike":
        out.append(finding(
            "lookalike_domain", "CRITICAL",
            "Lookalike (homoglyph) sender domain",
            f"@{mail.from_domain} ≈ {brand}.…",
            "Digit/character substitutions or brand tokens inside an "
            "unrelated domain — paypal style, paypal price."))

    # R7 risky TLD garnish
    tld = mail.from_domain.rsplit(".", 1)[-1] if mail.from_domain else ""
    if tld in RISKY_TLDS and status != "exact":
        out.append(finding(
            "risky_tld", "LOW",
            f"Sender uses throwaway TLD .{tld}",
            f"@{mail.from_domain}",
            "Cheap or free TLDs dominate phishing statistics. Weak signal "
            "alone, damning in company."))

    if mail.sender_addr and mail.sender_addr.lower() != mail.from_addr:
        out.append(finding(
            "sender_header", "INFO",
            "Sender header differs from From",
            f"Sender {mail.sender_addr} vs From {mail.from_addr}",
            "RFC 5322 wants these to agree. Mailing lists often differ."))
    return out


def check_auth(mail):
    out = []
    if mail.spf in ("fail", "softfail"):
        out.append(finding(
            "spf_fail", "HIGH",
            f"SPF {mail.spf}",
            f"Sending IP not authorized for @{mail.spf_mailfrom or mail.from_domain}",
            "The connecting server is not allowed to send for this domain."))
    elif mail.spf in ("none", "missing"):
        out.append(finding(
            "spf_none", "LOW",
            "SPF " + ("absent" if mail.spf == "missing" else "no record/check"),
            f"spf={mail.spf}",
            "No authorization signal at all."))

    if mail.dkim == "fail":
        out.append(finding(
            "dkim_fail", "HIGH", "DKIM signature FAILED",
            "dkim=fail",
            "Signature present but broken — tampered body or forged header."))
    elif mail.dkim in ("none", "missing"):
        out.append(finding(
            "dkim_missing", "MEDIUM", "Message is not DKIM-signed",
            f"dkim={mail.dkim}",
            "Unsigned mail can be rewritten by anyone in transit. Major "
            "senders always sign."))
    elif mail.dkim == "pass" and not mail.alignment_ok():
        out.append(finding(
            "dkim_misaligned", "MEDIUM", "DKIM signature is not aligned",
            f"d=@{mail.dkim_domain} vs From @{mail.from_domain}",
            "Signed, yes — but by a different organization than the one the "
            "victim reads."))

    if mail.dmarc == "fail":
        out.append(finding(
            "dmarc_fail", "HIGH", "DMARC fail",
            "dmarc=fail",
            "Both alignment and authentication broke down. This is the "
            "receiving server telling you the sender is fake."))
    elif mail.dmarc in ("none", "missing"):
        out.append(finding(
            "dmarc_missing", "MEDIUM",
            "No DMARC verdict",
            f"dmarc={mail.dmarc}",
            "Either the domain publishes no policy or no verifier ran."))
    return out


def check_routing(mail):
    out = []
    if not mail.received:
        out.append(finding(
            "no_received", "CRITICAL",
            "No Received headers at all",
            "0 hops",
            "Real SMTP journeys stamp every hop. Zero stamps = hand-forged "
            "message."))
        return out

    # chronological sanity — clock skew under 120s tolerated
    prev = None
    for hop in mail.received_chrono:
        if hop["dt"] and prev and (hop["dt"] - prev).total_seconds() < -120:
            out.append(finding(
                "hop_time_backwards", "MEDIUM",
                "Received chain timestamps run backwards",
                f"{hop['dt']} after {prev}",
                "Mail cannot arrive before it was sent. Header injection or "
                "a lying relay."))
            break
        if hop["dt"]:
            prev = hop["dt"]

    origin = mail.received_chrono[0]
    if origin["ip"]:
        try:
            if ipaddress.ip_address(origin["ip"]).is_private:
                out.append(finding(
                    "private_origin", "LOW",
                    "Originating hop is a private IP",
                    f"first hop {origin['helo'] or '?'} [{origin['ip']}]",
                    "Consumer/NAT origin dressed up as corporate mail. "
                    "Normal for home users, odd for a bank."))
        except ValueError:
            pass
    return out


def check_composition(mail):
    out = []
    ml = mail.mailer_l
    if ml:
        if any(s in ml for s in SCRIPT_MAILERS) and \
                not any(s in ml for s in MUA_MAILERS):
            out.append(finding(
                "script_mailer", "MEDIUM",
                "Mailer fingerprint: scripted sender",
                f"X-Mailer: {mail.mailer}",
                "Mass-mailing scripts and PHP stacks, not human mail apps."))
        elif any(s in ml for s in ESP_MAILERS):
            out.append(finding(
                "esp_mailer", "INFO",
                "Sent via bulk email service",
                f"X-Mailer: {mail.mailer}",
                "Legit infrastructure — but phishers rent it too."))

    if not mail.message_id:
        out.append(finding(
            "no_message_id", "MEDIUM",
            "Missing Message-ID",
            "header absent",
            "Every real MTA/ESP stamps one. Scripted senders forget."))
    else:
        mid_dom = re.search(r"@([^\s>]+)", mail.message_id)
        if mid_dom and mail.from_domain and \
                registered_domain(mid_dom.group(1).lower()) != \
                registered_domain(mail.from_domain):
            out.append(finding(
                "mid_mismatch", "LOW",
                "Message-ID domain differs from sender",
                f"{mail.message_id} vs @{mail.from_domain}",
                "Weak forgery smell; ESPs sometimes trip this."))

    if not mail.has_date:
        out.append(finding("no_date", "LOW", "Missing Date header",
                           "header absent",
                           "Hand-crafted message, sloppy tooling."))

    subj = mail.subject.lower()
    for pat in URGENCY_PATTERNS:
        if re.search(pat, subj, re.I):
            out.append(finding(
                "urgency_subject", "LOW",
                "Urgency / pressure language in subject",
                f'"{mail.subject}"',
                "Social-engineering accelerant. Worthless alone, decisive in "
                "combination."))
            break

    if mail.from_encoded_hidden:
        out.append(finding(
            "encoded_from_payload", "MEDIUM",
            "Encoded header hides an address or URL",
            "RFC 2047 encoded-word with @/http inside",
            "Base64-wrapped bait that some clients render and users never "
            "inspect."))
    return out


def check_body(mail):
    out = []
    html = mail.html_body
    if html:
        for m in re.finditer(
                r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                html, re.S | re.I):
            href, inner = m.group(1), strip_html(m.group(2))
            if not href.lower().startswith(("http://", "https://")):
                continue
            shown = {t.lower().rstrip(".") for t in DOMAIN_TOKEN_RE.findall(inner)}
            if not shown:
                continue
            try:
                host = urlparse(href).netloc.lower().split("@")[-1]
            except ValueError:
                continue
            host_dom = registered_domain(host)
            href_l = href.lower()
            for token in shown:
                if registered_domain(token) and registered_domain(token) != host_dom \
                        and host_dom not in token and token not in host \
                        and token not in href_l:
                    out.append(finding(
                        "deceptive_link", "HIGH",
                        "Link text lies about its destination",
                        f'shows "{token}" → goes to {href[:90]}',
                        "The domain you read is not the domain you visit."))
                    break
            if len([f for f in out if f["id"] == "deceptive_link"]) >= 3:
                break
        if re.search(r"<form\b", html, re.I):
            out.append(finding(
                "html_form", "MEDIUM",
                "HTML form embedded in email",
                "<form …>",
                "Credential harvesters that never leave the message."))
        for m in re.finditer(r'href=["\']https?://((?:\d{1,3}\.){3}\d{1,3})',
                             html, re.I):
            out.append(finding(
                "raw_ip_link", "MEDIUM",
                "Link points to a raw IP address",
                f"http://{m.group(1)}/…",
                "No domain, no certificate, no brand — just a box."))
            break

    for fname in mail.attachments:
        fname_l = fname.lower()
        exts = fname_l.split(".")
        if len(exts) >= 3 and exts[-2] in BENIGN_DOUBLE_EXTS \
                and exts[-1] in DANGEROUS_EXTS:
            out.append(finding(
                "double_extension", "CRITICAL",
                "Double-extension attachment",
                fname,
                "invoice.pdf.exe wears a PDF costume. Windows hides the "
                "second one."))
        elif exts[-1] in DANGEROUS_EXTS:
            out.append(finding(
                "dangerous_attachment", "HIGH",
                "Executable / macro attachment",
                fname,
                "No legitimate business email needs this to be opened."))
    return out


ALL_CHECKS = (check_identity, check_auth, check_routing,
              check_composition, check_body)


# --------------------------------------------------------------------------
# scoring & rendering
# --------------------------------------------------------------------------

def analyze(path):
    mail = Mail(path)
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(mail))
    findings.sort(key=lambda f: -SEV_ORDER[f["severity"]])

    score = min(100, sum(SEV_WEIGHT[f["severity"]] for f in findings))
    top = max((SEV_ORDER[f["severity"]] for f in findings), default=0)
    if top >= SEV_ORDER["CRITICAL"] or score >= 60:
        verdict = "PHISHING"
    elif top >= SEV_ORDER["HIGH"] or score >= 35:
        verdict = "SUSPICIOUS"
    elif top >= SEV_ORDER["MEDIUM"] or score >= 10:
        verdict = "REVIEW"
    else:
        verdict = "CLEAN"
    grade = "F" if score >= 80 else "D" if score >= 60 else \
            "C" if score >= 35 else "B" if score >= 10 else "A"

    return {
        "file": path,
        "verdict": verdict,
        "score": score,
        "grade": grade,
        "from": f'"{mail.from_name}" <{mail.from_addr}>' if mail.from_name
                else mail.from_addr,
        "from_domain": mail.from_domain,
        "subject": mail.subject,
        "auth": {"spf": mail.spf, "dkim": mail.dkim, "dmarc": mail.dmarc,
                 "dkim_domain": mail.dkim_domain,
                 "aligned": mail.alignment_ok() if mail.dkim_domain else None},
        "hops": len(mail.received),
        "attachments": mail.attachments,
        "findings": findings,
        "received_chain": [
            {"from": h["helo"], "ip": h["ip"], "by": h["by"],
             "time": h["dt"].isoformat() if h["dt"] else None}
            for h in mail.received_chrono
        ],
        "_mail": mail,
    }


VERDICT_COLOR = {"PHISHING": C.red, "SUSPICIOUS": C.orange,
                 "REVIEW": C.yellow, "CLEAN": C.green}


def _plain_len(text):
    return len(re.sub(r"\033\[[0-9;]*m", "", text))


def render_term(rep, verbose=False):
    w = 74
    lines = []
    lines.append("╭" + C.cyan(" MailHawk ") + "─" * (w - 10) + "╮")

    def boxline(text):
        lines.append(text + " " * max(0, w + 2 - _plain_len(text)) + "│")

    def row(label, value):
        boxline(f"│ {label:<9}: {value}")

    vc = VERDICT_COLOR[rep["verdict"]]
    row("file", rep["file"])
    row("from", rep["from"])
    row("subject", (rep["subject"][:52] + "…") if len(rep["subject"]) > 53
        else rep["subject"] or "(none)")
    row("auth", f"spf={rep['auth']['spf']}  dkim={rep['auth']['dkim']}  "
                f"dmarc={rep['auth']['dmarc']}")
    row("verdict", f"{VERDICT_ICON[rep['verdict']]} "
                   f"{vc(rep['verdict'])}  score {rep['score']}/100 "
                   f"[{rep['grade']}]  {len(rep['findings'])} findings")
    lines.append("│" + " " * (w + 1) + "│")

    if not rep["findings"]:
        boxline(f"│ {C.green('nothing suspicious — clean header set')}")
    for f in rep["findings"]:
        boxline(f"│ {SEV_ICON[f['severity']]} "
                f"[{C.sev(f['severity'], f['severity'])}] {f['title']}")
        boxline(f"│   {C.cyan('⤷')} {f['evidence']}")
        if verbose and f["detail"]:
            words, cur = f["detail"].split(), ""
            for word in words:
                if len(cur) + len(word) + 1 > w - 5:
                    boxline(f"│     {C.dim(cur)}")
                    cur = word
                else:
                    cur = f"{cur} {word}".strip()
            if cur:
                boxline(f"│     {C.dim(cur)}")

    if verbose:
        lines.append("│" + " " * (w + 1) + "│")
        boxline(f"│ {C.bold('Received chain (oldest first):')}")
        for i, hop in enumerate(rep["received_chain"], 1):
            t = hop["time"] or "?"
            boxline(f"│   {i}. {hop['from'] or '?'} "
                    f"[{hop['ip'] or '?'}] by {hop['by'] or '?'} — {t}")

    lines.append("╰" + "─" * w + "╯")
    return "\n".join(lines)


HTML_TMPL = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>MailHawk report — {file_esc}</title>
<style>
 body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;
      max-width:900px;margin:2rem auto;padding:0 1rem}}
 h1{{color:#58a6ff;font-size:1.4rem}} .mono{{font-family:Consolas,monospace}}
 .verdict{{display:inline-block;padding:.4rem 1rem;border-radius:6px;font-weight:700;
           font-size:1.1rem;margin:.3rem 0}}
 .PHISHING{{background:#da3633;color:#fff}} .SUSPICIOUS{{background:#bb6d00;color:#fff}}
 .REVIEW{{background:#9e6a03;color:#fff}} .CLEAN{{background:#238636;color:#fff}}
 .meta{{background:#161b22;border:1px solid #30363d;border-radius:8px;
       padding:1rem;margin:1rem 0;white-space:pre-wrap}}
 .finding{{border-left:4px solid;border-radius:4px;background:#161b22;
          padding:.6rem .9rem;margin:.6rem 0}}
 .CRITICAL{{border-color:#f85149}} .HIGH{{border-color:#f0883e}}
 .MEDIUM{{border-color:#d29922}} .LOW{{border-color:#58a6ff}} .INFO{{border-color:#8b949e}}
 .sev{{font-size:.75rem;font-weight:700;letter-spacing:.5px}}
 .CRITICAL .sev{{color:#f85149}} .HIGH .sev{{color:#f0883e}}
 .MEDIUM .sev{{color:#d29922}} .LOW .sev{{color:#58a6ff}} .INFO .sev{{color:#8b949e}}
 .ev{{color:#79c0ff;font-family:Consolas,monospace;font-size:.85rem;margin:.2rem 0}}
 .detail{{color:#8b949e;font-size:.85rem}}
 table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #30363d;
      padding:.35rem .6rem;font-size:.85rem;text-align:left}}
 section{{border-top:2px solid #30363d;margin-top:2.5rem;padding-top:1rem}}
 footer{{color:#484f58;font-size:.8rem;margin-top:2rem}}
</style></head><body>
<h1>🦅 MailHawk — {file_esc}</h1>
<section>{findings_html}</section>
<footer>MailHawk v{version} — generated {generated} · analyze only mail you
received; authorized use only.</footer>
</body></html>
"""


def _html_section(rep):
    import html as html_mod

    parts = []
    for f in rep["findings"]:
        parts.append(
            f'<div class="finding {f["severity"]}">'
            f'<span class="sev">[{f["severity"]}]</span> '
            f'<b>{html_mod.escape(f["title"])}</b>'
            f'<div class="ev">{html_mod.escape(f["evidence"])}</div>'
            f'<div class="detail">{html_mod.escape(f["detail"])}</div></div>')
    if not parts:
        parts.append('<div class="finding CLEAN">No findings.</div>')
    rows = "".join(
        f"<tr><td>{i}</td><td class='mono'>{html_mod.escape(h['from'] or '?')}"
        f"</td><td class='mono'>{h['ip'] or '?'}</td>"
        f"<td class='mono'>{html_mod.escape(h['by'] or '?')}</td>"
        f"<td>{h['time'] or '?'}</td></tr>"
        for i, h in enumerate(rep["received_chain"], 1))
    return (
        f'<p class="verdict {rep["verdict"]}">{rep["verdict"]} · '
        f'{rep["score"]}/100 · grade {rep["grade"]}</p>'
        f'<div class="meta">File: {html_mod.escape(rep["file"])}\n'
        f'From: {html_mod.escape(rep["from"])}\n'
        f'Subject: {html_mod.escape(rep["subject"] or "(none)")}\n'
        f'Auth: spf={rep["auth"]["spf"]} · dkim={rep["auth"]["dkim"]} · '
        f'dmarc={rep["auth"]["dmarc"]} · hops={rep["hops"]}</div>\n'
        + "\n".join(parts)
        + '\n<h2>Received chain</h2>\n<table><tr><th>#</th><th>from</th>'
          '<th>IP</th><th>by</th><th>time</th></tr>' + rows + "</table>")


def render_html(reports):
    import html as html_mod
    from datetime import datetime, timezone

    return HTML_TMPL.format(
        file_esc=html_mod.escape(reports[0]["file"])
        + (" …" if len(reports) > 1 else ""),
        findings_html="\n".join(_html_section(r) for r in reports),
        version=__version__,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))


BANNER = r"""
  __  __       _        _    _       _
 |  \/  | __ _| | _____| |  | | __ _| |__  ___
 | |\/| |/ _` | |/ / _ \ |  | |/ _` | '_ \/ __|
 | |  | | (_| |   <  __/ |__| | (_| | |_) \__ \
 |_|  |_|\__,_|_|\_\___|\____/ \__,_|_.__/|___/
"""


def main(argv=None):
    if os.name == "nt":
        os.system("")  # enable VT escapes in legacy consoles
    ap = argparse.ArgumentParser(
        prog="mailhawk",
        description="MailHawk — email header forensics & phishing detection "
                    "(zero dependencies).",
        epilog="Analyze only email you received. Authorized use only.")
    ap.add_argument("targets", nargs="+",
                    help=".eml file(s) or a directory of them")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show Received chain + finding details")
    ap.add_argument("--json", metavar="FILE", help="write JSON report")
    ap.add_argument("--html", metavar="FILE", help="write HTML report")
    ap.add_argument("--no-color", action="store_true", help="plain output")
    args = ap.parse_args(argv)

    if args.no_color:
        C.enabled = False

    paths = []
    for t in args.targets:
        if os.path.isdir(t):
            paths += sorted(
                os.path.join(t, f) for f in os.listdir(t)
                if f.lower().endswith(".eml"))
        else:
            paths.append(t)

    print(C.cyan(BANNER) + C.dim(f" v{__version__} — {len(paths)} message(s)\n"))

    reports = []
    for p in paths:
        if not os.path.isfile(p):
            print(C.red(f"✗ not found: {p}"))
            continue
        try:
            rep = analyze(p)
        except Exception as exc:
            print(C.red(f"✗ {p}: parse error ({exc})"))
            continue
        reports.append(rep)
        print(render_term(rep, verbose=args.verbose))
        print()

    if not reports:
        return 2

    # summary
    print(C.bold("┌─ Summary ") + "─" * 63)
    for rep in reports:
        vc = VERDICT_COLOR[rep["verdict"]]
        name = os.path.basename(rep["file"])
        print(f"│ {name[:34]:<34} {rep['grade']}  {rep['score']:>3}/100  "
              f"{vc(rep['verdict'])}")
    print("└" + "─" * 73)

    if args.json:
        serial = [{k: v for k, v in rep.items() if not k.startswith("_")}
                  for rep in reports]
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(serial, fh, indent=2, ensure_ascii=False)
        print(C.green(f"✓ JSON report → {args.json}"))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(reports))
        print(C.green(f"✓ HTML report → {args.html}"))

    worst = max(rep["score"] for rep in reports)
    return 0 if worst < 35 else 1


if __name__ == "__main__":
    sys.exit(main())
