# 🦅 MailHawk

> Email header forensics & phishing detection — who *really* sent that message? Spoofed senders, lookalike domains, failed SPF/DKIM/DMARC, forged Received chains, deceptive links and weaponized attachments, read straight from the `.eml`. Zero dependencies, pure Python stdlib.

[![Python](https://img.shields.io/badge/Python-3.9%2B-0D1117?style=for-the-badge&logo=python&logoColor=3776AB)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-00E676?style=for-the-badge&labelColor=0D1117)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-0D1117?style=for-the-badge&logoColor=00E676)](LICENSE)
[![Author](https://img.shields.io/badge/Author-mustafaak0-0D1117?style=for-the-badge&logo=github&logoColor=00E676)](https://github.com/mustafaak0)

Pairs with [PhishGuard](https://github.com/mustafaak0/phishguard): PhishGuard
judges the **URL**, MailHawk interrogates the **email that carried it**.

> ⚠️ For defensive analysis of email you received. You are responsible for
> how you use this tool.

## 🎯 Detections

| Finding | Logic | FP defense |
|---|---|---|
| 🔤 **lookalike domain** | sender SLD tokens normalized (`paypa1`→`paypal`, `rn`→`m`, `xn--`) and matched against ~45 known-brand SLDs | whole-token match only; brand + subdomain must equal the registered domain to count as legit |
| 🏷️ **brand display name** | "PayPal Support" in the name but not in the domain → HIGH | exact brand domains are exempt |
| 🏦 **brand domain unverified** | `From: @microsoft.com` **without** SPF+DKIM+DMARC all passing → CRITICAL envelope spoof | a pass on all three exempts the message |
| 📬 **Reply-To redirection** | reply travels to another domain — free-mail collection address (gmail/yandex/…) → HIGH | same-organization subdomains skipped |
| ✉️ **envelope mismatch** | `Return-Path` ≠ `From` — downgraded to INFO when a DKIM signature aligned to the From domain explains it (SendGrid & friends) | aligned-DKIM exemption |
| 🔐 **SPF / DKIM / DMARC** | verdicts parsed from `Authentication-Results`; DKIM alignment (`d=` org-domain vs From) checked separately | `pass` clears, `none` weighed as MEDIUM/LOW, never HIGH |
| 🕰️ **backwards Received chain** | hop timestamps must increase oldest→newest; < −120 s tolerated for clock skew | 2-minute skew window |
| 🏠 **private-IP origin** | first (bottom-most) hop injected from RFC1918 space | informational LOW — home senders exist |
| 🖨️ **script-mailer fingerprint** | `X-Mailer`/`User-Agent` ∈ {PHP mail, PHPMailer, gophish, swaks, …} | ESPs (SendGrid/Mailgun/…) and real MUAs exempt |
| 🧾 **missing Message-ID / Date** | every real MTA stamps them; scripted senders forget | — |
| ⏰ **urgency subject** | EN+TR pressure phrases ("urgent", "hesabınız askıya", "verify your account", …) | LOW weight alone — an accelerant, not a verdict |
| 🔗 **deceptive link** | `<a>` text shows domain A, href points to domain B → HIGH; raw-IP links → MEDIUM | token appearing anywhere in the href (trackers, redirect params) is skipped |
| 📋 **embedded HTML form** | credential harvest inside the message itself | — |
| 📎 **weaponized attachment** | `.exe/.vbs/.hta/.lnk/…` → HIGH; `fatura.pdf.exe` double extension → CRITICAL | macro-free normal docs ignored |

## 🚀 Usage

```bash
# build the demo corpus (2 clean + 4 attack emails) and hunt them
python demo_gen.py
python mailhawk.py demo/

# real mail: drag a message out of your client as .eml (or a whole folder)
python mailhawk.py suspicious.eml -v
python mailhawk.py mailbox/ --json report.json --html report.html
```

```
╭ MailHawk ────────────────────────────────────────────────────────────────╮
│ file     : demo/03_phish_paypal.eml                                       │
│ from     : "PayPal Security" <service@paypa1-secure.com>                  │
│ subject  : Urgent: your account has been suspended - verify now           │
│ auth     : spf=fail  dkim=none  dmarc=fail                                │
│ verdict  : 🚨 PHISHING  score 100/100 [F]  12 findings                     │
│                                                                           │
│ 🔴 [CRITICAL] Lookalike (homoglyph) sender domain                          │
│   ⤷ @paypa1-secure.com ≈ paypal.…                                         │
│ 🟠 [HIGH] Reply-To redirects to a free-mail account                        │
│   ⤷ From @paypa1-secure.com → Reply-To paypal.verify.team@gmail.com       │
│ 🟠 [HIGH] Link text lies about its destination                             │
│   ⤷ shows "www.paypal.com" → goes to http://185.199.108.153/paypal/login  │
│ 🟡 [MEDIUM] Received chain timestamps run backwards                        │
│   ⤷ 2026-11-12 09:12:00+03:00 after 2026-11-12 09:44:00+03:00             │
╰──────────────────────────────────────────────────────────────────────────╯
```

Scoring: CRITICAL 40 · HIGH 25 · MEDIUM 12 · LOW 5 · INFO 0 → capped at 100.
Verdicts: `CLEAN` (<10) · `REVIEW` (≥10 or any MEDIUM) · `SUSPICIOUS` (≥35 or
any HIGH) · `PHISHING` (≥60 or any CRITICAL). Exit codes for CI: `0` clean,
`1` HIGH/Critical findings, `2` error — wire it into your mail pipeline.

## 🧪 Verified on Synthetic Attacks

`demo_gen.py` writes six messages: two benign (personal Gmail mail, a signed
SendGrid newsletter with legitimate envelope mismatch) and four attacks —
PayPal homoglyph phish, Turkish CEO-fraud BEC, a zero-auth `@microsoft.com`
spoof with an injected backwards Received chain, and a Garanti BBVA phish
with an embedded credential form + `fatura.pdf.exe`.

MailHawk: **4/4 attacks → PHISHING (grade F), both clean mails → CLEAN (A)
with zero false-positive findings.** The SendGrid newsletter's Return-Path
mismatch is correctly recognized as signed-ESP relaying (INFO, score 0).

## 🔍 How it works

1. **Parse** — `email` stdlib, compat32 to preserve raw headers; encoded-words
   (RFC 2047) decoded for display-name inspection.
2. **Reconstruct** — From/Reply-To/Return-Path identities, the full Received
   chain (HELO · IP · by · timestamp), and SPF/DKIM/DMARC verdicts with DKIM
   alignment.
3. **Correlate** — 20+ rules vote with weighted severities; no single LOW
   signal can condemn a message, and legit infrastructure (ESPs, aligned
   relays, mailing lists) is explicitly whitelisted by design.
4. **Report** — colored terminal, JSON, dark-theme HTML (received chain
   included).

## 📄 License

[MIT](LICENSE) © Mustafa AK
