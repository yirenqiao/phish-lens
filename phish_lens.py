#!/usr/bin/env python3
"""phish-lens: explainable phishing triage for .eml files.

Reads raw email files, runs a set of transparent heuristics (authentication
results, sender spoofing, lookalike domains, deceptive links, pressure
language, dangerous attachments) and prints a 0-100 risk score with the
reason behind every point.

Zero dependencies - Python standard library only. Nothing is fetched from
the network: links are inspected, never visited.

Usage:
    python phish_lens.py message.eml [more.eml ...] [--json] [--no-color] [--exit-code]
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

# --------------------------------------------------------------------------- reference data

# brand keyword -> domains that legitimately send mail / host pages for it
BRANDS = {
    "paypal": {"paypal.com", "paypal.me", "paypal-communication.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com", "office365.com",
                  "microsoftonline.com", "sharepoint.com", "onmicrosoft.com", "hotmail.com"},
    "office365": {"microsoft.com", "office.com", "office365.com", "microsoftonline.com"},
    "outlook": {"outlook.com", "microsoft.com", "live.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.co.jp", "amazon.co.uk", "amazon.de", "amazon.fr",
               "amazon.ca", "amazon.in", "amazonses.com", "amazonaws.com", "aws.amazon.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com", "google.co.jp"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com", "fb.com"},
    "instagram": {"instagram.com", "facebookmail.com"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com", "githubusercontent.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "dhl": {"dhl.com", "dhl.de", "dhl.co.jp"},
    "fedex": {"fedex.com"},
    "chase": {"chase.com", "jpmorgan.com"},
    "wellsfargo": {"wellsfargo.com"},
    "rakuten": {"rakuten.co.jp", "rakuten.com", "rakuten-card.co.jp", "rakuten-bank.co.jp"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
}

BRAND_LABELS = {"paypal": "PayPal", "github": "GitHub", "linkedin": "LinkedIn", "icloud": "iCloud",
                "office365": "Office 365", "wellsfargo": "Wells Fargo", "docusign": "DocuSign",
                "dhl": "DHL", "fedex": "FedEx"}

EXECUTIVE_TITLES = r"\b(ceo|cfo|coo|cto|president|director|chairman|founder|managing partner|head of finance|payroll|hr)\b"

FREEMAIL = {"gmail.com", "yahoo.com", "yahoo.co.jp", "outlook.com", "hotmail.com", "live.com",
            "aol.com", "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
            "qq.com", "163.com", "126.com", "yandex.com"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
              "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "lnkd.in"}

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "link", "work", "gq", "tk", "ml", "cf",
                   "ga", "rest", "country", "kim", "loan", "men", "support", "icu", "cam", "buzz",
                   "monster", "quest", "sbs", "cfd"}

# second-level labels under which registrations happen (example.co.jp, example.com.au ...)
MULTI_PART_SUFFIXES = {"co", "com", "net", "org", "ac", "go", "ne", "or", "gov", "edu", "ltd", "plc"}

HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"),
              ("4", "a"), ("7", "t"), ("@", "a"), ("$", "s")]

PRESSURE_LANGUAGE = {
    "urgency": [r"\burgent\b", r"\bimmediately\b", r"within \d+ hours?", r"\bfinal (notice|warning)\b",
                r"\bact now\b", r"\bexpires? (today|soon)\b", r"\blast chance\b", r"\btime[- ]sensitive\b"],
    "account threat": [r"\b(account|mailbox|access) (has been |will be )?(suspended|locked|disabled|closed|restricted)\b",
                       r"\bunusual (sign[- ]?in|activity|login)\b", r"\bunauthori[sz]ed (access|transaction)\b",
                       r"\bsecurity (alert|breach)\b"],
    "credential request": [r"\bverify (your )?(account|identity|information|details)\b",
                           r"\bconfirm (your )?(password|identity|account|details)\b",
                           r"\b(update|re-?enter) (your )?(payment|billing|password)\b",
                           r"\blog ?in to (avoid|restore|keep)\b", r"\bsign in to (avoid|restore|keep)\b"],
    "secrecy": [r"\bdon'?t (call|tell|mention)\b", r"\bkeep (this|it) (confidential|between us|quiet)\b",
                r"\bjust reply (here|to this)\b", r"\bi'?m in (a meeting|meetings|back-to-back)", r"\bcan'?t talk\b"],
    "money": [r"\bgift ?cards?\b", r"\bwire transfer\b", r"\bbank details\b", r"\boverdue invoice\b",
              r"\brefund (is )?(pending|available)\b", r"\bcrypto(currency)? (wallet|payment)\b",
              r"\bpayment (failed|declined)\b"],
}

DANGEROUS_EXT = {".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
                 ".wsf", ".hta", ".ps1", ".msi", ".lnk", ".jar", ".cpl", ".reg", ".dll", ".one"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xlsb"}
CONTAINER_EXT = {".iso", ".img", ".vhd", ".vhdx", ".zip", ".rar", ".7z", ".ace", ".cab"}
HTML_EXT = {".html", ".htm", ".shtml", ".svg", ".xhtml"}
DOC_LIKE_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".ppt", ".pptx"}

URL_RE = re.compile(r"""\bhttps?://[^\s<>"'()\[\]]+""", re.IGNORECASE)
DOMAINISH_RE = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", re.IGNORECASE)

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


# --------------------------------------------------------------------------- data model

@dataclass
class Finding:
    check: str
    severity: str  # high | medium | low | info
    points: int
    title: str
    detail: str


@dataclass
class Report:
    file: str
    subject: str
    sender: str
    score: int = 0
    verdict: str = "low"
    findings: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)

    def add(self, *args):
        self.findings.append(Finding(*args))


# --------------------------------------------------------------------------- helpers

def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 without a public-suffix list (good enough for triage)."""
    host = (host or "").strip().strip(".").lower()
    if host.startswith("[") or _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in MULTI_PART_SUFFIXES and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of(address: str) -> str:
    return address.rpartition("@")[2].strip().strip(">").lower() if "@" in address else ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def label(brand: str) -> str:
    return BRAND_LABELS.get(brand, brand.title())


def normalize_homoglyphs(text: str) -> str:
    text = text.lower()
    for fake, real in HOMOGLYPHS:
        text = text.replace(fake, real)
    return text


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def impersonated_brand(domain: str) -> str | None:
    """Return the brand a domain imitates, or None if it is legitimate / unrelated."""
    reg = registrable_domain(domain)
    if not reg or _is_ip(reg):
        return None
    label = reg.split(".")[0]
    normalized = normalize_homoglyphs(label)
    tokens = [t for t in re.split(r"[^a-z0-9]+", normalized) if t]
    for brand, legit in BRANDS.items():
        if reg in legit or domain.lower() in legit:
            continue
        if normalized.replace("-", "") == brand or brand in tokens:
            return brand
        # one-character typos only for longer brands, so "apply" is not mistaken for "apple"
        if len(brand) >= 6 and any(len(t) >= 5 and levenshtein(t, brand) == 1 for t in tokens):
            return brand
    return None


ALL_LEGIT = set().union(*BRANDS.values())


def brand_in_subdomain(host: str) -> str | None:
    """Catch hosts like paypal.com.account-check.xyz or login.apple.com.verify.top."""
    host = host.lower()
    reg = registrable_domain(host)
    if reg in ALL_LEGIT or not host.endswith(reg):
        return None
    padded = "." + host[: -len(reg)].strip(".") + "."
    for legit in sorted(ALL_LEGIT):
        if "." + legit + "." in padded:
            return legit
    return None


class _LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []  # (href, visible text)
        self.forms: list[str] = []
        self._href = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self._href, self._text = attrs["href"].strip(), []
        elif tag == "form":
            self.forms.append(attrs.get("action") or "")

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None


def body_parts(msg: EmailMessage) -> tuple[str, str]:
    plain, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            text = part.get_content()
        except Exception:  # malformed charset / encoding - degrade gracefully
            payload = part.get_payload(decode=True) or b""
            text = payload.decode("utf-8", errors="replace")
        (plain if ctype == "text/plain" else html_parts).append(text)
    return "\n".join(plain), "\n".join(html_parts)


def strip_html(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", markup)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", markup))


# --------------------------------------------------------------------------- checks

def check_authentication(msg: EmailMessage, r: Report) -> None:
    results = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    if not results:
        r.add("auth-missing", "info", 0, "No Authentication-Results header",
              "The receiving server did not record SPF/DKIM/DMARC results, so sender authenticity cannot be confirmed.")
        return
    found = {m.group(1).lower(): m.group(2).lower()
             for m in re.finditer(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", results, re.IGNORECASE)}
    weights = {"dmarc": 25, "spf": 15, "dkim": 15}
    for mech in ("dmarc", "spf", "dkim"):
        value = found.get(mech)
        if value in ("fail", "permerror"):
            r.add(f"{mech}-fail", "high", weights[mech], f"{mech.upper()} failed",
                  f"The receiving server reported {mech}={value}: the message was not authorized by the domain it claims to come from.")
        elif value == "softfail":
            r.add(f"{mech}-softfail", "medium", 8, f"{mech.upper()} soft-failed",
                  "The sending server is not explicitly authorized by the sender's domain.")
        elif value in ("none", "neutral", "temperror") or value is None:
            r.add(f"{mech}-none", "low", 3, f"No passing {mech.upper()} result",
                  f"{mech}={value or 'absent'}; the sender's domain gives no strong proof of authenticity.")


def check_sender(msg: EmailMessage, r: Report) -> None:
    display, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = domain_of(from_addr)
    from_reg = registrable_domain(from_domain)

    reply_to = [a for _, a in getaddresses([str(h) for h in msg.get_all("Reply-To", [])]) if "@" in a]
    for addr in reply_to:
        reg = registrable_domain(domain_of(addr))
        if reg and from_reg and reg != from_reg:
            sev, pts = ("high", 20) if reg in FREEMAIL else ("medium", 12)
            r.add("reply-to-mismatch", sev, pts, "Replies go to a different domain",
                  f"From is {from_addr} but Reply-To is {addr}. Answers would reach someone other than the apparent sender.")
            break

    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    rp_reg = registrable_domain(domain_of(return_path))
    if rp_reg and from_reg and rp_reg != from_reg:
        r.add("return-path-mismatch", "low", 5, "Bounce address uses another domain",
              f"Return-Path is {return_path}. Common for mailing services, but worth a look alongside other signals.")

    embedded = re.search(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", display or "", re.IGNORECASE)
    if embedded and registrable_domain(domain_of(embedded.group(0))) != from_reg:
        r.add("display-name-address", "high", 20, "Display name contains a different address",
              f'Shown as "{display}" but actually sent from {from_addr}.')

    if display:
        disp_norm = normalize_homoglyphs(display)
        for brand, legit in BRANDS.items():
            if re.search(rf"\b{re.escape(brand)}\b", disp_norm) and from_reg not in legit:
                r.add("display-name-brand", "high", 20, f"Display name claims to be {label(brand)}",
                      f'"{display}" is sent from {from_domain or "an unknown domain"}, which is not an official {label(brand)} domain.')
                break

    if display and from_reg in FREEMAIL and re.search(EXECUTIVE_TITLES, display, re.IGNORECASE):
        r.add("freemail-executive", "high", 15, "Executive or finance role on a free-mail account",
              f'"{display}" writes from {from_domain}; executives do not run company business from personal webmail.')

    brand = impersonated_brand(from_domain) if from_domain else None
    if brand:
        r.add("lookalike-sender", "high", 30, f"Sender domain imitates {label(brand)}",
              f"{from_domain} resembles {brand} but is not one of its real domains ({', '.join(sorted(BRANDS[brand])[:3])}).")
    if from_domain.startswith("xn--") or ".xn--" in from_domain:
        r.add("punycode-sender", "medium", 12, "Internationalized (punycode) sender domain",
              f"{from_domain} may render with look-alike Unicode characters.")


def check_links(plain: str, html_body: str, r: Report) -> None:
    collector = _LinkCollector()
    if html_body:
        collector.feed(html_body)
    links = list(collector.links)
    seen = {h for h, _ in links}
    for url in URL_RE.findall(plain):
        url = url.rstrip(".,;:!?")
        if url not in seen:
            links.append((url, ""))
            seen.add(url)

    for action in collector.forms:
        r.add("html-form", "high", 20, "Email contains a form",
              f"An embedded form submits to {action or '(same page)'}; legitimate senders do not collect data inside an email.")
        break

    for href, text in links:
        if href.lower().startswith(("mailto:", "tel:", "#", "cid:")):
            continue
        parts = urlsplit(href if "://" in href else "http://" + href)
        host = (parts.hostname or "").lower()
        if not host:
            continue
        r.urls.append(href)
        reg = registrable_domain(host)

        if text and DOMAINISH_RE.match(text.strip()):
            shown_host = (urlsplit(text if "://" in text else "http://" + text).hostname or "").lower()
            if shown_host and registrable_domain(shown_host) != reg:
                r.add("deceptive-link", "high", 25, "Link text shows a different destination",
                      f'The link reads "{text}" but actually opens {href}.')
        if _is_ip(host):
            r.add("ip-link", "high", 15, "Link points to a raw IP address", f"{href} hides the destination behind a bare IP address.")
        if "@" in (parts.netloc or ""):
            r.add("userinfo-link", "high", 15, "Link uses the user@host trick",
                  f"{href}: everything before '@' is ignored by the browser.")
        brand = impersonated_brand(host)
        if brand:
            r.add("lookalike-link", "high", 20, f"Link domain imitates {label(brand)}", f"{host} is not an official {label(brand)} domain.")
        sub_brand = brand_in_subdomain(host)
        if sub_brand:
            r.add("brand-subdomain-link", "high", 20, "Brand name used as a subdomain",
                  f"{host} starts with {sub_brand} but really belongs to {reg}.")
        if "xn--" in host:
            r.add("punycode-link", "medium", 10, "Link uses a punycode domain", f"{host} may display as look-alike Unicode text.")
        if host in SHORTENERS:
            r.add("shortener-link", "low", 6, "Link uses a URL shortener", f"{href} hides its real destination.")
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            r.add("suspicious-tld", "medium", 8, "Link uses a high-abuse top-level domain", f"{host}")
        if parts.scheme == "http" and not _is_ip(host):
            r.add("plain-http-link", "low", 3, "Unencrypted http:// link", f"{href}")


def check_language(subject: str, text: str, r: Report) -> None:
    haystack = f"{subject}\n{text}".lower()
    hits = {}
    for category, patterns in PRESSURE_LANGUAGE.items():
        for pat in patterns:
            m = re.search(pat, haystack)
            if m:
                hits[category] = m.group(0)
                break
    if not hits:
        return
    sev = "medium" if len(hits) >= 2 else "low"
    pts = min(5 * len(hits), 15)
    examples = "; ".join(f'{cat}: "{phrase}"' for cat, phrase in hits.items())
    r.add("pressure-language", sev, pts, "Pressure or credential-harvesting language", examples)


def check_attachments(msg: EmailMessage, r: Report) -> None:
    for part in msg.iter_attachments():
        name = (part.get_filename() or "").strip()
        if not name:
            continue
        r.attachments.append(name)
        lower = name.lower()
        root, ext = os.path.splitext(lower)
        inner = os.path.splitext(root)[1]
        if inner in DOC_LIKE_EXT and ext and ext not in DOC_LIKE_EXT:
            r.add("double-extension", "high", 30, "Attachment hides its real type",
                  f'"{name}" looks like a {inner} file but is actually {ext}.')
        if ext in DANGEROUS_EXT:
            r.add("executable-attachment", "high", 30, "Executable or script attachment", f'"{name}" can run code when opened.')
        elif ext in MACRO_EXT:
            r.add("macro-attachment", "medium", 15, "Macro-enabled Office document", f'"{name}" can contain VBA macros.')
        elif ext in HTML_EXT:
            r.add("html-attachment", "medium", 15, "HTML/SVG attachment",
                  f'"{name}" opens in a browser - a common way to deliver fake login pages offline.')
        elif ext in CONTAINER_EXT:
            r.add("container-attachment", "medium", 10, "Archive or disk-image attachment",
                  f'"{name}" can be used to smuggle executables past filters.')


# --------------------------------------------------------------------------- scoring / entry points

def score(findings: list[Finding]) -> int:
    """Each check counts once (its highest-weighted hit) so ten bad links do not dominate."""
    best: dict[str, int] = {}
    for f in findings:
        best[f.check] = max(best.get(f.check, 0), f.points)
    return min(100, sum(best.values()))


def verdict_for(total: int) -> str:
    return "high" if total >= 60 else "medium" if total >= 30 else "low"


def analyze_bytes(raw: bytes, name: str = "<message>") -> Report:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    r = Report(file=name, subject=str(msg.get("Subject", "")), sender=str(msg.get("From", "")))
    check_authentication(msg, r)
    check_sender(msg, r)
    plain, html_body = body_parts(msg)
    check_links(plain, html_body, r)
    check_language(r.subject, plain + " " + strip_html(html_body), r)
    check_attachments(msg, r)
    r.findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.points))
    r.score = score(r.findings)
    r.verdict = verdict_for(r.score)
    return r


def analyze_file(path: str) -> Report:
    with open(path, "rb") as fh:
        return analyze_bytes(fh.read(), path)


COLORS = {"high": "\033[1;31m", "medium": "\033[1;33m", "low": "\033[36m", "info": "\033[2m", "reset": "\033[0m"}


def render_text(r: Report, color: bool) -> str:
    c = COLORS if color else {k: "" for k in COLORS}
    label = {"high": "HIGH RISK", "medium": "SUSPICIOUS", "low": "LOW RISK"}[r.verdict]
    lines = [
        f"phish-lens report: {r.file}",
        f"  Subject : {r.subject}",
        f"  From    : {r.sender}",
        f"  Score   : {c[r.verdict]}{r.score}/100  {label}{c['reset']}",
        "",
    ]
    if not r.findings:
        lines.append("  No indicators found.")
    counted = set()
    for f in r.findings:
        pts = f"+{f.points}" if f.check not in counted and f.points else "  -"
        counted.add(f.check)
        lines.append(f"  {c[f.severity]}[{f.severity.upper():6}]{c['reset']} {pts:>4}  {f.title}")
        lines.append(f"                  {f.detail}")
    if r.attachments:
        lines += ["", "  Attachments: " + ", ".join(r.attachments)]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score .eml files for phishing indicators, with explanations.")
    p.add_argument("files", nargs="+", help=".eml files to analyze")
    p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--exit-code", action="store_true",
                   help="exit 0/1/2 for the worst verdict (low/suspicious/high) - handy in scripts")
    args = p.parse_args(argv)

    reports = []
    for path in args.files:
        try:
            reports.append(analyze_file(path))
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 3

    if args.json:
        payload = [asdict(r) for r in reports]
        print(json.dumps(payload[0] if len(payload) == 1 else payload, indent=2, ensure_ascii=False))
    else:
        color = sys.stdout.isatty() and not args.no_color and os.environ.get("NO_COLOR") is None
        print("\n\n".join(render_text(r, color) for r in reports))

    if args.exit_code:
        return max({"low": 0, "medium": 1, "high": 2}[r.verdict] for r in reports)
    return 0


if __name__ == "__main__":
    sys.exit(main())
