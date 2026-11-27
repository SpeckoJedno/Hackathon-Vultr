"""Email parsing + cheap static checks. Runs in the backend, but only *reads*
the email as data: nothing is rendered, fetched or executed here."""
from __future__ import annotations

import email
import hashlib
import re
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

BRANDS = {
    "microsoft": ["microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com", "sharepoint.com"],
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.de", "amazon.se"],
    "netflix": ["netflix.com"],
    "dhl": ["dhl.com", "dhl.se"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "vultr": ["vultr.com"],
}
URGENCY = ["urgent", "immediately", "within 24 hours", "suspended", "verify your account",
           "confirm your identity", "unusual activity", "expires today", "final notice",
           "action required", "overdue", "late fee", "locked"]
INJECTION_RE = re.compile(
    r"(ignore (all |any )?(the )?(previous|prior|above) instructions|note to ai|for the ai|"
    r"ai (email )?(scanner|analyst|assistant)s?|system message|you are (an? )?(ai|assistant|language model)|"
    r"(classify|mark|report|label) (this|it|the email|this email|this page)[^.\n]{0,40}\b(safe|legitimate|clean)\b|"
    r"verdict[^.\n]{0,10}\bsafe\b)",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
MAX_LINKS = 25


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append({"url": self._href.strip(), "text": " ".join("".join(self._text).split())[:200]})
            self._href = None


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def base_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _leet(s: str) -> str:
    return s.translate(str.maketrans("01345@$", "oleasas"))


def brand_impersonation(host: str) -> str | None:
    """Return a brand name if `host` looks like a brand but is not one of its real domains."""
    if not host:
        return None
    for brand, legit in BRANDS.items():
        if brand in _leet(host).replace("-", "") and base_domain(host) not in legit:
            return brand
    return None


def is_brand_domain(host: str, brand: str | None) -> bool:
    if not brand:
        return False
    return base_domain(host) in BRANDS.get(brand.lower(), [])


def parse_email(raw: bytes) -> dict:
    msg = email.message_from_bytes(raw, policy=policy.default)
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    from_domain = from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else ""

    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or "unnamed.bin",
                "content_type": ctype,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "_data": payload,
            })
        elif ctype == "text/plain":
            text_parts.append(_safe_text(part))
        elif ctype == "text/html":
            html_parts.append(_safe_text(part))

    links: list[dict] = []
    for html in html_parts:
        p = _Links()
        try:
            p.feed(html)
        except Exception:  # noqa: BLE001
            pass
        links += p.links
    for text in text_parts:
        links += [{"url": u.rstrip(".,;"), "text": ""} for u in URL_RE.findall(text)]

    seen, uniq = set(), []
    for link in links:
        u = link["url"]
        if not u.lower().startswith(("http://", "https://")) or u in seen:
            continue
        seen.add(u)
        shown = URL_RE.search(link["text"]) or re.search(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", link["text"], re.I)
        shown_host = host_of(shown.group(0) if shown and shown.group(0).startswith("http") else
                             "http://" + shown.group(0)) if shown else ""
        link["host"] = host_of(u)
        link["text_mismatch"] = bool(shown_host and base_domain(shown_host) != base_domain(link["host"]))
        link["shown_host"] = shown_host
        uniq.append(link)
    uniq = uniq[:MAX_LINKS]

    body = "\n".join(text_parts).strip()
    if not body and html_parts:
        t = _Text()
        t.feed("\n".join(html_parts))
        body = " ".join(" ".join(t.parts).split())

    auth = str(msg.get("Authentication-Results", "")).lower()
    parsed = {
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "reply_to": reply_to,
        "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "(no subject)")),
        "date": str(msg.get("Date", "")),
        "auth": {k: (re.search(rf"{k}=(\w+)", auth).group(1) if re.search(rf"{k}=(\w+)", auth) else None)
                 for k in ("spf", "dkim", "dmarc")},
        "body": body[:20000],
        "links": uniq,
        "attachments": attachments,
    }
    parsed["static_findings"] = static_findings(parsed)
    return parsed


def _safe_text(part) -> str:
    try:
        return part.get_content()
    except Exception:  # noqa: BLE001
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", "replace")


def static_findings(p: dict) -> list[dict]:
    """Deterministic header/body red flags. level: 1 = suspicious, 2 = dangerous."""
    out: list[dict] = []

    def add(level: int, msg: str) -> None:
        out.append({"level": level, "source": "email", "reason": msg})

    a = p["auth"]
    if a.get("spf") in ("fail", "softfail") or a.get("dmarc") == "fail":
        add(1, f"Sender authentication failed (SPF={a.get('spf')}, DMARC={a.get('dmarc')})")
    brand = brand_impersonation(p["from_domain"])
    if brand:
        add(2, f"Sender domain {p['from_domain']} imitates {brand.title()}")
    name = (p["from_name"] or "").lower()
    for b, legit in BRANDS.items():
        if b in name and p["from_domain"] and base_domain(p["from_domain"]) not in legit:
            add(1, f"Display name says '{p['from_name']}' but mail comes from {p['from_domain']}")
            break
    if p["reply_to"] and "@" in p["reply_to"] and \
            base_domain(p["reply_to"].rsplit("@", 1)[-1].lower()) != base_domain(p["from_domain"]):
        add(1, f"Reply-To ({p['reply_to']}) differs from sender domain")
    for link in p["links"]:
        if link["text_mismatch"]:
            add(2, f"Link text shows {link['shown_host']} but really goes to {link['host']}")
        b = brand_impersonation(link["host"])
        if b:
            add(2, f"Link domain {link['host']} imitates {b.title()}")
        if re.fullmatch(r"[\d.]+", link["host"] or ""):
            add(1, f"Link points to a raw IP address: {link['host']}")
    body = (p["subject"] + "\n" + p["body"]).lower()
    hits = [w for w in URGENCY if w in body]
    if len(hits) >= 2:
        add(1, "Pressure language: " + ", ".join(hits[:4]))
    m = INJECTION_RE.search(p["subject"] + "\n" + p["body"])
    if m:
        add(2, f"Email contains instructions aimed at AI scanners (prompt injection): \"{m.group(0)[:80]}\"")
    return out
