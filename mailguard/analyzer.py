"""Static email analyzer. Standard library only, so it can run inside a
network-less sandbox container. Never executes anything from the email.

Usage:  python3 analyzer.py message.eml   -> prints a JSON report
"""
from __future__ import annotations

import email
import hashlib
import json
import math
import re
import sys
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# Built from pieces so this source file itself is not flagged by antivirus.
_EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()

BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "vultr": ["vultr.com"],
    "bank": [],  # generic: any "bank" display name from a free/odd domain is suspicious
}
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "gmx.com"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "zip", "mov", "ru", "tk", "gq", "cf", "work", "support"}
EXEC_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf",
            "ps1", "hta", "msi", "jar", "lnk", "iso", "sh", "py", "dll"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png", "zip"}
SCRIPT_EXT = {"py", "sh"}  # what the dynamic sandbox knows how to run
URGENCY = ["urgent", "immediately", "within 24 hours", "account will be suspended",
           "verify your account", "confirm your identity", "unusual activity",
           "password expires", "final notice", "act now", "locked"]
CODE_PATTERNS = {
    "base64 decode + exec": rb"(b64decode|base64\s+-d|FromBase64String).{0,200}(exec|eval|Invoke-Expression|\| *sh)",
    "eval/exec of dynamic code": rb"\b(eval|exec)\s*\(",
    "PowerShell encoded command": rb"powershell[^\n]{0,80}-e(nc|ncodedcommand)?\s",
    "VBA auto-run macro": rb"(AutoOpen|Document_Open|Workbook_Open)",
    "shell spawning": rb"(os\.system|subprocess|WScript\.Shell|/bin/sh|cmd\.exe)",
    "download cradle": rb"(curl|wget|Invoke-WebRequest|urllib\.request|DownloadString)",
    "credential file access": rb"(\.ssh/id_|\.aws/credentials|/etc/shadow|\.env\b)",
    "destructive command": rb"rm\s+-rf\s+/",
}


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[dict] = []
        self._href = None
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
            self.links.append({"href": self._href, "text": "".join(self._text).strip()})
            self._href = None


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _base(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return -sum(c / len(data) * math.log2(c / len(data)) for c in counts if c)


def _close(a: str, b: str) -> bool:
    """Edit distance <= 2 (cheap lookalike-domain check)."""
    if abs(len(a) - len(b)) > 2:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1] <= 2


def _leet(s: str) -> str:
    return s.translate(str.maketrans("01345@$", "oleasas"))


def analyze_url(url: str) -> list[dict]:
    """Static checks on one URL. Never fetches it."""
    out = []
    host = _host(url)
    if not host:
        return out
    if re.fullmatch(r"[\d.]+", host):
        out.append(_f("high", "link", f"Link points to a raw IP address: {host}"))
    if host.startswith("xn--") or ".xn--" in host:
        out.append(_f("high", "link", f"Punycode (possible homoglyph) domain: {host}"))
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        out.append(_f("medium", "link", f"Link uses a high-abuse TLD: {host}"))
    if "@" in (urlparse(url).netloc or ""):
        out.append(_f("high", "link", f"URL hides real host behind '@': {url}"))
    for brand, legit in BRANDS.items():
        if brand != "bank" and brand in _leet(host) and _base(host) not in legit:
            out.append(_f("high", "link", f"Domain imitates {brand.title()} but is {host}"))
    return out


def _f(severity: str, category: str, detail: str) -> dict:
    return {"severity": severity, "category": category, "detail": detail}


def analyze(raw: bytes) -> dict:
    msg = email.message_from_bytes(raw, policy=policy.default)
    findings: list[dict] = []

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = _domain(from_addr)
    reply_dom = _domain(parseaddr(str(msg.get("Reply-To", "")))[1])
    return_dom = _domain(parseaddr(str(msg.get("Return-Path", "")))[1])

    # --- authentication results -----------------------------------------
    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []) or []).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if m and m.group(1) in ("fail", "softfail", "permerror"):
            findings.append(_f("high" if mech != "dkim" else "medium", "auth",
                               f"{mech.upper()} check result: {m.group(1)}"))
    if not auth:
        findings.append(_f("low", "auth", "No Authentication-Results header (SPF/DKIM/DMARC unknown)"))

    # --- sender identity -------------------------------------------------
    name_l = _leet(from_name.lower())
    for brand, legit in BRANDS.items():
        if brand in name_l and from_dom and (_base(from_dom) not in legit if legit else from_dom in FREE_MAIL or from_dom.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS):
            findings.append(_f("high", "sender",
                               f"Display name '{from_name}' claims {brand.title()} but sender domain is {from_dom}"))
    findings += [dict(x, category="sender") for x in analyze_url(f"http://{from_dom}/")
                 if "imitates" in x["detail"] or "TLD" in x["detail"]]
    to_dom = _domain(parseaddr(str(msg.get("To", "")))[1])
    if to_dom and from_dom and from_dom != to_dom and _close(from_dom, to_dom):
        findings.append(_f("high", "sender", f"Sender domain {from_dom} is a lookalike of your domain {to_dom}"))
    if reply_dom and from_dom and _base(reply_dom) != _base(from_dom):
        findings.append(_f("medium", "sender", f"Reply-To domain ({reply_dom}) differs from From ({from_dom})"))
    if return_dom and from_dom and _base(return_dom) != _base(from_dom):
        findings.append(_f("low", "sender", f"Return-Path domain ({return_dom}) differs from From ({from_dom})"))

    # --- body & links ----------------------------------------------------
    text_parts, links = [], []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        ctype = part.get_content_type()
        if fname or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append((fname or "unnamed", ctype, payload))
            continue
        if ctype in ("text/plain", "text/html"):
            try:
                body = part.get_content()
            except Exception:
                body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            text_parts.append(body)
            if ctype == "text/html":
                p = _LinkParser()
                p.feed(body)
                links += p.links
            else:
                links += [{"href": u, "text": ""} for u in re.findall(r"https?://[^\s<>\"')]+", body)]

    full_text = "\n".join(text_parts)
    hits = [w for w in URGENCY if w in full_text.lower()]
    if hits:
        findings.append(_f("medium" if len(hits) > 1 else "low", "content",
                           f"Pressure/urgency language: {', '.join(hits)}"))
    if re.search(r"(password|passcode|card number|cvv|social security)", full_text, re.I) and links:
        findings.append(_f("medium", "content", "Asks for credentials or payment data and contains links"))

    seen = set()
    for link in links:
        href, label = link["href"], link["text"]
        if not href or href in seen:
            continue
        seen.add(href)
        h = _host(href)
        shown = _host(label if "://" in label else "http://" + label) if re.search(r"\w\.\w", label) else ""
        if shown and h and _base(shown) != _base(h):
            findings.append(_f("high", "link", f"Link text shows '{label}' but goes to {h}"))
        findings += analyze_url(href)

    # --- attachments -----------------------------------------------------
    att_report = []
    for fname, ctype, data in attachments:
        exts = [e.lower() for e in fname.split(".")[1:]]
        last = exts[-1] if exts else ""
        info = {
            "filename": fname,
            "content_type": ctype,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "entropy": round(_entropy(data), 2),
            "runnable_in_sandbox": last in SCRIPT_EXT,
            "patterns": [],
        }
        if len(exts) >= 2 and exts[-2] in DOC_EXT and last in EXEC_EXT:
            findings.append(_f("critical", "attachment", f"Disguised executable: '{fname}' looks like .{exts[-2]} but is .{last}"))
        elif last in EXEC_EXT:
            findings.append(_f("high", "attachment", f"Executable/script attachment: {fname}"))
        if last in MACRO_EXT:
            findings.append(_f("high", "attachment", f"Macro-enabled Office document: {fname}"))
        if "‮" in fname:
            findings.append(_f("critical", "attachment", f"Right-to-left override in filename: {fname!r}"))
        if data[:2] == b"MZ":
            findings.append(_f("critical", "attachment", f"{fname} is a Windows PE executable (MZ header)"))
        if _EICAR in data:
            findings.append(_f("critical", "attachment", f"{fname} contains the EICAR antivirus test signature"))
        for label, pat in CODE_PATTERNS.items():
            if re.search(pat, data, re.I | re.S):
                info["patterns"].append(label)
        if info["patterns"]:
            findings.append(_f("high" if len(info["patterns"]) > 1 else "medium", "attachment",
                               f"{fname} contains suspicious code patterns: {', '.join(info['patterns'])}"))
        if info["entropy"] > 7.5 and last not in {"zip", "png", "jpg", "pdf", "gz"}:
            findings.append(_f("medium", "attachment", f"{fname} has very high entropy ({info['entropy']}): packed or encrypted"))
        att_report.append(info)

    weights = {"critical": 60, "high": 25, "medium": 10, "low": 3}
    score = min(100, sum(weights[f["severity"]] for f in findings))
    verdict = "malicious" if score >= 50 else "suspicious" if score >= 20 else "clean"

    return {
        "headers": {
            "from": str(msg.get("From", "")),
            "reply_to": str(msg.get("Reply-To", "")),
            "to": str(msg.get("To", "")),
            "subject": str(msg.get("Subject", "")),
            "date": str(msg.get("Date", "")),
        },
        "body_excerpt": full_text[:1500],
        "links": [l["href"] for l in links][:30],
        "attachments": att_report,
        "findings": findings,
        "risk_score": score,
        "static_verdict": verdict,
    }


def extract_attachment(raw: bytes, filename: str) -> bytes | None:
    msg = email.message_from_bytes(raw, policy=policy.default)
    for part in msg.walk():
        if part.get_filename() == filename:
            return part.get_payload(decode=True) or b""
    return None


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as fh:
        print(json.dumps(analyze(fh.read()), indent=2))
