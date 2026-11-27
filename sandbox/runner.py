"""MailGuard sandbox runner. Runs INSIDE a throwaway container.

Reads one JSON job on stdin, writes newline-delimited JSON events on stdout:
  {"t": "log",    "msg": "..."}
  {"t": "shot",   "label": "...", "url": "...", "b64": "<jpeg>"}
  {"t": "result", "data": {...}}

Modes:
  link   open a URL in headless Chromium, record redirects, forms, scripts, downloads
  file   statically inspect an attachment (never executed)
  probe  containment self-test: prove what this container can and cannot reach

Everything this script sees (pages, files) is hostile. It never executes
attachments and never opens downloaded files.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import os
import re
import socket
import sys
import time
import urllib.request
import zipfile
from urllib.parse import urlparse

# Built from pieces so this source file itself is not flagged by antivirus.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()
URL_RE = re.compile(rb"https?://[^\s\"'<>\\)\]]{4,300}", re.I)


def emit(t: str, **kw) -> None:
    sys.stdout.write(json.dumps({"t": t, **kw}) + "\n")
    sys.stdout.flush()


def log(msg: str) -> None:
    emit("log", msg=msg)


# --------------------------------------------------------------------------- link

SCRIPT_PATTERNS = {
    "eval() of dynamic code": r"\beval\s*\(",
    "atob()/base64 decoding": r"\batob\s*\(",
    "document.write injection": r"document\.write\s*\(",
    "unescape/fromCharCode obfuscation": r"(unescape\s*\(|String\.fromCharCode)",
    "keystroke capture": r"addEventListener\s*\(\s*['\"]key(down|up|press)",
    "sends data with fetch/XHR/beacon": r"(fetch\s*\(|XMLHttpRequest|sendBeacon)",
    "reads cookies/localStorage": r"(document\.cookie|localStorage)",
    "JS redirect": r"(location\.(href|replace|assign)|window\.location\s*=)",
    "forces a file download": r"(\.download\s*=|msSaveBlob|createObjectURL)",
    "probes internal network": r"(169\.254\.169\.254|127\.0\.0\.1|localhost|192\.168\.|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.)",
}

PAGE_INFO_JS = """
() => {
  const forms = [...document.querySelectorAll('form')].map(f => ({
    action: f.action || '', method: (f.method || 'get').toLowerCase(),
    inputs: [...f.querySelectorAll('input')].map(i => ({type: (i.type||'text').toLowerCase(), name: i.name || i.id || ''}))
  }));
  const loosePw = document.querySelectorAll('input[type=password]').length;
  const scripts = [...document.scripts];
  return {
    title: document.title || '',
    forms, password_inputs: loosePw,
    inline_scripts: scripts.filter(s => !s.src).map(s => (s.textContent || '').slice(0, 20000)).slice(0, 30),
    external_scripts: scripts.filter(s => s.src).map(s => s.src).slice(0, 50),
    iframes: [...document.querySelectorAll('iframe')].map(f => f.src).slice(0, 20),
    meta_refresh: [...document.querySelectorAll('meta[http-equiv]')]
        .filter(m => m.httpEquiv.toLowerCase() === 'refresh').map(m => m.content),
    text: (document.body ? document.body.innerText : '').slice(0, 4000),
    links: [...document.querySelectorAll('a[href]')].map(a => a.href).slice(0, 40),
  };
}
"""


def run_link(job: dict) -> None:
    from playwright.sync_api import sync_playwright, Error as PWError

    url = job["url"]
    budget = float(job.get("budget_s", 40))
    t0 = time.time()
    requests, failed, downloads, navigations, dialogs = [], [], [], [], []

    with sync_playwright() as p:
        log("Launching headless Chromium inside the sandbox")
        browser = p.chromium.launch(headless=True, args=["--disable-gpu", "--no-first-run"])
        ctx = browser.new_context(
            viewport={"width": 1280, "height": 800},
            accept_downloads=True,
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        page = ctx.new_page()

        page.on("request", lambda r: len(requests) < 300 and requests.append(r.url))
        pending: dict = {}
        page.on("request", lambda r: pending.__setitem__(id(r), r.url))
        page.on("requestfinished", lambda r: pending.pop(id(r), None))
        page.on("requestfailed", lambda r: (pending.pop(id(r), None),
                                            failed.append({"url": r.url, "error": r.failure or "failed"})))
        page.on("dialog", lambda d: (dialogs.append(d.message[:300]), d.dismiss()))

        def on_nav(frame):
            if frame == page.main_frame and frame.url not in ("about:blank", ""):
                if not navigations or navigations[-1] != frame.url:
                    navigations.append(frame.url)
        page.on("framenavigated", on_nav)

        def on_download(d):
            try:
                path = f"/tmp/dl_{len(downloads)}"
                d.save_as(path)
                data = open(path, "rb").read()
                downloads.append({
                    "filename": d.suggested_filename, "url": d.url, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "eicar": EICAR in data, "magic": data[:4].hex(),
                })
                log(f"Page triggered a download: {d.suggested_filename} (saved, NOT opened)")
            except Exception as e:  # noqa: BLE001
                downloads.append({"filename": d.suggested_filename, "url": d.url, "error": str(e)[:200]})
        page.on("download", on_download)

        status, error, http_hops = None, None, []
        log(f"Opening {url}")
        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=20000)
            if resp is not None:
                status = resp.status
                r = resp.request.redirected_from
                while r is not None:  # HTTP 3xx hops never "commit", so collect them here
                    http_hops.insert(0, r.url)
                    r = r.redirected_from
        except PWError as e:
            error = str(e).split("\n")[0][:300]
            log(f"Navigation error: {error}")

        def shot(label: str) -> None:
            try:
                b = page.screenshot(type="jpeg", quality=60, timeout=8000)
                emit("shot", label=label, url=page.url, b64=base64.b64encode(b).decode())
                log(f"Screenshot taken: {label}")
            except Exception as e:  # noqa: BLE001
                log(f"Screenshot failed ({label}): {str(e)[:120]}")

        shot("first paint")
        # Give JS redirects, meta refreshes and late scripts time to run.
        try:
            page.wait_for_load_state("networkidle", timeout=min(8000, max(1000, (budget - (time.time() - t0)) * 1000)))
        except PWError:
            pass
        page.wait_for_timeout(2500)
        hops = len(http_hops) + max(0, len(navigations) - 1)
        if hops:
            log(f"Followed {hops} redirect(s), now at {page.url}")
        shot("final page")

        info = {}
        try:
            info = page.evaluate(PAGE_INFO_JS)
        except Exception as e:  # noqa: BLE001
            log(f"Could not read page DOM: {str(e)[:120]}")

        suspicious = []
        for s in info.get("inline_scripts", []):
            for label, pat in SCRIPT_PATTERNS.items():
                if re.search(pat, s, re.I) and label not in suspicious:
                    suspicious.append(label)
        if any(len(s) > 5000 and len(re.findall(r"\s", s)) < len(s) / 50 for s in info.get("inline_scripts", [])):
            suspicious.append("large obfuscated script blob")

        final_url = page.url
        final_host = (urlparse(final_url).hostname or "").lower()
        forms = info.get("forms", [])
        pw_forms = [f for f in forms if any(i["type"] == "password" for i in f["inputs"])]
        result = {
            "url": url,
            "final_url": final_url,
            "final_host": final_host,
            "http_status": status,
            "error": error,
            "redirect_chain": (http_hops + [u for u in navigations if u not in http_hops])[:15],
            "title": info.get("title", ""),
            "password_form": bool(pw_forms) or info.get("password_inputs", 0) > 0,
            "forms": [{"action": f["action"][:300], "method": f["method"],
                       "fields": [i["type"] + (":" + i["name"] if i["name"] else "") for i in f["inputs"]][:15]}
                      for f in forms[:5]],
            "form_targets": sorted({(urlparse(f["action"]).hostname or final_host) for f in forms if f["action"]}),
            "suspicious_scripts": suspicious,
            "external_scripts": info.get("external_scripts", [])[:20],
            "iframes": info.get("iframes", []),
            "meta_refresh": info.get("meta_refresh", []),
            "downloads": downloads,
            "dialogs": dialogs[:5],
            "requests": len(requests),
            "request_hosts": sorted({urlparse(u).hostname or "" for u in requests if u.startswith("http")})[:40],
            "blocked_requests": ([f for f in failed if "ERR_ABORTED" not in f["error"]]
                                 + [{"url": u, "error": "no response (dropped)"} for u in pending.values()
                                    if u.startswith("http")])[:20],
            "page_text": info.get("text", ""),
            "elapsed_s": round(time.time() - t0, 1),
        }
        browser.close()
    emit("result", data=result)


# --------------------------------------------------------------------------- file

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in counts if c), 2)


EXEC_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf", "ps1",
            "hta", "msi", "jar", "lnk", "iso", "img", "dll", "sh", "py", "reg", "cpl"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}


def run_file(job: dict) -> None:
    name = os.path.basename(job.get("filename") or "attachment.bin")[:120]
    data = base64.b64decode(job["b64"])
    os.makedirs("/tmp/sample", exist_ok=True)
    path = "/tmp/sample/sample.bin"  # neutral name, no extension, on a noexec tmpfs
    with open(path, "wb") as fh:
        fh.write(data)
    log(f"Copied {name} ({len(data)} bytes) into the sandbox at {path} (noexec, never run)")

    findings: list[dict] = []

    def add(sev: str, msg: str) -> None:
        findings.append({"severity": sev, "detail": msg})

    ftype, mime = "unknown", "application/octet-stream"
    try:
        import puremagic  # pure-Python libmagic replacement
        m = puremagic.magic_string(data)
        if m:
            ftype, mime = m[0].name or m[0].extension, m[0].mime_type or mime
    except Exception:  # noqa: BLE001
        pass
    if data[:5] == b"%PDF-":
        ftype, mime = "PDF document", "application/pdf"
    elif data[:4] == b"\xd0\xcf\x11\xe0":
        ftype, mime = "CDF V2 (legacy Office / OLE)", "application/msword"
    elif ftype == "unknown" and all(32 <= c < 127 or c in (9, 10, 13) for c in data[:4096]):
        ftype, mime = "ASCII text", "text/plain"
    log(f"File type: {ftype[:120]}")
    parts = name.lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""

    if EICAR in data:
        add("critical", "Contains the EICAR antivirus test signature (treated as malware)")
    if data[:2] == b"MZ":
        add("high", "Windows executable (PE / MZ header)")
        if ext not in {"exe", "dll", "scr", "com"}:
            add("high", f"Executable disguised as .{ext or 'no extension'}")
    if data[:4] == b"\x7fELF":
        add("high", "Linux executable (ELF)")
    if ext in EXEC_EXT:
        add("high", f"Dangerous file extension .{ext}")
    if len(parts) > 2 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip"}:
        add("high", f"Double extension trick: {name}")
    if ext in MACRO_EXT:
        add("medium", f"Macro-enabled Office format .{ext}")

    urls: set[str] = set()
    blobs = [data]

    # ZIP / OOXML containers: list members, look inside XML for links
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                members = z.namelist()[:200]
                log(f"Archive with {len(members)} entries")
                for m in members:
                    mext = m.lower().rsplit(".", 1)[-1] if "." in m else ""
                    if mext in EXEC_EXT:
                        add("high", f"Archive contains executable: {m}")
                    if m.lower().endswith("vbaproject.bin"):
                        add("high", "Office document contains a VBA macro project")
                    info = z.getinfo(m)
                    if info.file_size < 5_000_000 and not info.flag_bits & 0x1:
                        try:
                            blobs.append(z.read(m))
                        except Exception:  # noqa: BLE001
                            pass
                    elif info.flag_bits & 0x1:
                        add("medium", f"Password-protected archive member: {m} (common AV evasion)")
        except zipfile.BadZipFile:
            pass

    # Office macros (OLE + OOXML) via oletools
    macros = []
    if "officedocument" in mime or "msword" in mime or "ms-excel" in mime or "CDF V2" in ftype or ext in MACRO_EXT:
        try:
            from oletools.olevba import VBA_Parser
            vp = VBA_Parser(path, data=data)
            if vp.detect_vba_macros():
                for kw_type, kw, desc in vp.analyze_macros():
                    if kw_type in ("AutoExec", "Suspicious", "IOC"):
                        macros.append(f"{kw_type}: {kw}")
                add("high", "VBA macros present" + (f" ({', '.join(macros[:4])})" if macros else ""))
            vp.close()
        except Exception as e:  # noqa: BLE001
            log(f"olevba: {str(e)[:100]}")

    if data[:5] == b"%PDF-":
        for kw, sev in [(b"/JavaScript", "high"), (b"/JS", "medium"), (b"/OpenAction", "medium"),
                        (b"/Launch", "high"), (b"/EmbeddedFile", "medium"), (b"/AcroForm", "low")]:
            if kw in data:
                add(sev, f"PDF contains {kw.decode()}")

    for b in blobs:
        for m in URL_RE.findall(b):
            u = m.decode("latin-1").rstrip(".,;")
            if not re.search(r"(schemas\.openxmlformats|schemas\.microsoft|purl\.org|w3\.org|openxmlformats)", u):
                urls.add(u)
    if urls:
        add("low", f"{len(urls)} embedded link(s) found")
    ent = entropy(data[:2_000_000])
    if ent > 7.5 and data[:2] != b"PK" and not mime.startswith(("image/", "video/", "audio/")):
        add("medium", f"Very high entropy ({ent}) - packed or encrypted content")

    result = {
        "filename": name, "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "file_type": ftype[:200], "mime": mime, "entropy": ent,
        "macros": macros[:20], "embedded_urls": sorted(urls)[:30],
        "findings": findings, "executed": False,
    }
    log(f"SHA-256 {result['sha256']}")
    emit("result", data=result)


# --------------------------------------------------------------------------- probe

def try_http(url: str, timeout: float = 4) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return f"REACHABLE (HTTP {r.status})"
    except urllib.error.HTTPError as e:
        return f"REACHABLE (HTTP {e.code})"
    except Exception as e:  # noqa: BLE001
        return f"blocked ({type(e).__name__}: {str(e)[:60]})"


def try_write(path: str) -> str:
    try:
        with open(path, "w") as fh:
            fh.write("x")
        os.remove(path)
        return "WRITABLE"
    except Exception as e:  # noqa: BLE001
        return f"blocked ({type(e).__name__})"


def gateway_ip() -> str:
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000":
                return socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
    except Exception:  # noqa: BLE001
        pass
    return ""


def run_probe(job: dict) -> None:
    checks = []

    def check(name: str, value: str, ok: bool) -> None:
        checks.append({"check": name, "value": value, "contained": ok})
        log(f"{'OK ' if ok else '!! '} {name}: {value}")

    uid = os.getuid()
    check("Runs as non-root user", f"uid={uid}", uid != 0)
    secret_env = [k for k in os.environ if re.search(r"KEY|TOKEN|SECRET|PASSWORD|VULTR", k, re.I)]
    check("No secrets in environment", ", ".join(secret_env) or "none found", not secret_env)
    check("Docker socket not mounted", "present" if os.path.exists("/var/run/docker.sock") else "absent",
          not os.path.exists("/var/run/docker.sock"))
    cap = "?"
    for line in open("/proc/self/status"):
        if line.startswith("CapEff"):
            cap = line.split()[1]
    check("All capabilities dropped", f"CapEff={cap}", cap.strip("0") == "")
    nnp = next((line.split()[1] for line in open("/proc/self/status") if line.startswith("NoNewPrivs")), "?")
    check("no-new-privileges", f"NoNewPrivs={nnp}", nnp == "1")
    r = try_write("/opt/mailguard/pwned")
    check("Root filesystem read-only", f"write /opt -> {r}", "blocked" in r)
    r = try_write("/etc/pwned")
    check("Cannot modify /etc", f"write /etc -> {r}", "blocked" in r)
    r = try_write("/tmp/scratch")
    check("Scratch space only in /tmp", f"write /tmp -> {r}", r == "WRITABLE")
    mem = "?"
    for p in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        if os.path.exists(p):
            mem = open(p).read().strip()
            break
    mem_ok = mem.isdigit() and int(mem) <= 600 * 1024 * 1024
    check("Memory limit", f"{int(mem) // (1024 * 1024)} MB" if mem.isdigit() else mem, mem_ok)
    cpu = "?"
    if os.path.exists("/sys/fs/cgroup/cpu.max"):
        cpu = open("/sys/fs/cgroup/cpu.max").read().strip()
    elif os.path.exists("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"):
        cpu = open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read().strip() + " us/period"
    check("CPU limit", cpu, cpu not in ("?", "max 100000", "-1 us/period"))

    r = try_http("https://example.com/")
    check("Internet reachable (needed to open links)", r, r.startswith("REACHABLE"))
    r = try_http("http://169.254.169.254/v1.json")
    check("Cloud metadata 169.254.169.254 blocked", r, r.startswith("blocked"))
    gw = gateway_ip()
    if gw:
        r = try_http(f"http://{gw}/")
        check(f"Docker host gateway {gw} blocked", r, r.startswith("blocked"))
    host = job.get("backend_host")
    if host:
        r = try_http(f"http://{host}/api/health")
        check(f"MailGuard backend {host} blocked", r, r.startswith("blocked"))
    for target in ("http://backend:8000/api/health", "http://10.0.0.1/", "http://192.168.0.1/", "http://172.17.0.1/"):
        r = try_http(target, timeout=3)
        check(f"Internal network {urlparse(target).netloc} blocked", r, r.startswith("blocked"))
    emit("result", data={"checks": checks, "all_contained": all(c["contained"] for c in checks)})


def main() -> None:
    try:
        job = json.loads(sys.stdin.read() or "{}")
        mode = job.get("mode")
        if mode == "link":
            run_link(job)
        elif mode == "file":
            run_file(job)
        elif mode == "probe":
            run_probe(job)
        else:
            emit("result", data={"error": f"unknown mode {mode!r}"})
    except Exception as e:  # noqa: BLE001
        emit("result", data={"error": f"{type(e).__name__}: {str(e)[:300]}"})


if __name__ == "__main__":
    main()
