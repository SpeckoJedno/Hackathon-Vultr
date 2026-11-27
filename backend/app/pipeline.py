"""The MailGuard analysis flow for one email."""
from __future__ import annotations

import base64
import logging
import os
import re

from . import llm, sandbox, store
from .parser import INJECTION_RE, brand_impersonation, base_domain, is_brand_domain

log = logging.getLogger("mailguard.pipeline")
LEVELS = ["SAFE", "SUSPICIOUS", "DANGEROUS"]
MAX_LINKS = int(os.getenv("MAX_LINKS", "4"))
_PUB = re.escape(os.getenv("PUBLIC_HOST", "")) or "no-public-host"
INTERNAL_RE = re.compile(r"//(169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|localhost|backend[:/]|"
                         + _PUB + r")")
EXEC_EXT = re.compile(r"\.(exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|wsf|ps1|hta|msi|jar|lnk|iso|dll)$", re.I)


def _choose(plan: dict | None, parsed: dict) -> tuple[list[int], list[int], str]:
    n_links, n_atts = len(parsed["links"]), len(parsed["attachments"])
    links: list[int] = []
    if plan:
        for item in plan.get("links") or []:
            try:
                i = int(item.get("index"))
            except (TypeError, ValueError, AttributeError):
                continue
            if 0 <= i < n_links and item.get("open", True) and i not in links:
                links.append(i)
        note = "model plan"
    else:
        note = "fallback plan (model unavailable): open the first links"
    if not links and n_links:
        links = list(range(n_links))  # policy: a model may not skip every link
        note += "; policy: at least one link is always opened"
    links = links[:MAX_LINKS]
    # Policy floor: every attachment is inspected, whatever the model says.
    atts = list(range(n_atts))
    return links, atts, note


def _page_findings(page: dict, vision: dict | None) -> list[dict]:
    out = []
    host = page.get("final_host") or ""

    def add(level: int, msg: str) -> None:
        out.append({"level": level, "source": "sandbox", "reason": msg})

    if page.get("error") and not page.get("final_url", "").startswith("http"):
        add(0, f"Page could not be loaded: {page['error'][:120]}")
    hops = page.get("redirect_chain") or []
    if len(hops) > 1 and base_domain(host) != base_domain(llm_host(hops[0])):
        add(1, f"Redirected across domains: {llm_host(hops[0])} -> {host}")
    brand_v = (vision or {}).get("looks_like_brand")
    brand_v = brand_v if isinstance(brand_v, str) and brand_v.lower() not in ("", "null", "none") else None
    if page.get("password_form"):
        imitated = brand_impersonation(host)
        if imitated or (brand_v and not is_brand_domain(host, brand_v)):
            add(2, f"Password form on {host} pretending to be {(imitated or brand_v).title()}")
        else:
            add(1, f"Page asks for a password ({host})")
    for t in page.get("form_targets") or []:
        if t and base_domain(t) != base_domain(host):
            add(2 if page.get("password_form") else 1, f"Form sends data to another domain: {t}")
    for d in page.get("downloads") or []:
        if d.get("eicar") or d.get("magic", "").startswith("4d5a") or EXEC_EXT.search(d.get("filename", "")):
            add(2, f"Drive-by download of an executable: {d.get('filename')} (saved in sandbox, never opened)")
        else:
            add(1, f"Page started a download: {d.get('filename')}")
    internal = [b["url"] for b in page.get("blocked_requests") or []
                if INTERNAL_RE.search(b.get("url", ""))]
    if internal:
        add(2, f"Page tried to reach internal/cloud-metadata addresses (blocked by sandbox firewall): "
               + ", ".join(sorted({llm_host(u) for u in internal}))[:200])
    s = page.get("suspicious_scripts") or []
    if len(s) >= 3:
        add(2 if any(x in s for x in ("keystroke capture", "probes internal network")) else 1,
            "Suspicious page scripts: " + ", ".join(s[:6]))
    elif s:
        add(0, "Page scripts: " + ", ".join(s))
    m = INJECTION_RE.search(page.get("page_text") or "")
    if m or (vision or {}).get("prompt_injection_detected") is True:
        add(2, "Page contains hidden instructions aimed at the AI (prompt injection)"
               + (f": \"{m.group(0)[:60]}\"" if m else ""))
    if vision:
        p = vision.get("phishing_likelihood")
        try:
            p = float(p)
        except (TypeError, ValueError):
            p = 0.0
        why = "; ".join(str(r) for r in (vision.get("reasons") or [])[:3])
        if vision.get("is_fake_login") is True or p >= 0.7:
            add(2, f"Vision model: looks like a fake {brand_v or ''} page ({p:.0%}). {why}".replace("  ", " "))
        elif p >= 0.4:
            add(1, f"Vision model: possibly deceptive page ({p:.0%}). {why}")
    return out


def llm_host(url: str) -> str:
    from .parser import host_of
    return host_of(url) or url[:60]


def _file_findings(res: dict) -> list[dict]:
    out = []
    for f in res.get("findings") or []:
        lvl = {"critical": 2, "high": 2, "medium": 1}.get(f.get("severity"), 0)
        out.append({"level": lvl, "source": "attachment", "reason": f"{res.get('filename')}: {f.get('detail')}"})
    if res.get("error"):
        out.append({"level": 1, "source": "attachment", "reason": f"Attachment could not be inspected: {res['error']}"})
    return out


async def analyze(email_id: str, parsed: dict) -> None:
    e = store.emails[email_id]

    def emit(kind: str, msg: str, **data) -> None:
        store.event(email_id, kind, msg, **data)

    findings: list[dict] = list(parsed["static_findings"])
    try:
        emit("parsed", f"Parsed email: {len(parsed['links'])} link(s), {len(parsed['attachments'])} attachment(s)",
             links=[l["url"] for l in parsed["links"]], attachments=[a["filename"] for a in parsed["attachments"]],
             auth=parsed["auth"])
        for f in parsed["static_findings"]:
            emit("finding", f["reason"], level=LEVELS[f["level"]])

        # 1. Plan ------------------------------------------------------------------
        emit("llm", f"Asking {llm.MODEL} on Vultr Serverless Inference for an investigation plan")
        plan, model = await llm.make_plan(parsed)
        link_idx, att_idx, note = _choose(plan, parsed)
        e["plan"] = {"model": model if plan else None, "summary": (plan or {}).get("summary"),
                     "concerns": (plan or {}).get("initial_concerns") or [],
                     "links": [parsed["links"][i]["url"] for i in link_idx],
                     "attachments": [parsed["attachments"][i]["filename"] for i in att_idx], "note": note}
        emit("plan", f"Plan ({note}): open {len(link_idx)} link(s), inspect {len(att_idx)} attachment(s)",
             **e["plan"])

        # 2. Links ------------------------------------------------------------------
        e["pages"] = []
        for i in link_idx:
            url = parsed["links"][i]["url"]
            emit("link", f"Opening link in sandbox browser: {url}")
            shot_meta: list[dict] = []

            def on_shot(s: dict, url: str = url, shot_meta: list = shot_meta) -> None:
                n = len(e["shots"])
                path = store.DATA / "shots" / email_id
                path.mkdir(parents=True, exist_ok=True)
                (path / f"{n}.jpg").write_bytes(base64.b64decode(s["b64"]))
                meta = {"src": f"/shots/{email_id}/{n}.jpg", "label": s.get("label"), "url": s.get("url"), "link": url}
                e["shots"].append(meta)
                shot_meta.append(meta)
                emit("screenshot", f"Screenshot ({s.get('label')}): {s.get('url')}", **meta)

            page, shots = await sandbox.run_job({"mode": "link", "url": url, "budget_s": 40}, emit, url, on_shot)
            emit("page", f"Final URL {page.get('final_url') or '-'} | title {page.get('title')!r} | "
                         f"password form: {'YES' if page.get('password_form') else 'no'} | "
                         f"downloads: {len(page.get('downloads') or [])} | blocked requests: {len(page.get('blocked_requests') or [])}",
                 **{k: page.get(k) for k in ("final_url", "redirect_chain", "password_form", "form_targets",
                                             "suspicious_scripts", "downloads", "blocked_requests", "http_status")})

            vision = None
            if shots:
                emit("llm", f"Vision model {llm.VISION_MODEL} is looking at the final screenshot")
                vision, _ = await llm.judge_screenshot(page, shots[-1]["b64"])
                if vision:
                    emit("vision", f"Vision: {vision.get('page_type')} page, looks like "
                                   f"{vision.get('looks_like_brand') or 'no brand'}, phishing likelihood "
                                   f"{vision.get('phishing_likelihood')}", **vision)
                else:
                    emit("vision", "Vision model unavailable - relying on sandbox evidence only")
            pf = _page_findings(page, vision)
            for f in pf:
                if f["level"]:
                    emit("finding", f["reason"], level=LEVELS[f["level"]])
            findings += pf
            e["pages"].append({"url": url, "result": {k: v for k, v in page.items() if k != "page_text"},
                               "text_excerpt": (page.get("page_text") or "")[:600], "vision": vision,
                               "shots": shot_meta})

        # 3. Attachments --------------------------------------------------------------
        e["files"] = []
        for i in att_idx:
            a = parsed["attachments"][i]
            emit("attachment", f"Copying {a['filename']} into a fresh sandbox for inspection (never executed)")
            res, _ = await sandbox.run_job({"mode": "file", "filename": a["filename"],
                                            "b64": base64.b64encode(a["_data"]).decode()}, emit, a["filename"])
            ff = _file_findings(res)
            emit("file", f"{a['filename']}: {res.get('file_type', '?')} | sha256 {str(res.get('sha256', ''))[:16]}... | "
                         f"{len(res.get('findings') or [])} finding(s)", **{k: v for k, v in res.items()})
            for f in ff:
                if f["level"]:
                    emit("finding", f["reason"], level=LEVELS[f["level"]])
            findings += ff
            e["files"].append(res)

        # 4. Verdict ------------------------------------------------------------------
        floor = max([f["level"] for f in findings], default=0)
        evidence = {
            "static_findings": [f["reason"] for f in parsed["static_findings"]],
            "pages": [{"url": p["url"], **{k: p["result"].get(k) for k in
                       ("final_url", "redirect_chain", "title", "password_form", "form_targets",
                        "suspicious_scripts", "downloads", "blocked_requests", "error")},
                       "vision": p["vision"]} for p in e["pages"]],
            "attachments": [{k: f.get(k) for k in ("filename", "file_type", "sha256", "findings", "macros",
                                                     "embedded_urls")} for f in e["files"]],
            "rule_findings": [f"{LEVELS[f['level']]}: {f['reason']}" for f in findings if f["level"]],
        }
        emit("llm", f"Asking {llm.MODEL} for the final verdict")
        v, _ = await llm.final_verdict(parsed, evidence)
        llm_level = LEVELS.index(str(v.get("verdict", "")).upper()) if v and str(v.get("verdict", "")).upper() in LEVELS else None
        level = max(floor, llm_level if llm_level is not None else 0)
        reasons = [f["reason"] for f in sorted(findings, key=lambda f: -f["level"]) if f["level"]]
        ai_reasons = [str(r) for r in (v or {}).get("reasons") or []][:5]
        if llm_level is not None and llm_level < floor:
            reasons.insert(0, f"Guardrail: the model said {LEVELS[llm_level]}, but sandbox evidence sets the "
                              f"floor at {LEVELS[floor]} (model output cannot lower a verdict)")
        e.update({
            "verdict": LEVELS[level],
            "summary": (v or {}).get("summary") or _fallback_summary(level, reasons),
            "reasons": reasons[:12], "ai_reasons": ai_reasons,
            "verdict_detail": {"rules": LEVELS[floor], "model": LEVELS[llm_level] if llm_level is not None else None,
                               "confidence": (v or {}).get("confidence"), "model_name": llm.MODEL if v else None},
        })
        emit("verdict", f"Verdict: {LEVELS[level]} (evidence floor {LEVELS[floor]}, model "
                        f"{LEVELS[llm_level] if llm_level is not None else 'n/a'})", verdict=LEVELS[level])
        if level == 2:
            e["quarantined"] = True
            emit("quarantine", "Email moved to QUARANTINE. Nothing is delivered until a human presses Release.")
        else:
            emit("delivered", "Email delivered to the inbox" + (" with a warning banner" if level == 1 else ""))
        e["status"] = "done"
    except Exception as ex:  # noqa: BLE001
        log.exception("analysis failed")
        e["status"] = "error"
        e["verdict"] = e.get("verdict") or "SUSPICIOUS"
        e["quarantined"] = True
        e["summary"] = f"Analysis failed ({type(ex).__name__}); held in quarantine to be safe."
        emit("error", e["summary"])
    finally:
        store.updated(email_id)


def _fallback_summary(level: int, reasons: list[str]) -> str:
    if level == 0:
        return "No signs of phishing or malware were found."
    return ("This email looks dangerous: " if level == 2 else "This email has warning signs: ") + \
        (reasons[0] if reasons else "see the reasons below.")
