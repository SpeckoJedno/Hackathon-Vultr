"""MailGuard backend: REST API, live event stream (SSE) and the dashboard."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import llm, pipeline, sandbox, store
from .parser import parse_email

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("mailguard")

DEMO_DIR = Path(os.getenv("DEMO_DIR", "/app/demo"))
STATIC = Path(__file__).parent / "static"
PUBLIC_HOST = os.getenv("PUBLIC_HOST", "")
MAX_UPLOAD = 10 * 1024 * 1024

app = FastAPI(title="MailGuard")
_tasks: set[asyncio.Task] = set()


@app.on_event("startup")
async def startup() -> None:
    store.load()
    await sandbox.cleanup_leftovers()
    log.info("MailGuard up. LLM configured: %s, model: %s, vision: %s", llm.configured(), llm.MODEL, llm.VISION_MODEL)


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/shots", StaticFiles(directory=store.DATA / "shots"), name="shots")


@app.get("/api/health")
async def health():
    return {"ok": True, "docker": await sandbox.docker_ok(), "sandbox_image": await sandbox.image_ok(),
            "llm_configured": llm.configured(), "model": llm.MODEL, "vision_model": llm.VISION_MODEL,
            "inference": llm.BASE_URL, "sandbox_limits": sandbox.LIMITS}


@app.get("/api/demos")
async def demos():
    return sorted(p.name for p in DEMO_DIR.glob("*.eml")) if DEMO_DIR.exists() else []


@app.post("/api/emails")
async def submit(request: Request, file: UploadFile | None = File(None), raw: str | None = Form(None),
                 demo: str | None = Form(None)):
    source = "paste"
    if file is not None:
        data = await file.read(MAX_UPLOAD + 1)
        source = f"upload: {Path(file.filename or 'email.eml').name}"
    elif demo:
        p = (DEMO_DIR / Path(demo).name)
        if p.suffix != ".eml" or not p.exists():
            raise HTTPException(404, "demo not found")
        data, source = p.read_bytes(), f"demo: {p.name}"
    elif raw:
        data = raw.encode()
    else:
        raise HTTPException(400, "send a file, raw text or a demo name")
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "email too large (10 MB max)")
    if b":" not in data[:2000]:  # plain text without headers: wrap it as a minimal email
        data = b"From: unknown@unknown\nSubject: (pasted text)\n\n" + data

    parsed = parse_email(data)
    eid = uuid.uuid4().hex[:12]
    (store.DATA / "raw" / f"{eid}.eml").write_bytes(data)
    store.emails[eid] = {
        "id": eid, "received_at": time.time(), "source": source,
        "from": f"{parsed['from_name']} <{parsed['from_addr']}>".strip(), "subject": parsed["subject"],
        "to": parsed["to"], "date": parsed["date"], "auth": parsed["auth"],
        "body": parsed["body"][:5000],  # shown as plain text only, never rendered as HTML
        "links": [{k: l[k] for k in ("url", "text", "host", "text_mismatch")} for l in parsed["links"]],
        "attachments": [{k: a[k] for k in ("filename", "content_type", "size", "sha256")} for a in parsed["attachments"]],
        "status": "analyzing", "verdict": None, "quarantined": False, "released": None,
        "events": [], "shots": [], "pages": [], "files": [], "reasons": [], "summary": None,
    }
    store.event(eid, "received", f"Email received ({source}): {parsed['subject']!r} from {parsed['from_addr']}")
    store.updated(eid)
    t = asyncio.create_task(pipeline.analyze(eid, parsed))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return {"id": eid}


@app.get("/api/emails")
async def list_emails():
    return sorted((store.summary(e) for e in store.emails.values()), key=lambda e: -e["received_at"])


@app.get("/api/emails/{eid}")
async def get_email(eid: str):
    e = store.emails.get(eid)
    if not e:
        raise HTTPException(404)
    return e


@app.post("/api/emails/{eid}/release")
async def release(eid: str, by: str = Form("analyst")):
    e = store.emails.get(eid)
    if not e:
        raise HTTPException(404)
    if not e.get("quarantined"):
        raise HTTPException(400, "email is not in quarantine")
    e["quarantined"] = False
    e["released"] = {"by": by[:60] or "analyst", "at": time.time()}
    store.event(eid, "released", f"Released from quarantine by {e['released']['by']} - delivered to the inbox")
    store.updated(eid)
    return store.summary(e)


@app.delete("/api/emails/{eid}")
async def delete(eid: str):
    if store.emails.pop(eid, None) is None:
        raise HTTPException(404)
    store.save()
    store.broadcast({"type": "deleted", "id": eid})
    return {"ok": True}


@app.post("/api/containment-test")
async def containment_test():
    """Starts a probe container that tries to break out, and reports what was stopped."""
    def emit(kind, msg, **data):
        store.event("containment", kind, msg, **data)
    emit("received", "Containment self-test: starting a sandbox that tries to reach secrets, the host and the network")
    res, _ = await sandbox.run_job({"mode": "probe", "backend_host": PUBLIC_HOST}, emit, "containment self-test")
    emit("verdict", "All checks contained" if res.get("all_contained") else "Some checks NOT contained", **res)
    return res


@app.get("/api/stream")
async def stream(request: Request):
    q = store.subscribe()

    async def gen():
        try:
            yield "retry: 2000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(q.get(), 15)
                    yield f"data: {json.dumps(msg, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            store.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
