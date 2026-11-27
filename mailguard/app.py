"""MailGuard web app. Run:  uvicorn app:app --host 0.0.0.0 --port 80"""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse

import agent
import sandbox

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
QUARANTINE = DATA / "quarantine"
AUDIT = DATA / "audit.jsonl"
SAMPLES = HERE / "samples"
MAX_BYTES = 5 * 1024 * 1024
QUARANTINE.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="MailGuard")
SCANS: dict[str, dict] = {}
RAW: dict[str, bytes] = {}
_lock = threading.Lock()


def audit(event: str, scan_id: str, **kw):
    with AUDIT.open("a") as fh:
        fh.write(json.dumps({"ts": time.time(), "event": event, "scan_id": scan_id, **kw}) + "\n")


def _scan(raw: bytes, name: str) -> dict:
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "email too large (5 MB max)")
    sid = uuid.uuid4().hex[:10]
    try:
        result = agent.investigate(raw)
    except Exception as e:  # never 500 with a stack trace on hostile input
        raise HTTPException(422, f"could not analyse this email: {type(e).__name__}: {e}")
    result.update(id=sid, filename=name, scanned_at=time.time())
    with _lock:
        SCANS[sid], RAW[sid] = result, raw
    audit("scanned", sid, filename=name, verdict=result["verdict"], mode=result["agent_mode"])
    return result


@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    return _scan(await file.read(MAX_BYTES + 1), Path(file.filename or "upload.eml").name)


@app.post("/api/scan-sample/{name}")
def scan_sample(name: str):
    path = SAMPLES / Path(name).name
    if path.suffix != ".eml" or not path.exists():
        raise HTTPException(404, "no such sample (run: python3 make_samples.py)")
    return _scan(path.read_bytes(), path.name)


@app.get("/api/samples")
def samples():
    return sorted(p.name for p in SAMPLES.glob("*.eml"))


@app.get("/api/scans")
def scans():
    return [{k: s[k] for k in ("id", "filename", "verdict", "action", "quarantine", "scanned_at")}
            for s in sorted(SCANS.values(), key=lambda s: -s["scanned_at"])]


@app.get("/api/scans/{sid}")
def get_scan(sid: str):
    if sid not in SCANS:
        raise HTTPException(404)
    return SCANS[sid]


@app.post("/api/scans/{sid}/{decision}")
def decide(sid: str, decision: str):
    """Human-in-the-loop: nothing is quarantined until a person approves."""
    if sid not in SCANS or decision not in ("approve", "reject"):
        raise HTTPException(404)
    s = SCANS[sid]
    if s["quarantine"] != "pending_approval":
        raise HTTPException(409, f"nothing to decide (status: {s['quarantine']})")
    if decision == "approve":
        (QUARANTINE / f"{sid}.eml.quarantined").write_bytes(RAW[sid])
        s["quarantine"] = "quarantined"
    else:
        s["quarantine"] = "released_by_human"
    audit(decision, sid, filename=s["filename"])
    return {"id": sid, "quarantine": s["quarantine"]}


@app.get("/api/health")
def health():
    return {"docker": sandbox.docker_available(), "llm_configured": bool(agent.API_KEY),
            "model": agent.MODEL or None}


@app.get("/", response_class=HTMLResponse)
def index():
    return (HERE / "static" / "index.html").read_text()
