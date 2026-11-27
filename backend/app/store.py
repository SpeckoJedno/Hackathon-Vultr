"""In-memory state + JSON persistence + live event fan-out (SSE)."""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

DATA = Path(os.getenv("DATA_DIR", "/data"))
(DATA / "shots").mkdir(parents=True, exist_ok=True)
(DATA / "raw").mkdir(parents=True, exist_ok=True)
STATE = DATA / "state.json"

emails: dict[str, dict] = {}
_subscribers: set[asyncio.Queue] = set()


def load() -> None:
    if STATE.exists():
        try:
            emails.update(json.loads(STATE.read_text()))
        except Exception:  # noqa: BLE001
            pass
    for e in emails.values():  # analyses interrupted by a restart
        if e["status"] == "analyzing":
            e["status"] = "error"
            e["summary"] = "Analysis interrupted by a backend restart."


def save() -> None:
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(emails))
    tmp.replace(STATE)


def summary(e: dict) -> dict:
    return {k: e.get(k) for k in ("id", "received_at", "from", "subject", "status", "verdict",
                                  "quarantined", "released", "summary", "source")}


def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _subscribers.discard(q)


def broadcast(msg: dict) -> None:
    for q in list(_subscribers):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass


def event(email_id: str, kind: str, msg: str, **data) -> dict:
    """Append a step to an email's log and push it live to every dashboard."""
    ev = {"ts": time.time(), "kind": kind, "msg": msg, **({"data": data} if data else {})}
    e = emails.get(email_id)
    if e is not None:
        ev["seq"] = len(e["events"])
        e["events"].append(ev)
    broadcast({"type": "event", "email_id": email_id, "event": ev})
    return ev


def updated(email_id: str) -> None:
    save()
    broadcast({"type": "email", "email": summary(emails[email_id])})
