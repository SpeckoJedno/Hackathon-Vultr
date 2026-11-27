"""Docker sandbox for hostile email content.

Every container is fresh and thrown away (`--rm`), and runs with:
  no network, read-only root filesystem, unprivileged user, all Linux
  capabilities dropped, no privilege escalation, memory/CPU/PID limits,
  a small noexec-free tmpfs at /tmp, and a hard wall-clock timeout.

Run `python3 sandbox.py` for a self-test of the containment.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGE = os.environ.get("SANDBOX_IMAGE", "python:3.12-alpine")
TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", "10"))
MAX_OUTPUT = 4000


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def _docker_run(workdir: Path, cmd: list[str], timeout: int) -> dict:
    name = f"mailguard-{uuid.uuid4().hex[:12]}"
    args = [
        "docker", "run", "--rm", "--name", name,
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=16m",
        "--user", "65534:65534",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", "128m", "--memory-swap", "128m",
        "--cpus", "0.5",
        "--pids-limit", "64",
        "--ulimit", "nofile=64:64",
        "--env", "MAILGUARD_SANDBOX=1",
        "--env", "HOME=/tmp",
        # Decoy secrets: if the script reads/exfiltrates these, we see it.
        "--env", "AWS_SECRET_ACCESS_KEY=DECOY-not-a-real-key",
        "--env", "VULTR_API_KEY=DECOY-not-a-real-key",
        "-v", f"{workdir}:/work:ro",
        "-w", "/tmp",
        IMAGE, *cmd,
    ]
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {"exit_code": p.returncode, "timed_out": False, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired as e:
        subprocess.run(["docker", "kill", name], capture_output=True)
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return {"exit_code": None, "timed_out": True, "stdout": out, "stderr": err}


def analyze_email(raw: bytes) -> dict:
    """Parse the email inside a network-less container. Falls back to in-process
    parsing (parsing only, nothing executed) if Docker is unavailable."""
    if not docker_available():
        from analyzer import analyze
        rep = analyze(raw)
        rep["sandboxed"] = False
        return rep
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "msg.eml").write_bytes(raw)
        shutil.copy(HERE / "analyzer.py", d / "analyzer.py")
        os.chmod(d, 0o755)
        for f in d.iterdir():
            os.chmod(f, 0o644)
        r = _docker_run(d, ["python3", "-I", "/work/analyzer.py", "/work/msg.eml"], 30)
    if r["exit_code"] != 0:
        raise RuntimeError(f"sandboxed analyzer failed: {r['stderr'][-500:]}")
    rep = json.loads(r["stdout"])
    rep["sandboxed"] = True
    return rep


def detonate(filename: str, data: bytes) -> dict:
    """Run a script attachment in a throwaway container and record its behaviour."""
    ext = filename.rsplit(".", 1)[-1].lower()
    if ext not in ("py", "sh"):
        return {"ran": False, "reason": f"no runner for .{ext} files; static analysis only"}
    if not docker_available():
        return {"ran": False, "reason": "Docker unavailable: refusing to execute untrusted code outside a sandbox"}
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        target = d / f"sample.{ext}"
        target.write_bytes(data)
        shutil.copy(HERE / "tracer.py", d / "tracer.py")
        os.chmod(d, 0o755)
        for f in d.iterdir():
            os.chmod(f, 0o644)
        r = _docker_run(d, ["python3", "-I", "-u", "/work/tracer.py", f"/work/sample.{ext}"], TIMEOUT)

    events, stderr_lines = [], []
    for line in (r["stderr"] or "").splitlines():
        if line.startswith("@@EVENT "):
            try:
                events.append(json.loads(line[8:]))
            except json.JSONDecodeError:
                pass
        else:
            stderr_lines.append(line)
    blocked = [l for l in stderr_lines + (r["stdout"] or "").splitlines()
               if any(k in l for k in ("Read-only file system", "Permission denied", "Network is unreachable", "Network unreachable",
                                       "Temporary failure in name resolution", "Try again", "Name or service not known",
                                       "Operation not permitted", "Resource temporarily unavailable",
                                       "No such file or directory", "MemoryError", "Cannot allocate"))]
    return {
        "ran": True,
        "filename": filename,
        "exit_code": r["exit_code"],
        "timed_out": r["timed_out"],
        "events": events,
        "contained": sorted(set(blocked))[:40],
        "stdout": (r["stdout"] or "")[-MAX_OUTPUT:],
        "stderr": "\n".join(stderr_lines)[-MAX_OUTPUT:],
        "limits": {"network": "none", "rootfs": "read-only", "user": "nobody", "memory": "128m",
                   "pids": 64, "timeout_s": TIMEOUT},
    }


if __name__ == "__main__":
    print("Docker available:", docker_available())
    probe = b"""
import socket, os
try:
    socket.create_connection(("1.1.1.1", 80), timeout=2); print("NETWORK: reachable (BAD)")
except OSError as e: print("NETWORK: blocked ->", e)
try:
    open("/etc/evil", "w"); print("ROOTFS: writable (BAD)")
except OSError as e: print("ROOTFS: blocked ->", e)
print("UID:", os.getuid())
while True: pass
"""
    print(json.dumps(detonate("probe.py", probe), indent=2))
