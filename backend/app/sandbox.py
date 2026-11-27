"""Starts one disposable sandbox container per job via the Docker CLI.

The backend talks to Docker through the mounted socket; the sandbox itself
gets none of that: no socket, no volumes, no env vars except HOME, its own
firewalled network (see deploy/netguard.sh), read-only rootfs, non-root,
all capabilities dropped, 512 MB RAM, 1 CPU, 60 s hard timeout."""
from __future__ import annotations

import asyncio
import itertools
import json
import os
import time
import uuid

IMAGE = os.getenv("SANDBOX_IMAGE", "mailguard-sandbox:latest")
NETWORK = os.getenv("SANDBOX_NETWORK", "mailguard_sandbox")
TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT", "60"))
MEMORY = os.getenv("SANDBOX_MEMORY", "512m")
CPUS = os.getenv("SANDBOX_CPUS", "1")
_counter = itertools.count(1)
_slots = asyncio.Semaphore(int(os.getenv("SANDBOX_PARALLEL", "2")))  # 2 vCPU / 4 GB VM

LIMITS = {
    "network": f"{NETWORK} (internet only: metadata, VM, Docker & private ranges rejected)",
    "rootfs": "read-only (writable: /tmp tmpfs 256 MB, noexec)",
    "user": "pwuser (non-root)",
    "capabilities": "ALL dropped, no-new-privileges",
    "memory": MEMORY, "cpus": CPUS, "pids": "256", "timeout": f"{TIMEOUT}s",
    "secrets": "none (only HOME=/tmp is set)", "mounts": "none (no Docker socket, no volumes)",
}


def docker_args(name: str) -> list[str]:
    return [
        "docker", "create", "-i", "--name", name, "--hostname", "sandbox",
        "--label", "mailguard=sandbox",
        "--network", NETWORK,
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
        "--shm-size", "128m",
        "--memory", MEMORY, "--memory-swap", MEMORY, "--cpus", CPUS, "--pids-limit", "256",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "pwuser", "--env", "HOME=/tmp",
        "--stop-timeout", "1",
        IMAGE,
    ]


async def _run(*cmd: str, timeout: float = 30) -> tuple[int, str]:
    p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        p.kill()
        return -1, "timeout"
    return p.returncode, out.decode(errors="replace").strip()


async def docker_ok() -> bool:
    code, _ = await _run("docker", "version", "--format", "{{.Server.Version}}", timeout=10)
    return code == 0


async def image_ok() -> bool:
    code, _ = await _run("docker", "image", "inspect", IMAGE, timeout=10)
    return code == 0


async def cleanup_leftovers() -> None:
    code, out = await _run("docker", "ps", "-aq", "--filter", "label=mailguard=sandbox")
    if code == 0 and out:
        await _run("docker", "rm", "-f", *out.split())


async def run_job(job: dict, emit, label: str, on_shot=None) -> tuple[dict, list[dict]]:
    """Run one job in a fresh container. `emit(kind, msg, **data)` streams steps.
    Returns (result, screenshots[{label,url,b64}])."""
    name = f"mg-sbx-{next(_counter)}-{uuid.uuid4().hex[:6]}"
    shots: list[dict] = []
    result: dict = {}
    async with _slots:
        code, cid = await _run(*docker_args(name))
        if code != 0:
            emit("error", f"Could not create sandbox container: {cid[-200:]}")
            return {"error": "sandbox create failed"}, shots
        emit("container_started", f"Sandbox container {name} ({cid[:12]}) started for {label}",
             container=name, container_id=cid[:12], limits=LIMITS)
        t0 = time.time()
        proc = await asyncio.create_subprocess_exec(
            "docker", "start", "-ai", name,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            limit=32 * 1024 * 1024,
        )
        proc.stdin.write(json.dumps(job).encode())
        await proc.stdin.drain()
        proc.stdin.close()

        async def read() -> None:
            nonlocal result
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ev.get("t") == "log":
                    emit("sandbox", ev.get("msg", "")[:500])
                elif ev.get("t") == "shot":
                    shots.append(ev)
                    if on_shot:
                        on_shot(ev)
                elif ev.get("t") == "result":
                    result = ev.get("data") or {}

        try:
            await asyncio.wait_for(read(), TIMEOUT)
            await asyncio.wait_for(proc.wait(), 5)
        except asyncio.TimeoutError:
            emit("timeout", f"Sandbox hit the {TIMEOUT}s limit - killing container {name}")
            result = result or {"error": f"timeout after {TIMEOUT}s"}
            result["timed_out"] = True
            await _run("docker", "kill", name)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        finally:
            _, state = await _run("docker", "inspect", "-f", "{{.State.OOMKilled}} {{.State.ExitCode}}", name)
            await _run("docker", "rm", "-f", "-v", name)
            gone, _ = await _run("docker", "inspect", name)
            emit("container_destroyed",
                 f"Container {name} destroyed" + (" (verified: no longer exists)" if gone != 0 else " - WARNING: still present"),
                 container=name, runtime_s=round(time.time() - t0, 1), exit=state, verified=gone != 0)
        if "true" in (state or "").split(" ")[:1]:
            result["oom_killed"] = True
    return result, shots
