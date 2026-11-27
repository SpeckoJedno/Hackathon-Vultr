"""Runs INSIDE the sandbox container. Executes one untrusted script and records
what it tries to do, using Python audit hooks (for .py) or `sh -x` (for .sh).

Each event is printed as one JSON line prefixed with "@@EVENT " so the host can
parse it apart from the script's own output. The container itself (no network,
read-only root, nobody user, memory/pid/time limits) is what actually contains
the script; this file only observes.
"""
import json
import os
import subprocess
import sys

TARGET = sys.argv[1]
INTERESTING = {
    "open", "os.remove", "os.rmdir", "os.rename", "shutil.rmtree", "os.chmod",
    "socket.connect", "socket.getaddrinfo", "socket.bind", "urllib.Request",
    "subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn",
    "os.fork", "os.kill", "exec", "compile", "ctypes.dlopen", "os.putenv",
    "os.getenv",
}
_count = 0
_seen = set()


def emit(kind, detail):
    global _count
    if (kind, detail) in _seen or _count > 300:
        return
    _seen.add((kind, detail))
    _count += 1
    sys.__stderr__.write("@@EVENT " + json.dumps({"event": kind, "detail": detail[:300]}) + "\n")
    sys.__stderr__.flush()


def hook(event, args):
    if event not in INTERESTING:
        return
    if event == "open":
        path, mode = str(args[0]), str(args[1]) if len(args) > 1 else "r"
        if path == TARGET or path.startswith(("/usr/lib", "/usr/local/lib", "/proc/self", "/dev/")):
            return
        emit("file_open", f"{path} mode={mode}")
    elif event == "compile":
        # Only code compiled from strings at runtime (exec/eval), not imports.
        fname = str(args[1]) if len(args) > 1 else ""
        src = args[0] if args else b""
        if isinstance(src, (bytes, str)) and fname.startswith("<") and not fname.startswith("<frozen") \
                and not (src[:12] in (b"lambda _cls,", "lambda _cls,")):
            emit("dynamic_code", repr(args[0])[:200])
    elif event == "exec":
        return
    else:
        emit(event, " ".join(repr(a) for a in args)[:300])


if TARGET.endswith(".sh"):
    emit("info", "running shell script with tracing (sh -x)")
    p = subprocess.run(["sh", "-x", TARGET], capture_output=True, text=True)
    sys.stdout.write(p.stdout)
    for line in p.stderr.splitlines():
        if line.startswith("+"):
            emit("shell_command", line.lstrip("+ "))
        else:
            sys.stderr.write(line + "\n")
    sys.exit(p.returncode)

# Python: watch environment-variable reads too (common for key theft).
_orig_getitem = os.environ.__class__.__getitem__


def _getitem(self, key):
    emit("env_read", key)
    return _orig_getitem(self, key)


os.environ.__class__.__getitem__ = _getitem
_orig_get = os.environ.__class__.get
os.environ.__class__.get = lambda self, k, d=None: (emit("env_read", k), _orig_get(self, k, d))[1]

sys.addaudithook(hook)
emit("info", "running python script with audit hooks")
import runpy  # noqa: E402

try:
    runpy.run_path(TARGET, run_name="__main__")
except SystemExit:
    raise
except BaseException as e:  # report, don't crash the tracer
    emit("exception", f"{type(e).__name__}: {e}")
    sys.exit(1)
