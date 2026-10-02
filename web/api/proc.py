"""Run one subprocess with a hard timeout, streaming its output line by
line. Shared by the repo cache (git, prepare steps) and the runner (the
CLI itself), so every external command the API starts has exactly one
timeout/kill implementation.

Always an argv list, never a shell: nothing a client sent is ever
interpolated into a command string.
"""

import os
import signal
import subprocess
import sys
import threading
import time

# Used so a child that never writes anything can still be timed out, and
# so a child that writes forever can't grow the log without bound.
MAX_LINE_CHARS = 4000


def tool_env(extra: dict | None = None) -> dict:
    """The environment every subprocess gets: this interpreter's own bin
    directory first on PATH (the venv's `scons` lives there, and a plain
    `uvicorn` start does not put it on PATH), and git told never to prompt
    for credentials -- a prompt would hang a run until its timeout."""
    env = dict(os.environ)
    env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "true"
    if extra:
        env.update(extra)
    return env


class CommandTimeout(RuntimeError):
    pass


def run_streaming(argv, cwd, timeout, on_line, env=None, abort=None) -> int:
    """Run `argv` in `cwd`, calling `on_line(str)` for each line of merged
    stdout+stderr. Returns the exit code. On timeout the whole process
    group is killed (a `make` or `scons` child would otherwise outlive its
    parent) and CommandTimeout is raised. If `abort` (a threading.Event)
    is set while it runs, the group is killed and -9 is returned: the
    caller, which set the event, knows why."""
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env or tool_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )

    def pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            on_line(line.rstrip("\n")[:MAX_LINE_CHARS])

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()

    def kill() -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        reader.join(timeout=5)

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 and proc.poll() is None:
            kill()
            raise CommandTimeout(f"timed out after {timeout}s: {' '.join(argv[:3])} ...")
        try:
            code = proc.wait(timeout=max(0.01, min(0.25, remaining)))
            break
        except subprocess.TimeoutExpired:
            if abort is not None and abort.is_set():
                kill()
                return -9
    reader.join(timeout=10)
    return code
