"""Docker sandbox for Frontend B (rule 4.4).

Launches an untrusted MCP server inside a locked-down container and attaches to its
stdio so the MCP client can drive it:

* non-root user, read-only root filesystem,
* ``--network none`` (outbound is off; any exfil attempt fails — the intent is
  still caught statically and via decoy canary URLs),
* writable ``tmpfs`` seeded with decoy secret files at sensitive paths so a tool
  that reads them is caught when the decoy marker surfaces in a response,
* CPU / memory / pids / time limits; hard kill on timeout (a DoS signal).

Graceful degradation (rule 3.2): if Docker is unavailable we DO NOT execute the
untrusted server — the dynamic layer is skipped and clearly reported, static
detectors still run. An explicit, documented ``--allow-unsandboxed`` exists for
running *your own* trusted fixtures only.
"""
from __future__ import annotations

import base64
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..models import Target
from .argsynth import decoy_files

# Base images we derive from (pulled once), and the derived sandbox images we
# build on top of them with the MCP SDK baked in. A stock base image has no MCP
# SDK, so an untrusted server's `import mcp` fails under --network none and the
# process dies before the handshake (BrokenPipe) — the dynamic layer then sees
# nothing. The derived images fix that; they are built with network at BUILD
# time only, while the container RUN stays --network none.
BASE_IMAGES = {
    "python": "python:3.12-slim",
    "node": "node:20-slim",
    "unknown": "python:3.12-slim",
}
DERIVED_IMAGES = {
    "python": "deepsleuth-sbx-py:1",
    "node": "deepsleuth-sbx-node:1",
    "unknown": "deepsleuth-sbx-py:1",
}
# Dockerfiles for the derived images. Kept minimal and pinned so the build is
# reproducible. Python servers use the official `mcp` SDK; Node servers use
# `@modelcontextprotocol/sdk` (installed globally; NODE_PATH is set at run time
# so a bare `import ... from '@modelcontextprotocol/sdk/...'` resolves).
DOCKERFILES = {
    "python": (
        "FROM python:3.12-slim\n"
        "RUN pip install --no-cache-dir 'mcp<2'\n"
    ),
    "node": (
        "FROM node:20-slim\n"
        "RUN npm install -g @modelcontextprotocol/sdk >/dev/null 2>&1 || true\n"
        "ENV NODE_PATH=/usr/local/lib/node_modules\n"
    ),
}
# Backwards-compatible alias (older callers referenced DEFAULT_IMAGES).
DEFAULT_IMAGES = BASE_IMAGES


@dataclass
class SandboxLaunch:
    argv: List[str]
    mode: str  # "docker" | "unsandboxed"
    image: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def image_present(image: str) -> bool:
    try:
        r = subprocess.run(["docker", "image", "inspect", image],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def ensure_image(image: str, allow_pull: bool, timeout: int = 180) -> Tuple[bool, str]:
    if image_present(image):
        return True, "present"
    if not allow_pull:
        return False, "image-absent (pull disabled)"
    try:
        r = subprocess.run(["docker", "pull", image], capture_output=True,
                           timeout=timeout, text=True)
        if r.returncode == 0:
            return True, "pulled"
        return False, f"pull-failed: {r.stderr.strip()[:200]}"
    except Exception as exc:
        return False, f"pull-error: {exc}"


def ensure_sandbox_image(runtime: str, allow_build: bool, timeout: int = 600) -> Tuple[Optional[str], str]:
    """Ensure the derived sandbox image (MCP SDK baked in) exists; build it if
    absent. Returns (image_tag or None, note). Network is used only here, at
    build time — the container run stays --network none."""
    rt = runtime if runtime in DERIVED_IMAGES else "unknown"
    derived = DERIVED_IMAGES[rt]
    if image_present(derived):
        return derived, f"derived image {derived} present"
    if not allow_build:
        return None, f"derived image {derived} absent (build disabled)"
    dockerfile = DOCKERFILES.get("node" if rt == "node" else "python")
    base = BASE_IMAGES[rt]
    ok, why = ensure_image(base, allow_pull=True)
    if not ok:
        return None, f"base image {base} unavailable ({why})"
    import tempfile
    try:
        # Build from a temp directory context holding only the Dockerfile — no
        # target code is copied into the image, only the pinned SDK is installed.
        with tempfile.TemporaryDirectory(prefix="ds-sbx-") as ctx:
            with open(os.path.join(ctx, "Dockerfile"), "w") as fh:
                fh.write(dockerfile)
            r = subprocess.run(
                ["docker", "build", "-t", derived, ctx],
                capture_output=True, text=True, timeout=timeout,
            )
        if r.returncode == 0 and image_present(derived):
            return derived, f"built {derived}"
        return None, f"build-failed: {(r.stderr or r.stdout).strip()[-200:]}"
    except Exception as exc:
        return None, f"build-error: {exc}"


def _seed_prelude() -> str:
    """Shell that writes decoy secret files into the writable tmpfs home."""
    lines = ["set -e", "umask 022"]
    for _label, (path, content) in sorted(decoy_files().items()):
        d = os.path.dirname(path)
        b64 = base64.b64encode(content.encode()).decode()
        lines.append(f"mkdir -p {shlex.quote(d)} 2>/dev/null || true")
        lines.append(f"printf %s {shlex.quote(b64)} | base64 -d > {shlex.quote(path)} 2>/dev/null || true")
    return "; ".join(lines)


def _rewrite_args(target: Target) -> Tuple[str, List[str]]:
    """Map host paths under root_dir to the container mount (/srv)."""
    def rw(x: str) -> str:
        if target.root_dir and isinstance(x, str) and os.path.isabs(x) \
                and x.startswith(target.root_dir):
            rel = os.path.relpath(x, target.root_dir)
            return "/srv/" + rel
        return x
    cmd = rw(target.command or "")
    args = [rw(a) for a in (target.args or [])]
    return cmd, args


def build_docker_argv(target: Target, image: str, timeout: int = 30,
                      memory: str = "512m", cpus: str = "1.0",
                      pids: int = 128) -> List[str]:
    cmd, args = _rewrite_args(target)
    inner = f"{_seed_prelude()}; export HOME=/home/canary; cd /srv 2>/dev/null || true; exec " + \
            " ".join(shlex.quote(p) for p in ([cmd] + args))
    argv = [
        "docker", "run", "--rm", "-i",
        "--network", "none",
        "--read-only",
        "--tmpfs", "/home/canary:mode=1777,size=16m",
        "--tmpfs", "/tmp:mode=1777,size=16m",
        "--user", "1000:1000",
        "--memory", memory, "--memory-swap", memory,
        "--cpus", cpus, "--pids-limit", str(pids),
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "-e", "HOME=/home/canary",
    ]
    if target.runtime == "node":
        # so a bare import of the globally-installed SDK resolves
        argv += ["-e", "NODE_PATH=/usr/local/lib/node_modules"]
    for k, v in sorted((target.env or {}).items()):
        argv += ["-e", f"{k}={v}"]
    if target.root_dir and os.path.isdir(target.root_dir):
        argv += ["-v", f"{os.path.abspath(target.root_dir)}:/srv:ro", "-w", "/srv"]
    argv += [image, "sh", "-c", inner]
    return argv


def prepare_launch(target: Target, *, allow_unsandboxed: bool = False,
                   allow_pull: bool = True, timeout: int = 30) -> Tuple[Optional[SandboxLaunch], List[str]]:
    """Return (launch or None, notes). None means the dynamic layer must be skipped."""
    notes: List[str] = []
    if not target.launchable():
        return None, ["no launch command available for target; dynamic layer skipped"]

    if docker_available():
        # Prefer the derived image (MCP SDK baked in) so the server can actually
        # start under --network none. Fall back to the bare base image only if
        # the build fails — and say so, since dynamic detection will likely be
        # blind without the SDK.
        derived, why = ensure_sandbox_image(target.runtime, allow_build=allow_pull)
        if derived:
            argv = build_docker_argv(target, derived, timeout=timeout)
            return SandboxLaunch(argv=argv, mode="docker", image=derived,
                                 notes=[f"docker sandbox image={derived} ({why})"]), notes
        notes.append(f"derived sandbox image unavailable ({why}); "
                     "trying base image (MCP SDK may be missing)")
        image = BASE_IMAGES.get(target.runtime, BASE_IMAGES["unknown"])
        ok, why2 = ensure_image(image, allow_pull=allow_pull)
        if not ok:
            notes.append(f"docker image '{image}' unavailable ({why2}); dynamic layer skipped")
            if allow_unsandboxed:
                notes.append("falling back to UNSANDBOXED execution (trusted fixtures only)")
                return _unsandboxed(target), notes
            return None, notes
        argv = build_docker_argv(target, image, timeout=timeout)
        return SandboxLaunch(argv=argv, mode="docker", image=image,
                             notes=[f"docker sandbox image={image} (no MCP SDK — dynamic may be blind)"]), notes

    notes.append("Docker unavailable; dynamic layer requires the sandbox")
    if allow_unsandboxed:
        notes.append("UNSANDBOXED execution enabled (trusted fixtures only) — "
                     "NEVER use on untrusted servers")
        return _unsandboxed(target), notes
    notes.append("dynamic layer skipped (run with Docker, or --allow-unsandboxed for "
                 "your own fixtures)")
    return None, notes


def _unsandboxed(target: Target) -> SandboxLaunch:
    argv = [target.command or ""] + list(target.args or [])
    env = dict(os.environ)
    env.update(target.env or {})
    return SandboxLaunch(argv=argv, mode="unsandboxed",
                         notes=["UNSANDBOXED (no isolation)"], env=env)


def spawn(launch: SandboxLaunch, target: Target) -> subprocess.Popen:
    env = None
    if launch.mode == "unsandboxed":
        env = launch.env
    cwd = target.root_dir if (launch.mode == "unsandboxed" and target.root_dir) else None
    # stderr -> DEVNULL to avoid a full-pipe deadlock while we drive stdio;
    # server logs are not part of the fully deterministic finding set.
    return subprocess.Popen(
        launch.argv,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=env, cwd=cwd, bufsize=0,
    )
