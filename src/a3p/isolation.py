"""OS isolation for tool side effects.

Levels, strongest available first when ``A3P_ISOLATION`` is unset: runsc
(gVisor, when the binary is installed), container (Docker seccomp,
no-new-privileges, read-only root, no network), nsjail (when the binary is
installed), bwrap (namespaces, read-only root, no network). Set
``A3P_ISOLATION`` to ``runsc``, ``nsjail``, ``container``, or ``bwrap`` to
force that jail even when a stronger one is installed. ``process`` keeps the
host filesystem and network open and is used only when
``A3P_ISOLATION=process`` is set. ``inprocess`` is the historical thread
timeout and is also an explicit opt-in.

The model server is not placed in this sandbox. Tool probes are. A report
must say which level ran and what the monitor observed.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from a3p.env import setting
from a3p.handler_exec import HandlerSpec, accept_effects, spec_to_json

CONTAINER_IMAGE = "n8nio/n8n:1.109.1"
Runner = Callable[..., subprocess.CompletedProcess[str]]


_RESOLVED: str | None = None


def configured_level() -> str:
    """Honour ``A3P_ISOLATION``, otherwise :func:`best_level`.

    ``process`` and ``inprocess`` are explicit. An unset, ``auto``, or unknown
    value resolves once per process so tool calls do not repeat ``docker info``.
    When none of the jails is available the result is ``unavailable``.
    """
    raw = (setting("ISOLATION") or "").strip()
    if raw in {"container", "runsc", "nsjail", "bwrap", "process", "inprocess"}:
        return raw
    global _RESOLVED
    if _RESOLVED is None:
        _RESOLVED = best_level()
    return _RESOLVED


def best_level(run: Runner | None = None) -> str:
    """gVisor, else Docker, else nsjail, else bubblewrap.

    gVisor is ahead of plain Docker when ``runsc`` is on ``PATH`` because the
    guest has its own kernel. ``A3P_ISOLATION=container`` still forces Docker.
    """
    if shutil.which("runsc"):
        return "runsc"
    if docker_prefix(run) and _image_present(run):
        return "container"
    if shutil.which("nsjail"):
        return "nsjail"
    if shutil.which("bwrap"):
        return "bwrap"
    return "unavailable"


def runsc_platform() -> str:
    """Platform passed to ``runsc``. Default is systrap.

    ``A3P_RUNSC_PLATFORM=kvm`` selects KVM. On 14 October 2026 this VM's
    ``/dev/kvm`` is group ``docker``. Opening it in the agent session returns
    EACCES. ``sg docker`` can open it, and ``runsc --platform=kvm`` did not
    finish within 10 seconds even as root. The attested path stays systrap.
    """
    raw = (setting("RUNSC_PLATFORM") or "systrap").strip()
    if raw not in {"systrap", "kvm", "ptrace"}:
        return "systrap"
    return raw


def docker_prefix(run: Runner | None = None) -> list[str] | None:
    execute = run or subprocess.run
    if not shutil.which("docker"):
        return None
    if _ok(execute, ["docker", "info"]):
        return ["docker"]
    if shutil.which("sudo") and _ok(execute, ["sudo", "-n", "docker", "info"]):
        return ["sudo", "-n", "docker"]
    return None


def isolation_summary() -> dict[str, Any]:
    level = configured_level()
    if level == "inprocess":
        return _inprocess_report()
    return attest(level)


def _inprocess_report() -> dict[str, Any]:
    return {
        "level": "inprocess",
        "network": "open",
        "filesystem": "writable",
        "seccomp": False,
        "no_new_privileges": False,
        "handlers": "in-process",
        "note": (
            "Handlers run in this process because A3P_ISOLATION=inprocess was set. "
            "That is an explicit opt-in. When the variable is unset, the probe uses gVisor "
            "if runsc is installed, otherwise a container when Docker can run the sandbox image, "
            "otherwise nsjail, otherwise bubblewrap. A subprocess is not chosen automatically."
        ),
    }


def attest(level: str, run: Runner | None = None) -> dict[str, Any]:
    """Run the fixed worker and report what it could touch."""
    if level == "inprocess":
        return _inprocess_report()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    port = int(listener.getsockname()[1])
    escape_dir = Path(tempfile.mkdtemp(prefix="a3p-escape-"))
    escape = escape_dir / "marker"
    escape.write_text("safe", encoding="utf-8")
    try:
        observed = _run_worker(level, escape, port, run)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        observed = {"error": type(exc).__name__}
    finally:
        listener.close()
    host_text = escape.read_text(encoding="utf-8") if escape.exists() else ""
    filesystem = "read-only" if host_text == "safe" else "writable"
    shutil.rmtree(escape_dir, ignore_errors=True)
    network = str(observed.get("network", "untested"))
    return {
        "level": level,
        "network": network,
        "filesystem": filesystem,
        "seccomp": str(observed.get("seccomp", "0")) not in {"0", "unknown", ""},
        "no_new_privileges": str(observed.get("no_new_privileges", "0")) == "1",
        "scratch": observed.get("scratch"),
        "escape_inside": observed.get("escape"),
        "host_marker_intact": host_text == "safe",
        "handlers": "sandboxed",
        "error": observed.get("error"),
        "note": _note(level, network, filesystem),
    }


def sandbox_image() -> str:
    return setting("SANDBOX_IMAGE") or CONTAINER_IMAGE


def command_for(
    level: str,
    escape: Path,
    port: int,
    docker: list[str] | None = None,
    *,
    stdin_open: bool = False,
    tool_call: bool = False,
    ca_cert: str | None = None,
    program: list[str] | None = None,
    extra_env: dict[str, str] | None = None,
    rw_mount: tuple[Path, str] | None = None,
    interpreter: bool = True,
) -> list[str]:
    from a3p.egress import current_ca

    src = str(Path(__file__).resolve().parent.parent)
    ca = ca_cert or current_ca()
    argv = list(program or ["-m", "a3p.isolation_worker"])
    if level == "container":
        prefix = docker or ["docker"]
        cmd = [
            *prefix, "run", "--rm",
            *(["-i"] if stdin_open else []),
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "64",
            "--memory", "256m",
            "--tmpfs", "/tmp:rw,nosuid,size=32m",  # nosec B108
            "-v", "/usr:/usr:ro",
            "-v", f"{escape}:/opt/a3p-escape:ro",
            "-v", f"{src}:/opt/a3p-src:ro",
        ]
        if rw_mount is not None:
            cmd.extend(["-v", f"{rw_mount[0]}:{rw_mount[1]}:rw"])
        for host in ("/lib", "/lib64"):
            if Path(host).exists():
                cmd.extend(["-v", f"{host}:{host}:ro"])
        cmd.extend([
            "-e", "PYTHONPATH=/opt/a3p-src",
            "-e", "A3P_ESCAPE=/opt/a3p-escape",
            "-e", f"A3P_PROBE_PORT={port}",
        ])
        if tool_call:
            cmd.extend(["-e", "A3P_TOOL_CALL=1"])
        cmd.extend(_docker_env(extra_env))
        if ca:
            cmd.extend([
                "-v", f"{ca}:/opt/a3p-ca.pem:ro",
                "-e", "SSL_CERT_FILE=/opt/a3p-ca.pem",
                "-e", "REQUESTS_CA_BUNDLE=/opt/a3p-ca.pem",
            ])
        cmd.extend(_exec_tail(argv, interpreter, image=sandbox_image()))
        return cmd
    if level == "bwrap":
        cmd = [
            "bwrap", "--unshare-all", "--die-with-parent", "--new-session",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", str(escape), "/opt/a3p-escape",
            "--ro-bind", src, "/opt/a3p-src",
            "--tmpfs", "/tmp", "--dev", "/dev", "--proc", "/proc", "--chdir", "/tmp",  # nosec B108
        ]
        if rw_mount is not None:
            cmd.extend(["--bind", str(rw_mount[0]), rw_mount[1]])
        for host in ("/lib", "/lib64", "/bin"):
            if Path(host).exists():
                cmd.extend(["--ro-bind", host, host])
        cmd.extend([
            "--setenv", "PYTHONPATH", "/opt/a3p-src",
            "--setenv", "A3P_ESCAPE", "/opt/a3p-escape",
            "--setenv", "A3P_PROBE_PORT", str(port),
        ])
        if tool_call:
            cmd.extend(["--setenv", "A3P_TOOL_CALL", "1"])
        for key, value in _checked_env(extra_env).items():
            cmd.extend(["--setenv", key, value])
        if ca:
            cmd.extend([
                "--ro-bind", ca, "/opt/a3p-ca.pem",
                "--setenv", "SSL_CERT_FILE", "/opt/a3p-ca.pem",
                "--setenv", "REQUESTS_CA_BUNDLE", "/opt/a3p-ca.pem",
            ])
        cmd.extend(_exec_tail(argv, interpreter))
        return cmd
    if level == "nsjail":
        return _nsjail_command(escape, port, argv, extra_env, rw_mount, ca, tool_call, interpreter, src)
    if level == "runsc":
        return _runsc_command(escape, port, argv, extra_env, rw_mount, ca, tool_call, interpreter, src)
    if level == "process":
        if interpreter:
            return [sys.executable, *argv]
        if not argv or not str(argv[0]).startswith("/"):
            raise ValueError("sandbox command must be an absolute path")
        return list(argv)
    raise ValueError(f"unsupported sandbox level {level}")


def _checked_env(extra_env: dict[str, str] | None) -> dict[str, str]:
    checked: dict[str, str] = {}
    for key, value in (extra_env or {}).items():
        if not key.isupper() or not key.replace("_", "").isalnum():
            raise ValueError(f"refusing environment name {key}")
        checked[key] = value
    return checked


def _docker_env(extra_env: dict[str, str] | None) -> list[str]:
    cmd: list[str] = []
    for key, value in _checked_env(extra_env).items():
        cmd.extend(["-e", f"{key}={value}"])
    return cmd


def _exec_tail(argv: list[str], interpreter: bool, image: str | None = None) -> list[str]:
    if not interpreter and (not argv or not str(argv[0]).startswith("/")):
        raise ValueError("sandbox command must be an absolute path")
    if interpreter and image is not None:
        return ["--entrypoint", "/usr/bin/python3", image, *argv]
    if interpreter:
        return ["/usr/bin/python3", *argv]
    if image is not None:
        return ["--entrypoint", argv[0], image, *argv[1:]]
    return list(argv)


def _nsjail_command(
    escape: Path,
    port: int,
    argv: list[str],
    extra_env: dict[str, str] | None,
    rw_mount: tuple[Path, str] | None,
    ca: str | None,
    tool_call: bool,
    interpreter: bool,
    src: str,
) -> list[str]:
    """nsjail argv. A private chroot avoids remounting the host root.

    ``--clone_newnet`` is not a flag in current nsjail. A new network namespace
    is the default, so the argv must not pass ``--disable_clone_newnet``.
    ``--chroot /`` fails in this environment: nsjail tries to remount every host
    mount, including Docker overlay paths the user cannot stat.
    """
    root = escape.parent / "nsjail-root"
    root.mkdir(parents=True, exist_ok=True)
    cmd = [
        "nsjail", "--quiet", "--mode", "o", "--chroot", str(root),
        "--disable_clone_newcgroup", "--forward_signals",
        "--user", str(os.getuid()), "--group", str(os.getgid()),
        "--bindmount_ro", "/usr:/usr",
        "--bindmount_ro", f"{escape}:/opt/a3p-escape",
        "--bindmount_ro", f"{src}:/opt/a3p-src",
        "--tmpfsmount", "/tmp",  # nosec B108
        "--cwd", "/tmp",  # nosec B108
    ]
    for host in ("/lib", "/lib64", "/bin", "/etc"):
        if Path(host).is_dir():
            cmd.extend(["--bindmount_ro", f"{host}:{host}"])
    if rw_mount is not None:
        cmd.extend(["--bindmount", f"{rw_mount[0]}:{rw_mount[1]}"])
    cmd.extend([
        "--env", "PYTHONPATH=/opt/a3p-src",
        "--env", "A3P_ESCAPE=/opt/a3p-escape",
        "--env", f"A3P_PROBE_PORT={port}",
    ])
    if tool_call:
        cmd.extend(["--env", "A3P_TOOL_CALL=1"])
    for key, value in _checked_env(extra_env).items():
        cmd.extend(["--env", f"{key}={value}"])
    if ca:
        cmd.extend([
            "--bindmount_ro", f"{ca}:/opt/a3p-ca.pem",
            "--env", "SSL_CERT_FILE=/opt/a3p-ca.pem",
            "--env", "REQUESTS_CA_BUNDLE=/opt/a3p-ca.pem",
        ])
    policy = Path(__file__).resolve().parent / "static" / "nsjail.kafel"
    cmd.extend(["--seccomp_policy", str(policy)])
    cmd.append("--")
    cmd.extend(_exec_tail(argv, interpreter))
    return cmd


def _runsc_command(
    escape: Path,
    port: int,
    argv: list[str],
    extra_env: dict[str, str] | None,
    rw_mount: tuple[Path, str] | None,
    ca: str | None,
    tool_call: bool,
    interpreter: bool,
    src: str,
) -> list[str]:
    """gVisor argv via rootless OCI ``runsc run``.

    ``runsc do`` mounts the host filesystem. An earlier rootless OCI attempt
    failed with ``fork/exec /proc/self/exe: operation not permitted``.
    ``--ignore-cgroups`` plus a spec that does not add its own uid map runs
    here: network denied, host marker intact, ``noNewPrivileges`` true.
    ``/proc`` Seccomp inside the guest stays 0. KVM did not finish in this VM;
    the platform is systrap unless ``A3P_RUNSC_PLATFORM`` says otherwise.
    """
    root = escape.parent / "runsc-root"
    bundle = escape.parent / "runsc-bundle"
    root.mkdir(parents=True, exist_ok=True)
    (bundle / "rootfs").mkdir(parents=True, exist_ok=True)
    env = [
        "PATH=/usr/bin:/bin",
        "PYTHONPATH=/opt/a3p-src",
        "A3P_ESCAPE=/opt/a3p-escape",
        f"A3P_PROBE_PORT={port}",
    ]
    if tool_call:
        env.append("A3P_TOOL_CALL=1")
    for key, value in _checked_env(extra_env).items():
        env.append(f"{key}={value}")
    if ca:
        env.append("SSL_CERT_FILE=/opt/a3p-ca.pem")
        env.append("REQUESTS_CA_BUNDLE=/opt/a3p-ca.pem")
    mounts: list[dict[str, Any]] = [
        {"destination": "/usr", "type": "bind", "source": "/usr", "options": ["rbind", "ro"]},
        {"destination": "/opt/a3p-escape", "type": "bind", "source": str(escape), "options": ["rbind", "ro"]},
        {"destination": "/opt/a3p-src", "type": "bind", "source": src, "options": ["rbind", "ro"]},
        {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=755"]},  # nosec B108
        {"destination": "/proc", "type": "proc", "source": "proc"},
    ]
    for host in ("/lib", "/lib64", "/bin", "/etc"):
        if Path(host).is_dir():
            mounts.append({"destination": host, "type": "bind", "source": host, "options": ["rbind", "ro"]})
    if rw_mount is not None:
        mounts.append(
            {
                "destination": rw_mount[1],
                "type": "bind",
                "source": str(rw_mount[0]),
                "options": ["rbind"],
            }
        )
    if ca:
        mounts.append(
            {"destination": "/opt/a3p-ca.pem", "type": "bind", "source": ca, "options": ["rbind", "ro"]}
        )
    spec = {
        "ociVersion": "1.0.2",
        "process": {
            "user": {"uid": 0, "gid": 0},
            "args": _exec_tail(argv, interpreter),
            "env": env,
            "cwd": "/tmp",  # nosec B108
            "noNewPrivileges": True,
        },
        "root": {"path": "rootfs", "readonly": True},
        "hostname": "a3p",
        "mounts": mounts,
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "network"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
            ]
        },
    }
    (bundle / "config.json").write_text(json.dumps(spec), encoding="utf-8")
    ident = "a3p" + "".join(ch for ch in escape.parent.name if ch.isalnum())[-12:]
    return [
        "runsc",
        "--rootless",
        "--ignore-cgroups",
        "--network=none",
        f"--platform={runsc_platform()}",
        f"--root={root}",
        "run",
        "--bundle",
        str(bundle),
        ident,
    ]


@dataclass
class SandboxProcess:
    """A stdio process inside container, bubblewrap, or a plain subprocess."""

    process: subprocess.Popen[bytes]
    level: str
    cleanup_dir: str

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        shutil.rmtree(self.cleanup_dir, ignore_errors=True)


def popen_sandboxed(
    level: str,
    program: list[str],
    *,
    extra_env: dict[str, str] | None = None,
    rw_mount: tuple[Path, str] | None = None,
    interpreter: bool = True,
) -> SandboxProcess:
    """Launch ``program`` with stdin open and, for container and bwrap, no IP network.

    ``program`` is the argv after the interpreter, for example
    ``["-m", "a3p.mcp_vulnerable"]``. Container and bubblewrap keep
    ``--network none`` / ``--unshare-all``. A read-write mount is how an SSE
    server exposes a unix socket without opening a TCP port.
    """
    if level not in {"container", "runsc", "nsjail", "bwrap", "process"}:
        raise ValueError(f"unsupported sandbox level {level}")
    escape_dir = Path(tempfile.mkdtemp(prefix="a3p-mcp-"))
    escape = escape_dir / "marker"
    escape.write_text("safe", encoding="utf-8")
    prefix = docker_prefix() if level == "container" else None
    if level == "container" and not prefix:
        shutil.rmtree(escape_dir, ignore_errors=True)
        raise OSError("Docker is not available")
    cmd = command_for(
        level,
        escape,
        9,
        prefix,
        stdin_open=True,
        program=program,
        extra_env=extra_env,
        rw_mount=rw_mount,
        interpreter=interpreter,
    )
    env: dict[str, str] | None
    if level == "process":
        env = os.environ.copy()
        if extra_env:
            env.update(_checked_env(extra_env))
    elif level in {"nsjail", "runsc"}:
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "PYTHONPATH": "/opt/a3p-src",
            **_checked_env(extra_env),
        }
    else:
        env = None
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    return SandboxProcess(process=process, level=level, cleanup_dir=str(escape_dir))


def _limits() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (8, 8))


def _run_worker(
    level: str,
    escape: Path,
    port: int,
    run: Runner | None,
    *,
    stdin_text: str | None = None,
    timeout_s: float = 20,
    tool_call: bool = False,
) -> dict[str, Any]:
    execute = run or subprocess.run
    env = os.environ.copy()
    env["A3P_ESCAPE"] = str(escape)
    env["A3P_PROBE_PORT"] = str(port)
    if tool_call:
        env["A3P_TOOL_CALL"] = "1"
    from a3p.egress import current_ca

    ca = current_ca()
    if level == "process" and ca:
        env["SSL_CERT_FILE"] = ca
        env["REQUESTS_CA_BUNDLE"] = ca
    prefix = docker_prefix(execute) if level == "container" else None
    cmd = command_for(
        level,
        escape,
        port,
        prefix,
        stdin_open=stdin_text is not None,
        tool_call=tool_call,
        ca_cert=ca,
    )
    kwargs: dict[str, Any] = {
        "cwd": str(Path(__file__).resolve().parent.parent.parent),
        "capture_output": True,
        "text": True,
        "timeout": timeout_s,
        "check": False,
        "env": env if level == "process" else None,
    }
    if stdin_text is not None:
        kwargs["input"] = stdin_text
    if level == "process" and run is None:
        kwargs["preexec_fn"] = _limits
    proc = execute(cmd, **kwargs)
    if proc.returncode != 0 and not (proc.stdout or "").strip():
        raise OSError(proc.stderr.strip() or f"sandbox exited {proc.returncode}")
    line = ""
    for row in (proc.stdout or "").splitlines():
        if row.startswith("{"):
            line = row
    if not line:
        raise json.JSONDecodeError("worker produced no JSON", proc.stdout or "", 0)
    parsed = json.loads(line)
    if not isinstance(parsed, dict):
        raise json.JSONDecodeError("worker JSON was not an object", line, 0)
    return parsed


def _image_present(run: Runner | None) -> bool:
    prefix = docker_prefix(run)
    if not prefix:
        return False
    execute = run or subprocess.run
    return _ok(execute, [*prefix, "image", "inspect", sandbox_image()])


def _ok(execute: Runner, cmd: list[str]) -> bool:
    try:
        proc = execute(cmd, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _note(level: str, network: str, filesystem: str) -> str:
    channel = " Handler specs run in this sandbox. Effects are applied only from the JSON channel."
    if level == "container":
        return (
            "Docker container: default seccomp, no-new-privileges, read-only root, no network, memory and pid caps."
            + channel
        )
    if level == "bwrap":
        return "bubblewrap: user namespaces, read-only root, no network. Seccomp is whatever /proc reported." + channel
    if level == "nsjail":
        return (
            "nsjail: private chroot, default new network namespace, read-only binds, "
            "NoNewPrivs left on (the default; --disable_no_new_privs is not passed), "
            "and a kafel policy that returns EPERM for ptrace, mount, kexec, bpf, keyctl, and the rest of static/nsjail.kafel. "
            "A missing nsjail binary fails the run."
            + channel
        )
    if level == "runsc":
        return (
            "gVisor: runsc --rootless --ignore-cgroups --network=none run, platform "
            f"{runsc_platform()}, noNewPrivileges in the OCI spec. "
            "A missing runsc binary fails the run. /proc Seccomp inside the guest stays 0; "
            "the filter is gVisor's, not a host seccomp bit. "
            "KVM did not finish in this VM, so systrap is the default."
            + channel
        )
    if level == "process":
        return (
            "Subprocess only, and only when explicitly requested. Network and host files are not isolated."
            + channel
        )
    return f"level {level} network {network} filesystem {filesystem}"


def run_tool(
    spec: HandlerSpec,
    arguments: dict[str, Any],
    world: Any,
    level: str,
    *,
    timeout_s: float = 20.0,
    run: Runner | None = None,
) -> Any:
    """Run one handler spec in the sandbox. ``world.effects`` changes only on an accepted channel message."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1)
    port = int(listener.getsockname()[1])
    escape_dir = Path(tempfile.mkdtemp(prefix="a3p-escape-"))
    escape = escape_dir / "marker"
    escape.write_text("safe", encoding="utf-8")
    before = list(world.effects)
    request = json.dumps(
        {"spec": spec_to_json(spec), "arguments": arguments, "effects": before},
        default=str,
    )
    try:
        observed = _run_worker(
            level,
            escape,
            port,
            run,
            stdin_text=request,
            timeout_s=timeout_s,
            tool_call=True,
        )
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {"error": type(exc).__name__}
    finally:
        listener.close()
        host_text = escape.read_text(encoding="utf-8") if escape.exists() else ""
        shutil.rmtree(escape_dir, ignore_errors=True)
    if level in {"container", "bwrap", "nsjail", "runsc"} and host_text != "safe":
        return {"error": "sandbox wrote the host marker"}
    try:
        accepted = accept_effects(spec, before, observed.get("effects"))
    except ValueError as exc:
        return {"error": str(exc)}
    world.effects[:] = accepted
    result = observed.get("result")
    return result if result is not None else {"error": "worker returned no result"}
