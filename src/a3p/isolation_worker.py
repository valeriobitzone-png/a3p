"""Fixed probe that runs inside the sandbox. It does not take a shell command.

Without ``A3P_TOOL_CALL``, it only reports network and filesystem reach.
With that variable set, it also applies one handler spec from stdin and returns
the effect list on the same JSON channel.
"""

from __future__ import annotations

import json
import socket
import sys

from a3p.env import setting
from a3p.handler_exec import apply_spec, spec_from_json


def probe_status() -> dict[str, str]:
    port = int(setting("PROBE_PORT") or "0")
    escape = setting("ESCAPE") or ""
    scratch = "fail"
    try:
        with open("/tmp/a3p-scratch", "w", encoding="utf-8") as handle:  # nosec B108
            handle.write("ok")
        scratch = "ok"
    except OSError:
        scratch = "fail"
    wrote = "denied"
    if escape:
        try:
            with open(escape, "w", encoding="utf-8") as handle:
                handle.write("pwned")
            wrote = "wrote"
        except OSError:
            wrote = "denied"
    network = "untested"
    if port:
        sock = socket.socket()
        sock.settimeout(1.0)
        try:
            sock.connect(("127.0.0.1", port))
            network = "open"
        except OSError:
            network = "denied"
        finally:
            sock.close()
    seccomp = "unknown"
    no_new = "unknown"
    try:
        for line in open("/proc/self/status", encoding="utf-8"):
            if line.startswith("Seccomp:"):
                seccomp = line.split()[1]
            elif line.startswith("NoNewPrivs:"):
                no_new = line.split()[1]
    except OSError:
        pass
    return {
        "scratch": scratch,
        "escape": wrote,
        "network": network,
        "seccomp": seccomp,
        "no_new_privileges": no_new,
    }


def main() -> None:
    status = probe_status()
    if setting("TOOL_CALL") == "1":
        request = json.loads(sys.stdin.read() or "{}")
        spec = spec_from_json(request.get("spec") if isinstance(request.get("spec"), dict) else {})
        args = request.get("arguments") if isinstance(request.get("arguments"), dict) else {}
        effects = request.get("effects") if isinstance(request.get("effects"), list) else []
        result, new_effects = apply_spec(spec, args, effects)
        print(json.dumps({"result": result, "effects": new_effects, **status}, default=str))
        return
    print(json.dumps(status))


if __name__ == "__main__":
    main()
