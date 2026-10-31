"""Command line: run, verify, report, demo."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from a3p.adapters.callable_agent import CallableAdapter
from a3p.adapters.langgraph_agent import LangGraphAdapter
from a3p.adapters.n8n_webhook import N8nAdapter, N8nWebhookServer
from a3p.adapters.openai_chat import OpenAIChatAdapter
from a3p.config import ConfigError, MetaConfig, RunConfig, TargetConfig, load_config
from a3p.egress import EgressProxy
from a3p.env import setting
from a3p.keys import generate, key_dir, rotate
from a3p.ledger import load_public_key, verify_ledger
from a3p.log import configure
from a3p.runner import write_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="a3p",
        description="Sample-based reliability and security probes for AI agents.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="run probe batteries and write a report")
    run_p.add_argument("-c", "--config", required=True, type=Path)
    run_p.add_argument("-o", "--output", type=Path)
    run_p.add_argument("--promptfoo", type=Path, help="import a Promptfoo JSON export")
    run_p.add_argument("--garak", type=Path, help="import a Garak JSONL report")

    verify_p = sub.add_parser("verify", help="re-check a signed ledger")
    verify_p.add_argument("ledger", type=Path)
    verify_p.add_argument("--public-key", type=Path, help="pin the auditor public key")

    report_p = sub.add_parser("report", help="rewrite HTML and PDF from results.json")
    report_p.add_argument("run_dir", type=Path)

    demo_p = sub.add_parser("demo", help="probe the intentionally vulnerable demo agents")
    demo_p.add_argument("-o", "--output", type=Path, default=Path("out/demo"))
    demo_p.add_argument(
        "--publish-sample",
        action="store_true",
        help="copy the vulnerable LangGraph run into docs/sample",
    )

    keys_p = sub.add_parser("keys", help="generate or rotate the signing key")
    keys_sub = keys_p.add_subparsers(dest="keys_cmd", required=True)
    keys_sub.add_parser("generate", help="create a key if none exists")
    keys_sub.add_parser("rotate", help="archive the current key and create a new one")

    eval_p = sub.add_parser("eval", help="score the shipped claim-detection set")
    eval_p.add_argument("suite", choices=["claims"])

    corpus_p = sub.add_parser("corpus", help="attack archive stats or a deterministic sample")
    corpus_p.add_argument("action", choices=["stats", "sample"])
    corpus_p.add_argument("--mode", choices=["quick", "full"], default="quick")
    corpus_p.add_argument("--seed", type=int, default=0)

    badge_p = sub.add_parser("verify-badge", help="check a signed method badge")
    badge_p.add_argument("badge", type=Path)
    badge_p.add_argument("--public-key", type=Path, help="pin the auditor public key")
    badge_p.add_argument("--identity", help="expected Sigstore certificate identity")
    badge_p.add_argument("--issuer", help="expected Sigstore OIDC issuer")

    board_p = sub.add_parser("leaderboard", help="static page of phantom-success rates from signed badges")
    board_p.add_argument("-o", "--output", type=Path, required=True)
    board_p.add_argument("runs", nargs="+", type=Path)

    scan_p = sub.add_parser("scan", help="one command: config file or http(s) endpoint, with live progress")
    scan_p.add_argument("target", help="path to a YAML config, or an http(s) chat-completions base URL")
    scan_p.add_argument("-o", "--output", type=Path)
    scan_p.add_argument("--sarif", type=Path, help="write a SARIF 2.1.0 file")
    scan_p.add_argument("--quiet", action="store_true", help="skip the live progress lines")

    guard_p = sub.add_parser("guard", help="block unverified success claims (HTTP and MCP-style JSON-RPC)")
    guard_p.add_argument("--host", default="127.0.0.1")
    guard_p.add_argument("--port", type=int, default=8766)

    attest_p = sub.add_parser("verify-attestation", help="check an in-toto DSSE envelope")
    attest_p.add_argument("envelope", type=Path)
    attest_p.add_argument("--public-key", type=Path)

    page_p = sub.add_parser("verify-page", help="write the static badge check page")
    page_p.add_argument("-o", "--output", type=Path, required=True)

    scan_mcp = sub.add_parser("mcp-scan", help="static tool JSON, or a live sandboxed MCP server")
    scan_mcp.add_argument("tools", nargs="?", type=Path, help="JSON list of MCP tools")
    scan_mcp.add_argument("--pin", type=Path, help="JSON object of name to sha256")
    scan_mcp.add_argument("--skills", type=Path, help="directory of skill files")
    scan_mcp.add_argument("--live", action="store_true", help="launch an MCP server inside the sandbox")
    scan_mcp.add_argument("--transport", choices=["stdio", "sse", "streamable"], default="stdio")
    scan_mcp.add_argument(
        "--sandbox",
        choices=["auto", "container", "runsc", "nsjail", "bwrap", "process"],
        default="auto",
    )
    scan_mcp.add_argument("--output", type=Path, help="directory for the signed ledger")
    scan_mcp.add_argument("--seed", type=int, default=0)
    scan_mcp.add_argument("--probe", default="3", help="archive rows to send, or all")
    scan_mcp.add_argument("--command", default="", help="server argv inside the sandbox; shlex-split, no shell")
    scan_mcp.add_argument("--url", default="", help="loopback HTTP URL the command binds inside the sandbox")
    scan_mcp.add_argument(
        "--invoke-destructive",
        action="store_true",
        help="call destructive tools inside the sandbox; the demo records a fake effect",
    )
    scan_mcp.add_argument(
        "--unsafe-process-sandbox",
        action="store_true",
        help="allow the subprocess sandbox, which leaves network and host files open",
    )

    dash_p = sub.add_parser("dashboard", help="local HTML history of results.json runs")
    dash_p.add_argument("--history", type=Path, required=True)
    dash_p.add_argument("--dump", type=Path, help="write the page and exit")
    dash_p.add_argument("--host", default="127.0.0.1")
    dash_p.add_argument("--port", type=int, default=8767)
    dash_p.add_argument("--token", default="", help="bearer token; required with --allow-remote")
    dash_p.add_argument(
        "--allow-remote",
        action="store_true",
        help="bind a non-loopback host; requires --token of at least 16 characters",
    )
    dash_p.add_argument("--tls", action="store_true", help="HTTPS when --allow-remote; self-signed if no cert is given")
    dash_p.add_argument("--tls-cert", type=Path, default=None)
    dash_p.add_argument("--tls-key", type=Path, default=None)

    keyless_p = sub.add_parser("sign-keyless", help="Fulcio/Rekor signature when ambient OIDC exists")
    keyless_p.add_argument("statement", type=Path, help="JSON in-toto statement")
    keyless_p.add_argument("-o", "--output", type=Path, required=True)

    sig_p = sub.add_parser("verify-sigstore", help="check a Sigstore bundle, including the Rekor proof")
    sig_p.add_argument("statement", type=Path)
    sig_p.add_argument("bundle", type=Path)
    sig_p.add_argument("--identity", required=True)
    sig_p.add_argument("--issuer", required=True)

    proxy_p = sub.add_parser("mcp-proxy", help="pin and allow-list a live MCP server")
    proxy_p.add_argument("--upstream-command", action="append", default=[], help="stdio upstream argv, repeatable")
    proxy_p.add_argument("--upstream-url", default="", help="streamable HTTP upstream")
    proxy_p.add_argument("--downstream", choices=["stdio", "streamable-http"], default="stdio")
    proxy_p.add_argument("--pin", type=Path, help="JSON object of tool name to sha256")
    proxy_p.add_argument("--allow", action="append", default=[], help="tool name to forward")
    proxy_p.add_argument("--upstream-env", action="append", default=[], help="KEY=VALUE passed to a stdio upstream")
    proxy_p.add_argument("--host", default="127.0.0.1")
    proxy_p.add_argument("--port", type=int, default=8768)

    args = parser.parse_args(argv)
    configure(setting("LOG_LEVEL") or "INFO")
    if args.cmd == "run":
        return _cmd_run(args)
    if args.cmd == "verify":
        return _cmd_verify(args)
    if args.cmd == "report":
        return _cmd_report(args)
    if args.cmd == "demo":
        from a3p.demo import ROOT, run_demo

        sample = ROOT / "docs" / "sample" if args.publish_sample else None
        run_demo(args.output, sample)
        return 0
    if args.cmd == "keys":
        return _cmd_keys(args)
    if args.cmd == "eval":
        return _cmd_eval()
    if args.cmd == "corpus":
        return _cmd_corpus(args)
    if args.cmd == "verify-badge":
        return _cmd_verify_badge(args)
    if args.cmd == "leaderboard":
        return _cmd_leaderboard(args)
    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "guard":
        return _cmd_guard(args)
    if args.cmd == "verify-attestation":
        return _cmd_verify_attestation(args)
    if args.cmd == "verify-page":
        return _cmd_verify_page(args)
    if args.cmd == "mcp-scan":
        return _cmd_mcp_scan(args)
    if args.cmd == "dashboard":
        return _cmd_dashboard(args)
    if args.cmd == "sign-keyless":
        return _cmd_sign_keyless(args)
    if args.cmd == "verify-sigstore":
        return _cmd_verify_sigstore(args)
    if args.cmd == "mcp-proxy":
        return _cmd_mcp_proxy(args)
    return 2


def _cmd_keys(args: argparse.Namespace) -> int:
    if args.keys_cmd == "rotate":
        path = rotate()
    else:
        path = key_dir() / "current.pem"
        if not path.exists():
            path = generate()
    print(f"signing key {path}")
    print(f"public key {path.with_name('current.pub')}")
    return 0


def _cmd_eval() -> int:
    from a3p.eval.metrics import dataset_path, load_cases, score_by_language, score_cases

    cases = load_cases(dataset_path())
    metrics, _misses = score_cases(cases)
    print(
        f"cases={metrics.total} positives={metrics.positives} negatives={metrics.negatives} "
        f"precision={metrics.precision:.4f} recall={metrics.recall:.4f} "
        f"fpr={metrics.false_positive_rate:.4f}"
    )
    ok = metrics.recall >= 0.95 and metrics.false_positive_rate <= 0.05 and metrics.precision >= 0.95
    for lang, row in score_by_language(cases).items():
        print(
            f"lang={lang} cases={row.total} precision={row.precision:.4f} "
            f"recall={row.recall:.4f} fpr={row.false_positive_rate:.4f}"
        )
        if row.total < 100 or row.recall < 0.95 or row.precision < 0.95 or row.false_positive_rate > 0.05:
            ok = False
    return 0 if ok else 1


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"config: {exc}", file=sys.stderr)
        return 2
    meta = {
        "client": config.meta.client,
        "agent_name": config.meta.agent_name,
        "agent_version": config.meta.agent_version,
        "scope": config.meta.scope,
        "auditor": config.meta.auditor,
        "seeds": config.seeds,
    }
    target = config.target
    output = args.output or Path(config.output.directory or "out/run")
    output.mkdir(parents=True, exist_ok=True)
    handle = RunHandle()
    try:
        adapter, handle = _adapter(target, log_dir=output)
        report = write_run(
            adapter,
            output,
            meta,
            battery_names=config.batteries,
            promptfoo=str(args.promptfoo) if args.promptfoo else None,
            garak=str(args.garak) if args.garak else None,
            judge=build_judge(config),
        )
    finally:
        handle.stop()
    print(f"score {report['overall']} band {report['band']}")
    print(str(report.get("meta", {}).get("assessment") or ""))
    components = (report.get("meta") or {}).get("components") or {}
    print(
        "isolation "
        f"tools={_level(components, 'tools')} "
        f"model={_level(components, 'model')} "
        f"probe={_level(components, 'probe')}"
    )
    print(f"report {output / 'report.html'}")
    print(f"ledger {output / 'ledger.jsonl'}")
    print(f"badge {output / 'badge.json'}")
    return 0


def _level(components: dict, name: str) -> str:
    block = components.get(name) or {}
    if isinstance(block, dict):
        return str(block.get("level") or "")
    return ""


def _cmd_verify(args: argparse.Namespace) -> int:
    pinned = load_public_key(args.public_key) if args.public_key else None
    result = verify_ledger(args.ledger, pinned)
    if result.ok:
        print(
            f"OK records={result.records} head={result.head} "
            f"signer=ed25519:{result.public_key_hex[:16]}"
        )
        return 0
    print(f"FAIL {result.reason}", file=sys.stderr)
    return 1


def _cmd_verify_badge(args: argparse.Namespace) -> int:
    from a3p.method import verify_badge, verify_badge_keyless

    document = json.loads(args.badge.read_text(encoding="utf-8"))
    pinned = args.public_key.read_text(encoding="utf-8").strip() if args.public_key else None
    if not isinstance(document, dict):
        print("FAIL badge was not an object", file=sys.stderr)
        return 1
    ok, reason = verify_badge(document, pinned)
    if not ok:
        print(f"FAIL {reason}", file=sys.stderr)
        return 1
    print(f"OK ed25519 {document.get('statement')}")
    if not args.identity and not args.issuer:
        print("Sigstore was not requested. Ed25519 is the offline signature.")
        return 0
    if not args.identity or not args.issuer:
        print("FAIL --identity and --issuer are both required for a Sigstore check", file=sys.stderr)
        return 2
    keyless_ok, keyless_reason = verify_badge_keyless(document, args.identity, args.issuer)
    if keyless_ok:
        print(f"OK sigstore {keyless_reason}")
        print("A matching signature is not a certification.")
        return 0
    print(f"FAIL {keyless_reason}", file=sys.stderr)
    return 1


def _cmd_leaderboard(args: argparse.Namespace) -> int:
    from a3p.leaderboard import write_site

    board = write_site(list(args.runs), args.output)
    print(f"rows={len(board['rows'])} rejected={len(board['rejected'])}")
    print(args.output / "index.html")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from a3p.report_html import render_html
    from a3p.report_pdf import render_pdf

    path = args.run_dir / "results.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    (args.run_dir / "report.html").write_text(render_html(report), encoding="utf-8")
    render_pdf(report, args.run_dir / "report.pdf")
    print(args.run_dir / "report.html")
    return 0


def _cmd_corpus(args: argparse.Namespace) -> int:
    from a3p.corpus import load_archive, sample_cases

    cases = load_archive()
    if args.action == "stats":
        languages: dict[str, int] = {}
        techniques: dict[str, int] = {}
        for case in cases:
            languages[str(case["language"])] = languages.get(str(case["language"]), 0) + 1
            techniques[str(case["technique"])] = techniques.get(str(case["technique"]), 0) + 1
        print(f"version={cases[0]['version'] if cases else '0'} cases={len(cases)}")
        print("languages=" + ",".join(f"{key}:{languages[key]}" for key in sorted(languages)))
        print("techniques=" + ",".join(f"{key}:{techniques[key]}" for key in sorted(techniques)))
        return 0
    chosen = sample_cases(cases, args.mode, seed=args.seed)
    print(f"mode={args.mode} seed={args.seed} cases={len(chosen)}")
    for case in chosen[:12]:
        print(f"{case['id']} {case['language']} {case['technique']}")
    return 0


def build_judge(config: RunConfig) -> object | None:
    """Rules score every run. The LLM judge is used only when the config asks."""
    judge = config.judge
    if not judge.enabled:
        return None
    if not judge.base_url or not judge.model:
        raise ConfigError("judge.enabled requires judge.base_url and judge.model")
    from a3p.judge import LLMJudge

    return LLMJudge(
        judge.base_url,
        judge.model,
        judge.api_key or "ollama",
        timeout_s=config.target.timeout_s,
    )


class RunHandle:
    """Stops an n8n stand-in and an egress proxy started for one run."""

    def __init__(self) -> None:
        self.proxy: EgressProxy | None = None
        self._stops: list[Any] = []

    def add(self, stop: Any) -> None:
        if stop is not None:
            self._stops.append(stop)

    def stop(self) -> None:
        while self._stops:
            self._stops.pop()()


def _adapter(target: TargetConfig, *, log_dir: Path | None = None) -> tuple[Any, RunHandle]:
    kind = target.adapter
    policy = target.policy
    handle = RunHandle()
    if kind == "callable":
        return CallableAdapter(policy), handle
    if kind == "langgraph":
        if target.base_url and not target.base_url.startswith("mock://"):
            from a3p.adapters.langgraph_model import LangGraphModelAdapter

            model_adapter = LangGraphModelAdapter(
                base_url=target.base_url,
                model=target.model or "qwen2.5:1.5b",
                api_key=target.api_key or "ollama",
                timeout=target.timeout_s,
            )
            _attach_egress(model_adapter, target.base_url, handle, log_dir)
            return model_adapter, handle
        return LangGraphAdapter(policy), handle
    if kind == "openai":
        base_url = target.base_url or "mock://vulnerable"
        chat = OpenAIChatAdapter(
            base_url=base_url,
            model=target.model or "a3p-mock",
            api_key=target.api_key or "mock",
            timeout=target.timeout_s,
            retries=target.retries,
        )
        if base_url.startswith(("http://", "https://")):
            _attach_egress(chat, base_url, handle, log_dir)
        return chat, handle
    if kind == "n8n":
        workflow = target.workflow
        if not workflow:
            raise SystemExit("n8n target needs target.workflow")
        mode = target.mode
        if mode == "http":
            if target.webhook_url:
                return N8nAdapter(workflow, policy, mode="http", webhook_url=target.webhook_url), handle
            server = N8nWebhookServer(workflow, policy)
            server.start()
            handle.add(server.stop)
            return N8nAdapter(workflow, policy, mode="http", server=server), handle
        return N8nAdapter(workflow, policy, mode="inprocess"), handle
    raise SystemExit(f"unknown adapter {kind!r}")


def _cmd_scan(args: argparse.Namespace) -> int:
    from a3p.sarif_out import render_sarif
    from a3p.tui import LiveProgress

    try:
        config = _scan_config(args.target)
    except ConfigError as exc:
        print(f"config: {exc}", file=sys.stderr)
        return 2
    output = args.output or Path(config.output.directory or "out/scan")
    output.mkdir(parents=True, exist_ok=True)
    names = config.batteries
    total = _scenario_total(names) * _seed_count(config.seeds)
    progress = None if args.quiet else LiveProgress(total, sys.stderr)
    meta = {
        "client": config.meta.client or "scan",
        "agent_name": config.meta.agent_name or args.target,
        "agent_version": config.meta.agent_version or "scan",
        "scope": config.meta.scope or "a3p scan",
        "auditor": config.meta.auditor or "a3p",
        "seeds": config.seeds,
    }
    handle = RunHandle()
    try:
        adapter, handle = _adapter(config.target, log_dir=output)
        report = write_run(
            adapter,
            output,
            meta,
            battery_names=names,
            judge=build_judge(config),
            on_scenario=progress,
        )
    finally:
        if progress is not None:
            progress.close()
        handle.stop()
    if args.sarif:
        args.sarif.write_text(json.dumps(render_sarif(report), indent=2) + "\n", encoding="utf-8")
        print(f"sarif {args.sarif}")
    print(f"score {report['overall']} band {report['band']}")
    print(str(report.get("meta", {}).get("assessment") or ""))
    print(f"report {output / 'report.html'}")
    return 0


def _seed_count(value: object) -> int:
    try:
        count = int(str(value))
    except (TypeError, ValueError):
        return 1
    return min(max(count, 1), 8)


def _scenario_total(names: list[str]) -> int:
    from a3p.batteries import BATTERIES

    return sum(len(BATTERIES[name]()) for name in names)


def _scan_config(target: str) -> RunConfig:
    if target.startswith(("http://", "https://")):
        return RunConfig(
            meta=MetaConfig(
                client="scan",
                agent_name=target,
                agent_version="endpoint",
                scope="a3p scan",
                auditor="a3p",
            ),
            target=TargetConfig(
                adapter="openai",
                base_url=target,
                model=setting("MODEL") or "default",
                api_key=setting("API_KEY") or "ollama",
            ),
        )
    path = Path(target)
    if not path.is_file():
        raise ConfigError(f"not a config file or http(s) endpoint: {target}")
    return load_config(path)


def _cmd_guard(args: argparse.Namespace) -> int:
    from a3p.guard import GuardServer

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print("guard binds to loopback only", file=sys.stderr)
        return 2
    server = GuardServer(args.host, args.port)
    url = server.start()
    print(f"guard {url}")
    print("POST /v1/screen  and  POST /mcp")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()
    return 0


def _cmd_verify_attestation(args: argparse.Namespace) -> int:
    from a3p.attest import AttestationError, verify_envelope

    try:
        envelope = json.loads(args.envelope.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("FAIL envelope was not JSON", file=sys.stderr)
        return 1
    if not isinstance(envelope, dict):
        print("FAIL envelope was not an object", file=sys.stderr)
        return 1
    pinned = args.public_key.read_text(encoding="utf-8").strip() if args.public_key else None
    try:
        document = verify_envelope(envelope, pinned)
    except AttestationError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    raw_predicate = document.get("predicate")
    predicate = raw_predicate if isinstance(raw_predicate, dict) else {}
    print(predicate.get("statement") or document.get("predicateType"))
    print("This signature is not a certification.")
    return 0


def _cmd_verify_page(args: argparse.Namespace) -> int:
    from a3p.verify_page import write_verification_page

    path = write_verification_page(args.output)
    print(path)
    return 0


def _cmd_mcp_scan(args: argparse.Namespace) -> int:
    from a3p.mcp_static import scan_skills, scan_tools

    if args.live:
        return _cmd_mcp_live(args)
    if args.tools is None:
        print("mcp-scan needs a tools JSON file, or --live", file=sys.stderr)
        return 2
    loaded = json.loads(args.tools.read_text(encoding="utf-8"))
    tools = loaded if isinstance(loaded, list) else []
    pins: dict[str, str] = {}
    if args.pin:
        raw = json.loads(args.pin.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            pins = {str(key): str(value) for key, value in raw.items()}
    findings = scan_tools([item for item in tools if isinstance(item, dict)], pins)
    if args.skills:
        findings.extend(scan_skills(args.skills, pins))
    print(json.dumps(findings, indent=2))
    return 1 if any(item.get("kind") in {"poisoning", "shadowing", "rug-pull"} for item in findings) else 0


def _cmd_mcp_live(args: argparse.Namespace) -> int:
    from a3p.mcp_dynamic import (
        McpScanError,
        loopback_port,
        parse_probe_limit,
        run_live_scan,
        split_command,
    )

    output = args.output or Path("out/mcp-scan")
    try:
        command = split_command(args.command) if args.command else None
        tcp_port = loopback_port(args.url) if args.url else None
        if tcp_port is not None and args.transport not in {"sse", "streamable"}:
            print("FAIL --url is the HTTP bridge; pass --transport sse or --transport streamable", file=sys.stderr)
            return 2
        if tcp_port is not None and command is None:
            print("FAIL --url needs --command, the server to launch inside the sandbox", file=sys.stderr)
            return 2
        report = run_live_scan(
            level=str(args.sandbox),
            transport=str(args.transport),
            output=output,
            seed=int(args.seed),
            probe_limit=parse_probe_limit(str(args.probe)),
            command=command,
            tcp_port=tcp_port,
            invoke_destructive=bool(args.invoke_destructive),
            allow_process=bool(args.unsafe_process_sandbox),
        )
    except (McpScanError, OSError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"findings": report["findings"], "ledger": str(output / "ledger.jsonl")}, indent=2))
    print("This scan is one sample, not a certification.")
    return 1 if report["findings"] else 0


def _cmd_sign_keyless(args: argparse.Namespace) -> int:
    from a3p.attest import AttestationError, KeylessUnavailable, sign_keyless

    try:
        document = json.loads(args.statement.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    if not isinstance(document, dict):
        print("FAIL statement was not an object", file=sys.stderr)
        return 1
    try:
        bundle = sign_keyless(document)
    except KeylessUnavailable as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    except AttestationError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    args.output.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print(args.output)
    print("This bundle is not a certification.")
    return 0


def _cmd_verify_sigstore(args: argparse.Namespace) -> int:
    import tempfile

    from a3p.attest import AttestationError, canonical, verify_keyless, verify_keyless_cli

    try:
        document = json.loads(args.statement.read_text(encoding="utf-8"))
        bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    if not isinstance(document, dict) or not isinstance(bundle, dict):
        print("FAIL statement and bundle must be JSON objects", file=sys.stderr)
        return 1
    try:
        checked = verify_keyless(document, bundle, identity=args.identity, issuer=args.issuer)
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "statement.json"
            artifact.write_text(canonical(document), encoding="utf-8")
            nested = bundle.get("bundle")
            raw_bundle = nested if isinstance(nested, dict) else bundle
            bundle_path = Path(directory) / "bundle.json"
            bundle_path.write_text(json.dumps(raw_bundle), encoding="utf-8")
            verify_keyless_cli(str(artifact), str(bundle_path), args.identity, args.issuer)
    except AttestationError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(f"logIndex {checked['logIndex']}")
    print("Rekor inclusion proof checked. This is not a certification.")
    return 0


def _cmd_mcp_proxy(args: argparse.Namespace) -> int:
    from a3p.mcp_proxy import ProxyRefusal, run_proxy_sync

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print("mcp-proxy binds to loopback only", file=sys.stderr)
        return 2
    pins: dict[str, str] = {}
    if args.pin:
        try:
            raw = json.loads(args.pin.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            return 1
        if isinstance(raw, dict):
            pins = {str(key): str(value) for key, value in raw.items()}
    allow = set(args.allow) if args.allow else None
    upstream_env: dict[str, str] = {}
    for item in args.upstream_env:
        if "=" not in item:
            print(f"FAIL upstream env must be KEY=VALUE, got {item}", file=sys.stderr)
            return 2
        key, value = item.split("=", 1)
        upstream_env[key] = value
    command = list(args.upstream_command) or None
    url = args.upstream_url or None
    if command and url:
        print("pass an upstream command or a URL, not both", file=sys.stderr)
        return 2
    if not command and not url:
        print("mcp-proxy needs --upstream-command or --upstream-url", file=sys.stderr)
        return 2
    try:
        run_proxy_sync(
            upstream_command=command,
            upstream_url=url,
            downstream=args.downstream,
            host=args.host,
            port=args.port,
            pins=pins,
            allow=allow,
            upstream_env=upstream_env or None,
        )
    except ProxyRefusal as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from a3p.dashboard import LOOPBACK, generate_certificate, load_history, render_history, serve

    remote = args.host not in LOOPBACK
    if remote and not args.allow_remote:
        print("dashboard stays on loopback unless --allow-remote and --token are set", file=sys.stderr)
        return 2
    if args.allow_remote and len(args.token) < 16:
        print("FAIL --allow-remote requires --token of at least 16 characters", file=sys.stderr)
        return 2
    wants_tls = bool(args.tls or args.tls_cert or args.tls_key)
    if wants_tls and not args.allow_remote:
        print("FAIL dashboard TLS requires --allow-remote", file=sys.stderr)
        return 2
    if (args.tls_cert is None) != (args.tls_key is None):
        print("FAIL pass both --tls-cert and --tls-key", file=sys.stderr)
        return 2
    token = args.token or None
    if args.dump:
        args.dump.write_text(render_history(load_history(args.history), remote=remote), encoding="utf-8")
        print(args.dump)
        return 0
    certfile = str(args.tls_cert) if args.tls_cert else None
    keyfile = str(args.tls_key) if args.tls_key else None
    if args.tls and certfile is None:
        cert_path, key_path = generate_certificate(Path(tempfile.mkdtemp(prefix="a3p-dash-tls-")), args.host)
        certfile, keyfile = str(cert_path), str(key_path)
        print("self-signed certificate for this process only; this is not a public deployment", file=sys.stderr)
    try:
        server = serve(args.history, args.host, args.port, token=token, certfile=certfile, keyfile=keyfile)
    except ValueError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    scheme = "https" if certfile else "http"
    print(f"{scheme}://{args.host}:{server.server_address[1]}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def _attach_egress(adapter: Any, base_url: str, handle: RunHandle, log_dir: Path | None) -> None:
    cleanup: Path | None = None
    directory = log_dir
    if directory is None:
        cleanup = Path(tempfile.mkdtemp(prefix="a3p-egress-"))
        directory = cleanup
    directory.mkdir(parents=True, exist_ok=True)
    proxy = EgressProxy.for_base_url(base_url, directory / "egress.log", intercept=True)
    adapter.proxy = proxy.start()
    adapter.tls_intercept = bool(proxy.intercept and proxy.ca_path)
    handle.proxy = proxy
    handle.add(proxy.stop)
    if cleanup is not None:
        handle.add(lambda: shutil.rmtree(cleanup, ignore_errors=True))
