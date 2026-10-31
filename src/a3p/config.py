"""Typed run configuration. Unknown fields are rejected."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ADAPTERS = {"callable", "langgraph", "openai", "n8n"}
POLICIES = {"vulnerable", "careful"}
BATTERY_NAMES = {"phantom", "injection", "permission", "leakage"}


class ConfigError(ValueError):
    pass


@dataclass
class MetaConfig:
    client: str = ""
    agent_name: str = ""
    agent_version: str = ""
    scope: str = ""
    auditor: str = ""


@dataclass
class TargetConfig:
    adapter: str = "callable"
    policy: str = "vulnerable"
    base_url: str = ""
    model: str = ""
    api_key: str = ""
    workflow: str = ""
    mode: str = "inprocess"
    webhook_url: str = ""
    timeout_s: float = 30.0
    retries: int = 2


@dataclass
class OutputConfig:
    directory: str = "out/run"


@dataclass
class JudgeConfig:
    enabled: bool = False
    base_url: str = ""
    model: str = ""
    api_key: str = ""


@dataclass
class RunConfig:
    meta: MetaConfig = field(default_factory=MetaConfig)
    target: TargetConfig = field(default_factory=TargetConfig)
    batteries: list[str] = field(default_factory=lambda: sorted(BATTERY_NAMES))
    output: OutputConfig = field(default_factory=OutputConfig)
    judge: JudgeConfig = field(default_factory=JudgeConfig)
    seeds: int = 1


def load_config(path: Path) -> RunConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    raw = _expand(raw)
    if not isinstance(raw, dict):
        raise ConfigError("config must be a mapping")
    _unknown(raw, {"meta", "target", "batteries", "output", "judge", "seeds"})
    return RunConfig(
        meta=_meta(raw.get("meta") or {}),
        target=_target(raw.get("target") or {}),
        batteries=_batteries(raw.get("batteries")),
        output=_output(raw.get("output") or {}),
        judge=_judge(raw.get("judge") or {}),
        seeds=_seeds(raw.get("seeds")),
    )


def _meta(raw: object) -> MetaConfig:
    data = _mapping(raw, "meta")
    _unknown(data, {"client", "agent_name", "agent_version", "scope", "auditor"})
    return MetaConfig(**{key: _text(data.get(key), key) for key in ("client", "agent_name", "agent_version", "scope", "auditor")})


def _target(raw: object) -> TargetConfig:
    data = _mapping(raw, "target")
    _unknown(
        data,
        {
            "adapter", "policy", "base_url", "model", "api_key", "workflow",
            "mode", "webhook_url", "timeout_s", "retries",
        },
    )
    adapter = str(data.get("adapter") or "callable")
    policy = str(data.get("policy") or "vulnerable")
    mode = str(data.get("mode") or "inprocess")
    if adapter not in ADAPTERS:
        raise ConfigError(f"unknown adapter {adapter!r}")
    if policy not in POLICIES:
        raise ConfigError(f"unknown policy {policy!r}")
    if mode not in {"inprocess", "http"}:
        raise ConfigError(f"unknown mode {mode!r}")
    timeout = float(data.get("timeout_s") or 30)
    raw_retries = data.get("retries")
    retries = 2 if raw_retries is None else int(str(raw_retries))
    if not 0.1 <= timeout <= 120:
        raise ConfigError("timeout_s must be between 0.1 and 120")
    if not 0 <= retries <= 5:
        raise ConfigError("retries must be between 0 and 5")
    api_key = _text(data.get("api_key"), "api_key")
    if api_key.startswith("$"):
        api_key = os.environ.get(api_key[1:], "")
    workflow = _text(data.get("workflow"), "workflow")
    if workflow and not Path(workflow).is_file():
        raise ConfigError(f"workflow file not found: {workflow}")
    return TargetConfig(
        adapter=adapter,
        policy=policy,
        base_url=_text(data.get("base_url"), "base_url"),
        model=_text(data.get("model"), "model"),
        api_key=api_key,
        workflow=workflow,
        mode=mode,
        webhook_url=_text(data.get("webhook_url"), "webhook_url"),
        timeout_s=timeout,
        retries=retries,
    )


def _seeds(raw: object) -> int:
    if raw is None:
        return 1
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ConfigError("seeds must be an integer")
    if not 1 <= raw <= 8:
        raise ConfigError("seeds must be between 1 and 8")
    return raw


def _batteries(raw: object) -> list[str]:
    if raw is None:
        return sorted(BATTERY_NAMES)
    if not isinstance(raw, list) or not raw:
        raise ConfigError("batteries must be a non-empty list")
    names = [str(item) for item in raw]
    unknown = [name for name in names if name not in BATTERY_NAMES]
    if unknown:
        raise ConfigError(f"unknown batteries: {', '.join(unknown)}")
    return names


def _output(raw: object) -> OutputConfig:
    data = _mapping(raw, "output")
    _unknown(data, {"directory"})
    directory = _text(data.get("directory"), "directory") or "out/run"
    if ".." in Path(directory).parts:
        raise ConfigError("output directory must not contain '..'")
    return OutputConfig(directory=directory)


def _judge(raw: object) -> JudgeConfig:
    data = _mapping(raw, "judge")
    _unknown(data, {"enabled", "base_url", "model", "api_key"})
    api_key = _text(data.get("api_key"), "api_key")
    if api_key.startswith("$"):
        api_key = os.environ.get(api_key[1:], "")
    return JudgeConfig(
        enabled=bool(data.get("enabled") or False),
        base_url=_text(data.get("base_url"), "base_url"),
        model=_text(data.get("model"), "model"),
        api_key=api_key,
    )


def _mapping(raw: object, name: str) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{name} must be a mapping")
    return raw


def _unknown(data: dict, allowed: set[str]) -> None:
    extra = sorted(set(data) - allowed)
    if extra:
        raise ConfigError("unknown fields: " + ", ".join(extra))


def _expand(value: object) -> object:
    if isinstance(value, dict):
        return {key: _expand(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand(item) for item in value]
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        body = value[2:-1]
        if ":-" in body:
            name, default = body.split(":-", 1)
            return os.environ.get(name, default)
        return os.environ.get(body, "")
    return value


def _text(value: object, name: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value
