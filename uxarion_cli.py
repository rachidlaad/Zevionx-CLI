#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Uxarion – AI-driven pentesting agent with single execution gateway."""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import platform
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlsplit

try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - rich optional
    Console = None  # type: ignore[assignment]
    RICH_AVAILABLE = False

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init()  # type: ignore[misc]
except Exception:  # pragma: no cover - colorama optional
    class _ForeFallback:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""

    class _StyleFallback:
        RESET_ALL = ""
        BRIGHT = ""
        DIM = ""

    Fore = _ForeFallback()  # type: ignore[assignment]
    Style = _StyleFallback()  # type: ignore[assignment]


RESET = getattr(Style, "RESET_ALL", "")
DIM = getattr(Style, "DIM", "")
BRIGHT = getattr(Style, "BRIGHT", "")


def _color(text: str, prefix: str) -> str:
    return f"{prefix}{text}{RESET}" if prefix else text


openai_client = None

DEFAULT_PROVIDER = "openai"
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.2")
OPENAI_REASONING_EFFORT = os.environ.get("OPENAI_REASONING_EFFORT", "high")
OPENAI_DECISION_REASONING_EFFORT = os.environ.get(
    "OPENAI_DECISION_REASONING_EFFORT",
    os.environ.get("OPENAI_REASONING_EFFORT", "medium"),
)
OPENAI_CONTEXT_REASONING_EFFORT = os.environ.get("OPENAI_CONTEXT_REASONING_EFFORT", "low")
OPENAI_REPORT_REASONING_EFFORT = os.environ.get(
    "OPENAI_REPORT_REASONING_EFFORT",
    os.environ.get("OPENAI_REASONING_EFFORT", "medium"),
)
OPENAI_DIRECT_REPLY_REASONING_EFFORT = os.environ.get(
    "OPENAI_DIRECT_REPLY_REASONING_EFFORT",
    os.environ.get("OPENAI_REASONING_EFFORT", "low"),
)

DEFAULT_TIMEOUT_S = 300
MIN_TIMEOUT_S = 10
MAX_TIMEOUT_S = 3600
IDLE_TIMEOUT_S = 180
MAX_STREAM_LINE_CHARS = 400
MAX_STREAM_CAPTURE_LINES = 1200
MAX_STREAM_EMIT_LINES = 260
WALL_CLOCK_LIMIT_S: Optional[int] = None
SCHEMA_VERSION = "1.0"
LOOP_MODE_DIRECT = "direct"
LOOP_MODES = {LOOP_MODE_DIRECT}

_ENV_DEFAULT_TOOLS = os.environ.get("UXARION_ALLOW_TOOLS") or os.environ.get("POWN_ALLOW_TOOLS")
DEFAULT_TOOL_ALLOW: Optional[Set[str]] = (
    {tool.strip() for tool in _ENV_DEFAULT_TOOLS.split(",") if tool.strip()}
    if _ENV_DEFAULT_TOOLS
    else None
)

DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\s+/(?:\s|$)",
    r"\bmkfs\.",
    r"\bdd\s+if=",
    r"\bshutdown\b",
    r"\breboot\b",
    r":\(\)\s*{\s*:\s*\|\s*:\s*;\s*}\s*;\s*:",
    r"\bchown\s+-R\s+/",
    r"\bchmod\s+-R\s+777\s+/",
]

_REDACT_API_KEY_RE = re.compile(r"(key=)[^&\s]+")


def _redact_api_keys(text: str) -> str:
    return _REDACT_API_KEY_RE.sub(r"\1***REDACTED***", text or "")


SHELL_BUILTINS = {
    "command",
    "cd",
    "echo",
    "export",
    "printf",
    "pwd",
    "set",
    "test",
    "[",
    "type",
    "ulimit",
    "umask",
    "unset",
}
# ----------------------------------------------------------------------------
# Policy / memory containers
# ----------------------------------------------------------------------------


@dataclass
class Policy:
    dry_run: bool = False
    no_command_timeouts: bool = False
    idle_timeout_s: int = IDLE_TIMEOUT_S
    show_banner: bool = True
    jsonl_path: Optional[str] = None
    verbosity: str = "normal"
    loop_mode: str = LOOP_MODE_DIRECT


@dataclass
class Memory:
    history: List[Dict[str, Any]] = field(default_factory=list)
    discovered_vulns: List[str] = field(default_factory=list)
    context_notes: List[str] = field(default_factory=list)
    completed_deliverables: List[str] = field(default_factory=list)
    blocked_deliverables: List[str] = field(default_factory=list)
    next_focus: List[str] = field(default_factory=list)


# ----------------------------------------------------------------------------
# Command execution (single gateway target)
# ----------------------------------------------------------------------------


def stream_command_execution(
    command: str,
    timeout: Optional[int] = DEFAULT_TIMEOUT_S,
    idle_timeout: Optional[int] = IDLE_TIMEOUT_S,
    *,
    workdir: Optional[str] = None,
    use_stdbuf: bool = False,
    emit_console: bool = True,
    line_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Run a shell command and stream output to stdout."""
    if emit_console:
        print(f"\n> {command}")
        print("\033[90m" + "─" * 80 + "\033[0m")

    proc: Optional[subprocess.Popen[str]] = None
    try:
        run_cmd = command
        if use_stdbuf and command.lstrip()[:6] != "stdbuf":
            run_cmd = f"stdbuf -oL -eL {command}"
        start = time.time()
        last_output = start
        proc = subprocess.Popen(
            run_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            executable="/bin/bash",
            preexec_fn=os.setsid,
            cwd=workdir,
        )

        output_lines: List[str] = []
        capture_truncated = False
        termination_reason = "completed"
        last_line: Optional[str] = None
        last_line_time = start
        repeat_count = 0
        suppress_until = 0.0
        emitted_lines = 0
        emit_truncated_notice = False
        while True:
            now = time.time()
            if timeout and (now - start) > timeout:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                    proc.wait(timeout=8)
                    termination_reason = "timeout"
                except Exception:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    termination_reason = "timeout_killed"
                if emit_console:
                    print(f"\033[91mCommand timed out after {timeout}s\033[0m")
                break

            line = proc.stdout.readline() if proc.stdout else ""
            if not line and proc.poll() is not None:
                break
            if line:
                clean = line.rstrip("\n")
                if len(clean) > MAX_STREAM_LINE_CHARS:
                    clean = f"{clean[:MAX_STREAM_LINE_CHARS - 20].rstrip()} ... [line truncated]"
                if len(output_lines) < MAX_STREAM_CAPTURE_LINES:
                    output_lines.append(clean)
                elif not capture_truncated:
                    output_lines.append(f"... (output truncated after {MAX_STREAM_CAPTURE_LINES} lines) ...")
                    capture_truncated = True
                if emitted_lines < MAX_STREAM_EMIT_LINES:
                    if line_callback:
                        try:
                            line_callback(clean)
                        except Exception:
                            pass
                    if emit_console:
                        print(f"\033[90m{clean}\033[0m")
                    emitted_lines += 1
                elif not emit_truncated_notice:
                    notice = f"... (live output truncated after {MAX_STREAM_EMIT_LINES} lines) ..."
                    if line_callback:
                        try:
                            line_callback(notice)
                        except Exception:
                            pass
                    if emit_console:
                        print(f"\033[90m{notice}\033[0m")
                    emit_truncated_notice = True
                if clean == last_line and (now - last_line_time) < 2.0:
                    repeat_count += 1
                    if repeat_count > 5:
                        if now < suppress_until:
                            last_output = now
                            continue
                        suppress_until = now + 1.0
                        last_output = now
                        continue
                else:
                    repeat_count = 0
                    last_line = clean
                    last_line_time = now
                last_output = now

            if idle_timeout and (now - last_output) > idle_timeout:
                try:
                    if emit_console:
                        print(f"\033[91mNo output for {idle_timeout}s - sending SIGINT\033[0m")
                    os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                    proc.wait(timeout=8)
                    termination_reason = "idle"
                except Exception:
                    if emit_console:
                        print("\033[91mEscalating to SIGKILL\033[0m")
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    termination_reason = "idle_killed"
                break

        returncode = proc.wait()
        duration = time.time() - start
        if emit_console:
            print("\033[90m" + "─" * 80 + "\033[0m")
            print(f"✅ Exit code: {returncode} | Duration: {duration:.1f}s\n")

        return {
            "returncode": returncode,
            "output": "\n".join(output_lines),
            "duration": round(duration, 2),
            "termination_reason": termination_reason,
        }
    except Exception as exc:
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        if emit_console:
            print(f"\033[91m❌ Error: {exc}\033[0m")
        return {
            "returncode": 1,
            "output": f"Execution failed: {exc}",
            "duration": 0.0,
            "termination_reason": "error",
        }
    finally:
        if proc is not None and proc.stdout is not None:
            try:
                proc.stdout.close()
            except Exception:
                pass


def parse_max_commands(user_prompt: str) -> Optional[int]:
    """Extract strict command budgets from the user request."""
    patterns = [
        r"\bexactly\s+(\d+)\s+commands?\b",
        r"\brun\s+(\d+)\s+commands?\b",
        r"\b(\d+)\s+commands?\s*(?:max|maximum|only)?\b",
    ]
    for pat in patterns:
        match = re.search(pat, user_prompt, flags=re.IGNORECASE)
        if match:
            try:
                return max(1, int(match.group(1)))
            except ValueError:
                continue
    return None


def normalize_loop_mode(loop_mode: Optional[str], *, default: str = LOOP_MODE_DIRECT) -> str:
    candidate = (loop_mode or default).strip().lower()
    if candidate == "guided":
        candidate = LOOP_MODE_DIRECT
    if candidate not in LOOP_MODES:
        allowed = ", ".join(sorted(LOOP_MODES))
        raise ValueError(f"Invalid loop mode '{loop_mode}'. Allowed values: {allowed}")
    return candidate


def in_cidrs(ip: ipaddress._BaseAddress, cidrs: Optional[List[ipaddress._BaseNetwork]]) -> bool:
    if not cidrs:
        return True
    return any(ip in network for network in cidrs)


def parse_hosts_and_urls(s: str) -> tuple[Set[str], Set[str]]:
    urls = {
        match.group(0)
        for match in re.finditer(r"https?://[A-Za-z0-9\.\-]+(?::\d+)?(?:/[^\s]*)?", s)
    }

    hosts: Set[str] = set()

    for match in re.finditer(r"https?://([^/\s:]+)", s):
        token = match.group(1).strip("[]'\"")
        if token:
            hosts.add(token)

    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s):
        token = match.group(0).strip("[]'\"")
        if token:
            hosts.add(token)

    # Require at least two ':' characters to avoid false-positives like the ":PORT"
    # suffix in IPv4 URLs (e.g., "127.0.0.1:5002" contains "1:5002").
    for match in re.finditer(r"\b[0-9a-fA-F]{0,4}:(?:[0-9a-fA-F]{0,4}:)+[0-9a-fA-F]{0,4}\b", s):
        token = match.group(0).strip("[]'\"")
        if token:
            hosts.add(token)

    if "localhost" in s:
        hosts.add("localhost")

    hosts.discard("")
    return hosts, urls


def first_tool(cmd: str) -> str:
    try:
        parts = shlex.split(cmd)
    except Exception:
        return ""
    return parts[0] if parts else ""


def validate_freeform_command(
    cmd: str,
    *,
    scope_hosts: Set[str],
    allow_tools: Optional[Set[str]] = None,
    deny_tools: Set[str] = frozenset(),
    scope_cidrs: Optional[List[ipaddress._BaseNetwork]] = None,
) -> tuple[bool, str, Dict[str, Any]]:
    statement = cmd.strip()

    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, statement):
            return False, f"dangerous pattern: {pat}", {"risk": 1.0}

    tool = first_tool(statement)
    if tool in deny_tools:
        return False, f"tool explicitly denied: {tool}", {"risk": 0.9}
    if allow_tools and tool and tool not in SHELL_BUILTINS and tool not in allow_tools:
        return False, f"tool not in allow-list: {tool}", {"risk": 0.7}

    if tool and tool not in SHELL_BUILTINS and shutil.which(tool) is None:
        return False, f"tool not found on PATH: {tool}", {"risk": 0.6, "missing_tool": tool}

    hosts, _ = parse_hosts_and_urls(statement)
    if hosts:
        out_of_scope = {host for host in hosts if scope_hosts and host not in scope_hosts}
        if out_of_scope:
            return False, f"out-of-scope host(s): {', '.join(sorted(out_of_scope))}", {"risk": 0.7}
        if scope_cidrs:
            for host in hosts:
                try:
                    ip_obj = ipaddress.ip_address(host)
                except ValueError:
                    continue
                if not in_cidrs(ip_obj, scope_cidrs):
                    return False, f"IP {host} outside allowed CIDR ranges", {"risk": 0.7}

    if tool == "sqlmap" and "--batch" not in statement:
        return False, "sqlmap must include --batch (non-interactive)", {"risk": 0.4}

    return True, "ok", {"risk": 0.3, "tool": tool}


def validate_decision_schema(decision: Dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(decision, dict):
        return False, "decision response not a JSON object"
    if "stop" not in decision or not isinstance(decision["stop"], bool):
        return False, "missing or invalid 'stop' boolean"
    if "reason" not in decision or not isinstance(decision["reason"], str):
        return False, "missing or invalid 'reason' string"
    stop_flag = decision["stop"]
    command_value = decision.get("command")
    if stop_flag:
        if command_value is not None and not isinstance(command_value, str):
            return False, "'command' must be string when provided"
    else:
        if not isinstance(command_value, str) or not command_value.strip():
            return False, "non-stop decisions must include a non-empty command string"
    timeout_hint = decision.get("timeout_hint")
    if timeout_hint is not None and not isinstance(timeout_hint, (int, float)):
        return False, "timeout_hint must be an integer or null"
    final_reply = decision.get("final_reply")
    if final_reply is not None and not isinstance(final_reply, str):
        return False, "final_reply must be a string when provided"
    return True, "ok"


def load_api_keys() -> Dict[str, str]:
    keys: Dict[str, str] = {}
    try:
        with open(".env", "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped.startswith("OPENAI_API_KEY="):
                    keys["openai"] = stripped.split("=", 1)[1]
    except FileNotFoundError:
        pass

    env_openai = os.getenv("OPENAI_API_KEY")
    # Environment value must override .env for testability and runtime overrides.
    if env_openai:
        keys["openai"] = env_openai
    return keys


def _update_env_var_file(env_var: str, value: str, *, env_path: str = ".env") -> None:
    lines: List[str] = []
    try:
        with open(env_path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        lines = []

    updated = False
    for idx, line in enumerate(lines):
        if line.startswith(f"{env_var}="):
            lines[idx] = f"{env_var}={value}"
            updated = True
            break
    if not updated:
        lines.append(f"{env_var}={value}")

    with open(env_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines).rstrip() + "\n")


def _mask_secret(value: str) -> str:
    secret = (value or "").strip()
    if not secret:
        return "(empty)"
    if len(secret) <= 8:
        return secret[:2] + "..." + secret[-1:]
    return secret[:6] + "..." + secret[-4:]


def set_openai_api_key(api_key: Optional[str] = None) -> str:
    key = (api_key or "").strip()
    if not key:
        if sys.stdin.isatty():
            try:
                key = getpass.getpass("Enter OpenAI API key: ").strip()
            except Exception:
                key = input("Enter OpenAI API key: ").strip()
        else:
            key = input("Enter OpenAI API key: ").strip()
    if not key:
        raise ValueError("No API key provided.")

    os.environ["OPENAI_API_KEY"] = key
    _update_env_var_file("OPENAI_API_KEY", key)

    global openai_client
    openai_client = None
    return key


def run_doctor() -> int:
    checks: List[tuple[str, bool, str]] = []

    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python >= 3.10", py_ok, platform.python_version()))

    openai_pkg = shutil.which("python3") is not None
    try:
        import openai  # type: ignore  # noqa: F401
        openai_pkg = True
    except Exception:
        openai_pkg = False
    checks.append(("openai package installed", openai_pkg, "required for agent execution"))

    has_key = bool(load_api_keys().get("openai"))
    checks.append(("OPENAI_API_KEY configured", has_key, "use `uxarion --addKey`"))

    for tool in ("curl", "openssl", "dig"):
        present = shutil.which(tool) is not None
        checks.append((f"tool `{tool}` available", present, "optional but recommended"))

    print("Uxarion Doctor")
    print("--------------")
    for label, ok, detail in checks:
        status = _color("OK", Fore.GREEN) if ok else _color("MISSING", Fore.RED)
        print(f"[{status}] {label}  ({detail})")

    critical_failures = [item for item in checks if not item[1] and item[0] in {"Python >= 3.10", "openai package installed", "OPENAI_API_KEY configured"}]
    if critical_failures:
        print("\nSetup incomplete. Fix the missing critical items above.")
        return 1
    print("\nSetup looks good.")
    return 0


def get_openai_client():
    global openai_client
    if openai_client is None:
        keys = load_api_keys()
        if "openai" not in keys:
            raise RuntimeError("OPENAI_API_KEY not configured")
        from openai import OpenAI

        openai_client = OpenAI(api_key=keys["openai"])
    return openai_client


# ----------------------------------------------------------------------------
# Timeout helpers & sanitizers
# ----------------------------------------------------------------------------


def _clamp_timeout(value: Optional[int]) -> int:
    base = value if value is not None else DEFAULT_TIMEOUT_S
    return max(MIN_TIMEOUT_S, min(MAX_TIMEOUT_S, int(base)))


def _classify_command(cmd: str) -> str:
    lowered = cmd.lower()
    if re.search(r"\b(curl|wget)\b", lowered) and not re.search(r"(-i|-I|-d\s|--data|--proxy|--retry|\b-F\b)", lowered):
        return "http_probe_fast"
    if re.search(r"(-w\s|wordlist|--rate|--threads)", lowered):
        return "content_enum"
    if re.search(r"(-p-|--top-ports|-sC|-sV|-A|--level|--risk)", lowered):
        return "deep_scan"
    if re.search(r"(--forms|--batch|--crawl|--dbs|--tables)", lowered):
        return "automated_injection"
    return "generic"


def _suggest_timeout_for(cmd: str) -> int:
    category = _classify_command(cmd)
    return {
        "http_probe_fast": 60,
        "content_enum": 300,
        "deep_scan": 300,
        "automated_injection": 600,
        "generic": DEFAULT_TIMEOUT_S,
    }[category]


def _should_prefix_stdbuf(command: str, tool_name: str, *, has_stdbuf: bool) -> bool:
    if not has_stdbuf:
        return False
    if not tool_name or tool_name in SHELL_BUILTINS:
        return False

    stripped = (command or "").lstrip()
    if not stripped:
        return False
    if stripped[0] in "({[":
        return False

    # Prefixing `stdbuf` in front of compound shell statements can break syntax.
    if any(token in stripped for token in (";", "&&", "||", "\n")):
        return False

    first = first_tool(stripped)
    if first in {"for", "while", "if", "case", "until", "select", "function"}:
        return False
    return True


# ----------------------------------------------------------------------------
# AI helpers – chat JSON / text with hardening
# ----------------------------------------------------------------------------


def _normalize_reasoning_effort(value: Optional[str], *, default: str = "medium") -> str:
    candidate = (value or default).strip().lower() or default
    if candidate not in {"none", "low", "medium", "high", "xhigh"}:
        return default
    return candidate


def chat_json_openai(
    system: str,
    payload: Dict[str, Any],
    model: str = OPENAI_MODEL,
    *,
    reasoning_effort: Optional[str] = None,
) -> Dict[str, Any]:
    client = get_openai_client()
    user_payload = json.dumps(payload, indent=2)
    effort = _normalize_reasoning_effort(reasoning_effort, default="medium")
    try:
        resp = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_payload},
            ],
            max_output_tokens=2000,
            reasoning={"effort": effort},
            text={
                "verbosity": "low",
                "format": {"type": "json_object"},
            },
            timeout=30,
        )
        content = (getattr(resp, "output_text", "") or "").strip()
        if not content:
            raise RuntimeError("OpenAI JSON response was empty")
        return json.loads(_clean_json_candidate(content))
    except Exception as exc:
        # Compatibility fallback for older SDK/runtime behavior.
        try:
            resp = client.chat.completions.create(
                model=model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_payload},
                ],
                timeout=30,
            )
            content = resp.choices[0].message.content or "{}"
            return json.loads(_clean_json_candidate(content))
        except Exception as fallback_exc:
            raise RuntimeError(f"OpenAI JSON completion failed: {fallback_exc}") from exc


def chat_text_openai(
    system: str,
    payload: Dict[str, Any],
    model: str = OPENAI_MODEL,
    *,
    reasoning_effort: Optional[str] = None,
) -> str:
    client = get_openai_client()
    user_payload = json.dumps(payload, indent=2)
    effort = _normalize_reasoning_effort(reasoning_effort, default="low")
    try:
        resp = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_payload},
            ],
            max_output_tokens=2200,
            reasoning={"effort": effort},
            text={"verbosity": "low"},
            timeout=30,
        )
        content = getattr(resp, "output_text", "") or ""
        if content.strip():
            return content
        raise RuntimeError("OpenAI text response was empty")
    except Exception as exc:
        # Compatibility fallback for older SDK/runtime behavior.
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_payload},
                ],
                timeout=30,
            )
            return resp.choices[0].message.content or ""
        except Exception as fallback_exc:
            raise RuntimeError(f"OpenAI text completion failed: {fallback_exc}") from exc


def _clean_json_candidate(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def chat_json(
    system: str,
    payload: Dict[str, Any],
    provider: str = DEFAULT_PROVIDER,
    *,
    retries: int = 2,
    backoff_seconds: float = 0.8,
    reasoning_effort: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_provider = (provider or DEFAULT_PROVIDER).strip().lower()
    if normalized_provider != DEFAULT_PROVIDER:
        raise RuntimeError(f"Unsupported provider '{provider}'. Only '{DEFAULT_PROVIDER}' is available.")
    last_error: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            return chat_json_openai(system, payload, reasoning_effort=reasoning_effort)
        except Exception as exc:  # noqa: PERF203
            last_error = exc
            if attempt == retries:
                break
            time.sleep(backoff_seconds)
    raise RuntimeError(
        f"AI decision request failed after {retries} retries; connection appears unstable."
    ) from last_error


def chat_text(
    system: str,
    payload: Dict[str, Any],
    provider: str = DEFAULT_PROVIDER,
    *,
    reasoning_effort: Optional[str] = None,
) -> str:
    normalized_provider = (provider or DEFAULT_PROVIDER).strip().lower()
    if normalized_provider != DEFAULT_PROVIDER:
        raise RuntimeError(f"Unsupported provider '{provider}'. Only '{DEFAULT_PROVIDER}' is available.")
    return chat_text_openai(system, payload, reasoning_effort=reasoning_effort)


# ----------------------------------------------------------------------------
# Context compression helpers
# ----------------------------------------------------------------------------

MAX_CONTEXT_NOTE_LEN = 180
MAX_CONTEXT_NOTES = 24
MAX_OUTPUT_FOR_CONTEXT = 2800
MAX_LAST_OUTPUT_FOR_DECISION = 1800
_DELIVERABLE_TOKEN_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "into",
    "onto",
    "that",
    "this",
    "http",
    "https",
    "www",
    "com",
    "org",
    "net",
    "dev",
    "app",
    "io",
}
_DELIVERABLE_TOKEN_CANONICAL = {
    "cert": "certificate",
    "certs": "certificate",
    "certificates": "certificate",
    "headers": "header",
    "records": "record",
    "titles": "title",
    "statuses": "status",
    "details": "detail",
    "basics": "detail",
}


def _normalize_short_line(value: str, *, limit: int = MAX_CONTEXT_NOTE_LEN) -> str:
    compact = re.sub(r"\s+", " ", (value or "")).strip()
    if not compact:
        return ""
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"


def _append_unique_short_lines(target: List[str], candidates: List[str], *, limit: int) -> None:
    for item in candidates:
        normalized = _normalize_short_line(item)
        if not normalized:
            continue
        lowered = normalized.lower()
        if any(existing.lower() == lowered for existing in target):
            continue
        target.append(normalized)
    if len(target) > limit:
        del target[:-limit]


def _trim_output(value: str, *, limit: int) -> str:
    text = (value or "").strip()
    if len(text) <= limit:
        return text
    head = int(limit * 0.7)
    tail = max(0, limit - head - 32)
    return f"{text[:head].rstrip()}\n\n... (truncated) ...\n\n{text[-tail:].lstrip()}"


def _deliverable_tokens(value: str) -> Set[str]:
    tokens = re.findall(r"[a-z0-9]{3,}", (value or "").lower())
    normalized: Set[str] = set()
    for token in tokens:
        canonical = _DELIVERABLE_TOKEN_CANONICAL.get(token, token)
        if canonical in _DELIVERABLE_TOKEN_STOPWORDS:
            continue
        normalized.add(canonical)
    return normalized


def _deliverables_match(candidate: str, resolved: str) -> bool:
    left = _normalize_short_line(candidate, limit=300).lower()
    right = _normalize_short_line(resolved, limit=300).lower()
    if not left or not right:
        return False
    if left == right:
        return True

    left_tokens = _deliverable_tokens(left)
    right_tokens = _deliverable_tokens(right)
    if not left_tokens or not right_tokens:
        return False

    overlap = left_tokens & right_tokens
    if len(overlap) < 2:
        return False
    if left_tokens.issubset(right_tokens) or right_tokens.issubset(left_tokens):
        return True
    overlap_ratio_left = len(overlap) / len(left_tokens)
    overlap_ratio_right = len(overlap) / len(right_tokens)
    if overlap_ratio_left >= 0.5 and overlap_ratio_right >= 0.5:
        return True
    return len(overlap) >= 3 and (overlap_ratio_left >= 0.5 or overlap_ratio_right >= 0.5)


def summarize_for_report(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    summary: List[Dict[str, Any]] = []
    for item in history:
        obs = item.get("observation", {})
        summary.append(
            {
                "phase": item.get("phase", ""),
                "analysis": item.get("analysis", ""),
                "command": obs.get("command", ""),
                "returncode": obs.get("returncode", 0),
                "duration": obs.get("duration", 0),
                "output_excerpt": obs.get("output", "")[:300],
            }
        )
    return summary

def should_finish(decision: Dict[str, Any], observation: Dict[str, Any]) -> bool:
    phase = (decision.get("phase") or "").lower()
    if phase == "report":
        return True
    finish_note = (decision.get("finish_if") or "").strip().lower()
    if finish_note and finish_note != "":
        obs_output = observation.get("output", "").lower()
        if finish_note in obs_output:
            return True
    return False


def extract_evidence(output: str, max_lines: int = 6) -> List[str]:
    if not output:
        return []
    heuristics = [
        r"\b(server|version|powered|allowed|method|header|missing|warning|error|vulnerab|cookie|auth|login)\b",
        r"^[A-Z][A-Za-z0-9\-]+:\s*",
        r"^/[A-Za-z0-9._\-]+",
        r"\b\d{3}\b",
    ]
    rx = re.compile("|".join(heuristics), re.IGNORECASE)
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    hits = [ln for ln in lines if rx.search(ln)]
    evidence: List[str] = []
    seen = set()
    for line in hits:
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        evidence.append(line)
        if len(evidence) >= max_lines:
            break
    return evidence


def analyze_shell(command: str, sandbox_dir: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    info["has_sequence"] = bool(re.search(r";|&&|\|\|", command))
    info["has_subshell"] = ("`" in command) or ("$(" in command)

    segments = [seg.strip() for seg in command.split("|")]
    info["pipe_count"] = max(len(segments) - 1, 0)
    allowed_sinks = {"head", "tail", "grep", "awk", "sed", "cut", "tee"}
    info["pipe_ok"] = True
    info["pipe_sink"] = None
    if info["pipe_count"] > 1:
        info["pipe_ok"] = False
    elif info["pipe_count"] == 1:
        sink_tool = first_tool(segments[-1])
        info["pipe_sink"] = sink_tool
        if sink_tool not in allowed_sinks:
            info["pipe_ok"] = False

    redirects: List[str] = []
    for match in re.finditer(r"(?:^|\s)([0-9]*>{1,2})\s*(\S+)", command):
        redirect_target = match.group(2).strip('"\'')
        redirects.append(redirect_target)
    info["redirects"] = redirects
    info["redirects_ok"] = True
    info["redirect_violations"] = []
    sandbox_dir_abs = os.path.realpath(sandbox_dir)
    for target in redirects:
        if not target:
            continue
        candidate = target if os.path.isabs(target) else os.path.join(sandbox_dir_abs, target)
        abs_target = os.path.realpath(candidate)
        if os.path.commonpath([abs_target, sandbox_dir_abs]) != sandbox_dir_abs:
            info["redirects_ok"] = False
            info["redirect_violations"].append(target)

    info["analysis_ok"] = (
        not info["has_sequence"]
        and not info["has_subshell"]
        and info["pipe_ok"]
        and info["redirects_ok"]
    )
    info["control_ops_blocked"] = False
    info["sandbox_dir"] = sandbox_dir
    return info


def command_signature(cmd: str) -> str:
    try:
        parts = shlex.split(cmd)
    except Exception:
        return cmd.strip()
    if not parts:
        return cmd.strip()
    tool = parts[0]
    args = " ".join(sorted(parts[1:]))
    return f"{tool}::{args}"


def command_family(cmd: str) -> str:
    try:
        parts = shlex.split(cmd)
    except Exception:
        parts = cmd.strip().split()
    if not parts:
        return "unknown"
    tool = parts[0]
    for token in parts[1:]:
        if token.startswith("http://") or token.startswith("https://"):
            parsed = urlsplit(token)
            path_segments = [seg for seg in parsed.path.split("/") if seg]
            path_hint = "/"
            if path_segments:
                path_hint = "/" + "/".join(path_segments[:2])
            return f"{tool} {parsed.scheme}://{parsed.netloc}{path_hint}"
    return tool


# ----------------------------------------------------------------------------
# Agent implementation
# ----------------------------------------------------------------------------

DIRECT_EXECUTION_PROMPT = """You are an autonomous security assistant and penetration-testing executor.
The user task is authoritative and must be handled verbatim.

Reply ONLY with JSON in one of these shapes:
1) Continue:
{{
  "stop": false,
  "reason": "<why this action advances the task>",
  "command": "<single shell command to execute now>"
}}
2) Complete:
{{
  "stop": true,
  "reason": "<why the task is complete or blocked>",
  "final_reply": "<final plain-text answer for the user>"
}}

User_task_verbatim:
{user_task}

Available_tools:
{tools_hint}

Context_memory (high-value notes from prior steps):
{context_memory}

Conversation_turn_context (carry-over memory from earlier user turns):
{conversation_turn_context}

Deliverables_state:
{deliverables_state}

Recent_step_briefs (newest first):
{recent_step_briefs}

Recent_command_families (latest grouping to avoid redundant steps):
{recent_command_families}

Last_command_result:
{last_command_result}

Last_command_output (raw, only latest command):
{last_command_output}

Terminal_capabilities:
{terminal_capabilities}

Timeout_seconds:
{timeout_seconds}

Rules:
1. Return exactly one command when stop=false.
2. Base the next action on Last_command_result, Last_command_output, Context_memory, Deliverables_state, and Recent_command_families.
3. Do not stop until requested deliverables are completed with evidence or explicitly blocked with reason.
4. Do not ask again for target/input if it already exists in task or context.
5. Keep commands non-interactive and fully specified.
6. Use robust shell syntax. Avoid brittle quoting and avoid `set -e` on pipelines that may return non-zero (for example grep/head with no matches) unless explicitly guarded.
7. Keep each command bounded and safe: limit endpoints per command, bound output (`head`/selected lines), and prefer request timeouts (for example `curl --max-time`).
8. Prefer atomic commands that target one unmet deliverable at a time. Avoid long nested scripts unless unavoidable.
9. If target is an explicit HTTP(S) URL/port and deliverables are web-focused, prioritize HTTP-level probes first. Avoid broad port/service scans unless a specific gap requires it.
10. If using scan/enumeration tools (for example nmap/ffuf/sqlmap), include explicit runtime bounds (`--max-time`, `--maxtime`, `--host-timeout`, low thread/rate) so each step completes quickly.
11. If a deliverable is already completed in Deliverables_state, do not rerun it unless evidence is conflicting or stale.
12. Do not repeat the same command family unless there is a clear delta (different method, path cluster, protocol/port, or auth/cookie context). If repeated, explain the delta in `reason`.
13. If the previous command failed, run one minimal corrective step next; do not restart broad enumeration.
14. Keep output focused. Prefer compact evidence extraction (status/headers/selected lines) over full document dumps.
15. Use POSIX-compatible shell syntax; avoid placeholders.
16. If the user input is a plain question, greeting, explanation request, or planning request that does not require running shell commands, return stop=true immediately with a direct final_reply.
17. For command-based security tasks, final_reply must be practical and grounded in observed evidence and should follow requested output structure when provided.
18. Do not mention internal orchestration, loop state, hidden memory, or schema rules.
19. Do not use emojis in final_reply unless the user explicitly asks for them.
20. If the user references previous work (for example: "continue", "next", "retest that"), resolve it from Conversation_turn_context without asking to restart from zero.
21. Keep follow-up actions incremental: prefer the smallest next command that advances unresolved items.
22. Be command-efficient: for routine micro-tasks aim to finish in a small number of high-signal commands, then stop with a clear reply.
23. For Python one-liners/scripts, prefer `python3` unless `python` is explicitly confirmed available.
24. Do not jump to heavyweight scanners (for example `nikto`, `nmap`, `whatweb`, `ffuf`) unless the user explicitly asks for them or a specific evidence gap requires them.
25. Stay strictly in-scope; avoid external lookups or third-party endpoints unless required for the user task.

Return valid JSON only."""

STEP_CONTEXT_PROMPT = """You compress one command result into high-value memory for an autonomous pentest loop.
Return JSON only with this schema:
{{
  "step_summary": "<one concise sentence>",
  "valuable_observations": ["<short fact from output>"],
  "completed_deliverables": ["<task-level deliverable now done>"],
  "blocked_deliverables": ["<task-level deliverable blocked and why>"],
  "next_focus": ["<task-level deliverable still needed next>"]
}}

Rules:
- Ground every statement in provided output/result only; no speculation.
- Keep each string under 180 chars.
- Prefer concrete evidence (status codes, headers, cert facts, DNS, discovered endpoints).
- Do not copy long output; summarize into compact facts.
- Use stable task-level phrasing (for example: DNS records, TLS details, HTTP headers, robots, sitemap, tech fingerprinting, exposed ports).
- next_focus must include only unresolved tasks and must NOT repeat anything already in deliverables_state.completed or deliverables_state.blocked.
- Do not output generic items like "command ran" or "step completed".
- If output is empty/uninformative, return empty arrays and a short step_summary."""

REPORT_PROMPT = """Create a concise plain-text penetration test summary grounded in observed evidence.
If execution was partial, explicitly separate completed checks and blocked/failed checks.
Include key findings, risk interpretation, limitations, and next safe validation steps."""

DIRECT_REPLY_PROMPT = """You are Uxarion, a concise assistant inside a terminal chat.
Respond directly to the user's message as plain text.

Rules:
- Keep the answer useful and concise.
- Do not mention internal execution loops, reports, or hidden system state.
- If the user asks for a security action that needs a target/scope but none is provided, ask briefly for the missing target/scope/authorization details.
- Do not use emojis unless explicitly requested by the user."""


class Agent:
    def __init__(self, policy: Policy, provider: str = DEFAULT_PROVIDER):
        normalized_provider = (provider or DEFAULT_PROVIDER).strip().lower()
        if normalized_provider != DEFAULT_PROVIDER:
            raise ValueError(f"Unsupported provider '{provider}'. Only '{DEFAULT_PROVIDER}' is available.")
        self.policy = policy
        self.provider = DEFAULT_PROVIDER
        self.memory = Memory()

    def _push_event(
        self,
        callback: Optional[Callable[[Dict[str, Any]], None]],
        payload: Dict[str, Any],
    ) -> None:
        if callback is None:
            return
        try:
            callback(payload)
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _resolve_timeout(self, command: str, timeout_hint: Optional[int]) -> tuple[Optional[int], str]:
        if self.policy.no_command_timeouts:
            return None, "⏱ Per-command timeout: disabled (idle & wall-clock still apply)."
        hint = _clamp_timeout(timeout_hint) if timeout_hint is not None else None
        floor = _suggest_timeout_for(command)
        effective = _clamp_timeout(max(floor, hint or 0))
        return effective, f"⏱ Timeout for this command: {effective}s"

    def _execute_command(
        self,
        command: str,
        analysis: str,
        *,
        effective_timeout: Optional[int],
        workdir: str,
        use_stdbuf: bool,
        emit_console: bool,
        line_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        idle_timeout = self.policy.idle_timeout_s or None

        if self.policy.dry_run:
            if emit_console:
                print(f"\n> {command}")
            return {
                "command": command,
                "original_command": command,
                "purpose": analysis,
                "returncode": 0,
                "output": f"[DRY-RUN] Would execute: {command}",
                "duration": 0.0,
                "timeout_used": effective_timeout,
                "termination_reason": "dry-run",
            }

        result = stream_command_execution(
            command,
            timeout=effective_timeout,
            idle_timeout=idle_timeout,
            workdir=workdir,
            use_stdbuf=use_stdbuf,
            emit_console=emit_console,
            line_callback=line_callback,
        )
        result.update(
            {
                "command": command,
                "original_command": command,
                "purpose": analysis,
                "timeout_used": effective_timeout,
            }
        )
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _context_text(value: Any) -> str:
        if value in (None, "", [], {}):
            return "(none)"
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False)

    def _deliverables_state(self) -> Dict[str, List[str]]:
        return {
            "completed": self.memory.completed_deliverables[-10:],
            "blocked": self.memory.blocked_deliverables[-10:],
            "next_focus": self.memory.next_focus[-10:],
        }

    def _context_memory_text(self) -> str:
        notes = self.memory.context_notes[-MAX_CONTEXT_NOTES:]
        if not notes:
            return "(none)"
        return "\n".join(f"- {item}" for item in notes)

    def _conversation_turn_context_text(self, conversation_context: Optional[Dict[str, Any]]) -> str:
        if not conversation_context or not isinstance(conversation_context, dict):
            return "(none)"

        lines: List[str] = []

        def _append_line(label: str, value: str) -> None:
            normalized = _normalize_short_line(value, limit=220)
            if normalized:
                lines.append(f"- {label}: {normalized}")

        target = conversation_context.get("last_known_target")
        if isinstance(target, str) and target.strip():
            _append_line("target", target)

        session_goal = conversation_context.get("session_goal")
        if isinstance(session_goal, str) and session_goal.strip():
            _append_line("session_goal", session_goal)

        for key, label, cap in (
            ("recent_user_tasks", "user_task", 4),
            ("recent_agent_replies", "assistant_reply", 3),
            ("carry_over_notes", "note", 8),
            ("carry_over_findings", "finding", 6),
            ("pending_items", "pending", 8),
        ):
            values = conversation_context.get(key, [])
            if not isinstance(values, list):
                continue
            for item in values[-cap:]:
                if isinstance(item, str) and item.strip():
                    _append_line(label, item)

        return "\n".join(lines) if lines else "(none)"

    def _recent_step_briefs(self, limit: int = 8) -> str:
        lines: List[str] = []
        for entry in reversed(self.memory.history[-limit:]):
            observation = entry.get("observation", {}) or {}
            command = (observation.get("command") or "").strip()
            if not command:
                continue
            summary = (entry.get("context_memory", {}) or {}).get("step_summary") or ""
            if not summary:
                if observation.get("returncode") is None:
                    summary = observation.get("termination_reason") or "no result"
                else:
                    summary = f"rc={observation.get('returncode')}"
            summary = _normalize_short_line(summary, limit=140) or "no summary"
            lines.append(f"- {command} :: {summary}")
        return "\n".join(lines) if lines else "(none)"

    def _recent_command_families(self, limit: int = 10) -> str:
        counts: Dict[str, int] = {}
        last_cmd_for_family: Dict[str, str] = {}
        for entry in self.memory.history[-limit:]:
            observation = entry.get("observation", {}) or {}
            command = (observation.get("command") or "").strip()
            if not command:
                continue
            family = command_family(command)
            counts[family] = counts.get(family, 0) + 1
            last_cmd_for_family[family] = _normalize_short_line(command, limit=120) or command[:120]
        if not counts:
            return "(none)"
        ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        lines = [
            f"- {family} :: count={count} :: last={last_cmd_for_family.get(family, '')}"
            for family, count in ordered[:8]
        ]
        return "\n".join(lines)

    def _last_command_result(self) -> Dict[str, Any]:
        if not self.memory.history:
            return {"status": "no previous command"}
        entry = self.memory.history[-1]
        observation = entry.get("observation", {}) or {}
        step_context = entry.get("context_memory", {}) or {}
        return {
            "step": entry.get("step"),
            "command": observation.get("command"),
            "returncode": observation.get("returncode"),
            "termination_reason": observation.get("termination_reason"),
            "duration_seconds": observation.get("duration"),
            "step_summary": step_context.get("step_summary", ""),
            "evidence": (observation.get("evidence") or [])[:6],
        }

    def _last_command_output(self) -> str:
        if not self.memory.history:
            return "(none)"
        output = (self.memory.history[-1].get("observation", {}) or {}).get("output", "")
        compact = _trim_output(output, limit=MAX_LAST_OUTPUT_FOR_DECISION)
        return compact or "(none)"

    def _request_decision_direct(
        self,
        user_task: str,
        tools_hint: str = "",
        *,
        conversation_context: Optional[Dict[str, Any]] = None,
        terminal_capabilities: Optional[Dict[str, Any]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        prompt = DIRECT_EXECUTION_PROMPT.format(
            user_task=user_task.rstrip(),
            tools_hint=tools_hint or "none detected",
            context_memory=self._context_memory_text(),
            conversation_turn_context=self._conversation_turn_context_text(conversation_context),
            deliverables_state=self._context_text(self._deliverables_state()),
            recent_step_briefs=self._recent_step_briefs(),
            recent_command_families=self._recent_command_families(),
            last_command_result=self._context_text(self._last_command_result()),
            last_command_output=self._last_command_output(),
            terminal_capabilities=self._context_text(terminal_capabilities),
            timeout_seconds=self._context_text(timeout_seconds),
        )
        return chat_json(
            prompt,
            {},
            self.provider,
            reasoning_effort=OPENAI_DECISION_REASONING_EFFORT,
        )

    def _fallback_step_context(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        output = observation.get("output", "") or ""
        evidence = extract_evidence(output, max_lines=4)
        rc = observation.get("returncode")
        status_line = f"Command completed with rc={rc}" if rc is not None else "Command completed"
        if observation.get("termination_reason") and observation.get("termination_reason") != "completed":
            status_line = f"{status_line} ({observation.get('termination_reason')})"
        completed: List[str] = []
        blocked: List[str] = []
        if rc == 0:
            completed.append(status_line)
        elif rc is not None:
            blocked.append(status_line)
        return {
            "step_summary": evidence[0] if evidence else status_line,
            "valuable_observations": evidence[:3],
            "completed_deliverables": completed,
            "blocked_deliverables": blocked,
            "next_focus": [],
        }

    def _summarize_step_context(
        self,
        *,
        user_task: str,
        reason_text: str,
        observation: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "user_task": user_task,
            "reason_for_command": reason_text,
            "command": observation.get("command", ""),
            "returncode": observation.get("returncode"),
            "termination_reason": observation.get("termination_reason"),
            "duration_seconds": observation.get("duration"),
            "output": _trim_output(observation.get("output", ""), limit=MAX_OUTPUT_FOR_CONTEXT),
            "current_context_notes": self.memory.context_notes[-10:],
            "deliverables_state": self._deliverables_state(),
        }
        try:
            raw = chat_json(
                STEP_CONTEXT_PROMPT,
                payload,
                self.provider,
                retries=3,
                backoff_seconds=0.5,
                reasoning_effort=OPENAI_CONTEXT_REASONING_EFFORT,
            )
        except Exception:
            return self._fallback_step_context(observation)

        if not isinstance(raw, dict):
            return self._fallback_step_context(observation)

        def _collect(key: str, *, cap: int = 8) -> List[str]:
            values = raw.get(key, [])
            if not isinstance(values, list):
                return []
            cleaned: List[str] = []
            for value in values:
                if not isinstance(value, str):
                    continue
                normalized = _normalize_short_line(value)
                if normalized:
                    cleaned.append(normalized)
                if len(cleaned) >= cap:
                    break
            return cleaned

        step_summary = _normalize_short_line(str(raw.get("step_summary", ""))) or ""
        parsed = {
            "step_summary": step_summary,
            "valuable_observations": _collect("valuable_observations"),
            "completed_deliverables": _collect("completed_deliverables"),
            "blocked_deliverables": _collect("blocked_deliverables"),
            "next_focus": _collect("next_focus"),
        }
        if not parsed["step_summary"] and parsed["valuable_observations"]:
            parsed["step_summary"] = parsed["valuable_observations"][0]
        if not parsed["step_summary"]:
            fallback = self._fallback_step_context(observation)
            parsed["step_summary"] = fallback["step_summary"]
            if not parsed["valuable_observations"]:
                parsed["valuable_observations"] = fallback["valuable_observations"]
        return parsed

    def _apply_step_context(self, step_context: Dict[str, Any]) -> None:
        summary = step_context.get("step_summary")
        if isinstance(summary, str) and summary.strip():
            _append_unique_short_lines(self.memory.context_notes, [summary], limit=MAX_CONTEXT_NOTES)
        _append_unique_short_lines(
            self.memory.context_notes,
            [item for item in step_context.get("valuable_observations", []) if isinstance(item, str)],
            limit=MAX_CONTEXT_NOTES,
        )
        _append_unique_short_lines(
            self.memory.completed_deliverables,
            [item for item in step_context.get("completed_deliverables", []) if isinstance(item, str)],
            limit=24,
        )
        _append_unique_short_lines(
            self.memory.blocked_deliverables,
            [item for item in step_context.get("blocked_deliverables", []) if isinstance(item, str)],
            limit=24,
        )
        _append_unique_short_lines(
            self.memory.next_focus,
            [item for item in step_context.get("next_focus", []) if isinstance(item, str)],
            limit=24,
        )
        resolved = [
            item
            for item in (self.memory.completed_deliverables + self.memory.blocked_deliverables)
            if isinstance(item, str) and item.strip()
        ]
        if resolved and self.memory.next_focus:
            filtered_focus: List[str] = []
            for item in self.memory.next_focus:
                if any(_deliverables_match(item, done_item) for done_item in resolved):
                    continue
                filtered_focus.append(item)
            self.memory.next_focus = filtered_focus[-24:]

    # ------------------------------------------------------------------
    def _generate_report(self, intent_paragraph: str, execution_mode: str) -> str:
        evidence_lines: List[str] = []
        for entry in self.memory.history:
            obs = entry.get("observation", {})
            phase = entry.get("phase", "").upper() or "PHASE"
            for line in obs.get("evidence", []):
                formatted = f"{phase}: {line}" if line else None
                if formatted and formatted not in evidence_lines:
                    evidence_lines.append(formatted)
                if len(evidence_lines) >= 10:
                    break
            if len(evidence_lines) >= 10:
                break

        payload = {
            "intent": intent_paragraph,
            "findings": self.memory.discovered_vulns,
            "history": summarize_for_report(self.memory.history),
            "evidence": evidence_lines,
            "execution_mode": execution_mode,
        }
        report_text = chat_text(
            REPORT_PROMPT,
            payload,
            self.provider,
            reasoning_effort=OPENAI_REPORT_REASONING_EFFORT,
        )
        if not report_text:
            raise RuntimeError("Report generation returned an empty response.")
        return report_text.strip()

    def _generate_direct_reply(self, user_text: str) -> str:
        payload = {"user_text": user_text}
        reply = chat_text(
            DIRECT_REPLY_PROMPT,
            payload,
            self.provider,
            reasoning_effort=OPENAI_DIRECT_REPLY_REASONING_EFFORT,
        )
        if not reply:
            raise RuntimeError("Direct reply generation returned an empty response.")
        return reply.strip()

    # ------------------------------------------------------------------
    def run(
        self,
        user_prompt: str,
        *,
        max_commands: Optional[int] = None,
        scope_hosts: Optional[Set[str]] = None,
        allow_tools: Optional[Set[str]] = None,
        deny_tools: Optional[Set[str]] = None,
        scope_cidrs: Optional[List[ipaddress._BaseNetwork]] = None,
        exit_on_first_finding: bool = False,
        report_out_path: Optional[str] = None,
        validate: bool = True,
        loop_mode: Optional[str] = None,
        conversation_context: Optional[Dict[str, Any]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        run_id = uuid.uuid4().hex
        self.run_id = run_id
        active_loop_mode = normalize_loop_mode(loop_mode, default=getattr(self.policy, "loop_mode", LOOP_MODE_DIRECT))
        self.memory = Memory()
        intent_paragraph = user_prompt.strip()
        emit_console = event_callback is None
        if emit_console:
            print(f"\n{intent_paragraph}\n")
        self._push_event(
            event_callback,
            {
                "type": "intent",
                "run_id": run_id,
                "intent": intent_paragraph,
                "assumptions": [],
                "derived_targets": [],
                "loop_mode": active_loop_mode,
            },
        )
        target_hints_list: List[str] = []

        start_time = time.time()
        step = 0
        hard_cap = max_commands if max_commands is not None else parse_max_commands(user_prompt)
        executed = 0
        stop_reason = "completed"
        artifacts_root = os.environ.get("UXARION_ARTIFACT_DIR") or os.environ.get("POWN_ARTIFACT_DIR")
        if artifacts_root:
            run_dir = os.path.abspath(os.path.join(artifacts_root, run_id))
        else:
            run_dir = os.path.abspath(os.path.join(os.getcwd(), ".uxarion_runs", run_id))
        os.makedirs(run_dir, exist_ok=True)
        execution_cwd = os.getcwd()

        MAX_DECISION_RETRIES = 3

        _ = scope_hosts
        _ = allow_tools
        _ = deny_tools
        _ = scope_cidrs
        _ = validate
        # Direct loop remains prompt-governed; command hard-blocking stays disabled.
        validate_commands = False

        has_stdbuf = shutil.which("stdbuf") is not None

        decision_retries = 0
        user_intent_text = user_prompt.strip()
        final_reply: Optional[str] = None

        common_tools = [
            "curl",
            "wget",
            "httpie",
            "nmap",
            "openssl",
            "sslyze",
            "sslscan",
            "whatweb",
            "nikto",
            "gobuster",
            "ffuf",
            "nslookup",
            "host",
            "dig",
            "testssl.sh",
        ]
        available_tools = [tool for tool in common_tools if shutil.which(tool)]
        tools_hint = ", ".join(available_tools) if available_tools else "none detected"
        terminal_capabilities = {
            "shell": "bash",
            "cwd": execution_cwd,
            "has_timeout_cmd": bool(shutil.which("timeout")),
            "has_curl": bool(shutil.which("curl")),
            "has_wget": bool(shutil.which("wget")),
            "has_httpie": bool(shutil.which("http")),
            "has_python": bool(shutil.which("python3") or shutil.which("python")),
            "has_nmap": bool(shutil.which("nmap")),
            "has_nslookup": bool(shutil.which("nslookup")),
            "has_host": bool(shutil.which("host")),
            "has_dig": bool(shutil.which("dig")),
            "available_tools": available_tools,
        }
        timeout_seconds_context: Optional[int] = None if self.policy.no_command_timeouts else DEFAULT_TIMEOUT_S

        while True:
            if WALL_CLOCK_LIMIT_S and time.time() - start_time > WALL_CLOCK_LIMIT_S:
                if emit_console:
                    print("Wall clock limit reached, wrapping up.")
                stop_reason = f"wall-clock limit ({WALL_CLOCK_LIMIT_S}s) reached"
                break

            step += 1

            try:
                decision = self._request_decision_direct(
                    user_intent_text,
                    tools_hint,
                    conversation_context=conversation_context,
                    terminal_capabilities=terminal_capabilities,
                    timeout_seconds=timeout_seconds_context,
                )
            except Exception as exc:
                if emit_console:
                    print(f"error: decision request failed ({exc})")
                stop_reason = "decision_failure"
                break

            if "error" in decision:
                if emit_console:
                    print(f"error: decision response contained error ({decision['error']})")
                stop_reason = "decision_error"
                break

            schema_ok, schema_reason = validate_decision_schema(decision)
            if not schema_ok:
                decision_retries += 1
                if decision_retries > MAX_DECISION_RETRIES:
                    if emit_console:
                        print("error: decision retries exhausted")
                    stop_reason = "decision_retry_exhausted"
                    break
                if decision_retries > 1:
                    if emit_console:
                        print(f"error: invalid decision response ({schema_reason})")
                    stop_reason = "decision_invalid_json"
                    break
                if emit_console:
                    print("error: invalid decision response; retrying")
                continue

            if bool(decision.get("stop")):
                stop_reason = decision.get("reason") or "decision_stop"
                candidate_reply = decision.get("final_reply")
                if isinstance(candidate_reply, str) and candidate_reply.strip():
                    final_reply = candidate_reply.strip()
                break

            reason_text = (decision.get("reason") or "AI-generated command").strip()
            command = (decision.get("command") or "").strip()
            timeout_hint = decision.get("timeout_hint")

            if not command:
                if emit_console:
                    print("error: decision returned empty command; retrying")
                decision_retries += 1
                if decision_retries > MAX_DECISION_RETRIES:
                    if emit_console:
                        print("error: decision retries exhausted")
                    stop_reason = "decision_retry_exhausted"
                    break
                if decision_retries > 1:
                    stop_reason = "decision_empty"
                    break
                continue

            self._push_event(
                event_callback,
                {
                    "type": "decision",
                    "run_id": run_id,
                    "step": step,
                    "reason": reason_text,
                    "command": command,
                    "decision": decision,
                },
            )

            validator_record = {"ok": True, "reason": "prompt-governed direct mode", "risk": 0.0}
            if validate_commands:
                validator_record["reason"] = "validation disabled by direct execution loop"

            tool_name = validator_record.get("tool") or first_tool(command)
            if tool_name:
                validator_record["tool"] = tool_name
            use_stdbuf = _should_prefix_stdbuf(command, tool_name, has_stdbuf=has_stdbuf)

            effective_timeout, timeout_msg = self._resolve_timeout(command, timeout_hint)

            thought_line = reason_text.splitlines()[0] if reason_text else "continuing"
            if len(thought_line) > 160:
                thought_line = thought_line[:157] + "…"
            if emit_console:
                print(f"thinking: {thought_line}")
                print(f"> {command}")

            def _line_event(line: str) -> None:
                self._push_event(
                    event_callback,
                    {
                        "type": "output",
                        "run_id": run_id,
                        "step": step,
                        "command": command,
                        "line": line,
                    },
                )

            observation = self._execute_command(
                command,
                reason_text,
                effective_timeout=effective_timeout,
                workdir=execution_cwd,
                use_stdbuf=use_stdbuf,
                emit_console=emit_console,
                line_callback=_line_event if event_callback else None,
            )
            executed += 1
            decision_retries = 0

            observation.setdefault("termination_reason", "completed")
            observation["phase"] = decision.get("phase", "free_form")
            observation["decision_id"] = decision.get("decision_id")
            observation["analysis"] = reason_text
            observation["timeout_message"] = timeout_msg
            observation["step_index"] = step
            observation["run_id"] = run_id
            observation["source"] = "free_form"
            observation["tool"] = validator_record.get("tool") or first_tool(command)
            observation["validator"] = validator_record

            is_live_obs = observation.get("termination_reason") not in {"dry-run", "error"}
            if is_live_obs:
                observation["evidence"] = extract_evidence(observation.get("output", ""))
            else:
                observation["evidence"] = []

            step_context = self._summarize_step_context(
                user_task=user_intent_text,
                reason_text=reason_text,
                observation=observation,
            )
            self._apply_step_context(step_context)
            observation["context_summary"] = step_context

            entry = {
                "step": step,
                "phase": decision.get("phase", "free_form"),
                "analysis": reason_text,
                "decision": decision,
                "observation": observation,
                "context_memory": step_context,
                "validator": validator_record,
                "timeout_message": timeout_msg,
                "run_id": run_id,
                "source": "free_form",
            }
            self.memory.history.append(entry)
            self._push_event(
                event_callback,
                {
                    "type": "observation",
                    "run_id": run_id,
                    "step": step,
                    "observation": observation,
                },
            )

            if self.policy.jsonl_path:
                try:
                    jsonl_entry = entry.copy()
                    jsonl_entry.update(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "provider": self.provider,
                            "execution_mode": "dry-run"
                            if observation.get("termination_reason") == "dry-run"
                            else "live",
                            "loop_mode": active_loop_mode,
                            "targets": target_hints_list,
                            "run_id": run_id,
                        }
                    )
                    with open(self.policy.jsonl_path, "a", encoding="utf-8") as jf:
                        jf.write(json.dumps(jsonl_entry, ensure_ascii=False) + "\n")
                except Exception as exc:
                    if emit_console:
                        print(f"warning: JSONL write failed: {exc}")

            if exit_on_first_finding and self.memory.discovered_vulns:
                stop_reason = "first finding observed"
                break
            if hard_cap is not None and executed >= hard_cap:
                if emit_console:
                    print(f"Command budget reached (executed {executed}/{hard_cap}).")
                stop_reason = f"command budget used ({executed}/{hard_cap})"
                break

        live_seen = any(
            entry.get("observation", {}).get("termination_reason") not in {"dry-run", "error"}
            for entry in self.memory.history
        )
        execution_mode = "live" if live_seen else "dry-run"

        if final_reply:
            report = final_reply
        elif not self.memory.history:
            report = self._generate_direct_reply(intent_paragraph)
        else:
            report = self._generate_report(intent_paragraph, execution_mode)
        self._push_event(
            event_callback,
            {
                "type": "report",
                "run_id": run_id,
                "execution_mode": execution_mode,
                "report": report,
            },
        )
        report_path = os.path.abspath(report_out_path) if report_out_path else os.path.join(run_dir, "report.md")
        saved_paths: List[str] = []
        try:
            with open(report_path, "w", encoding="utf-8") as handle:
                handle.write(report + "\n")
            saved_paths.append(os.path.abspath(report_path))
        except Exception as exc:
            if emit_console:
                print(f"error: failed to write report ({exc})")

        run_result_path_session = os.path.join(run_dir, "run_result.json")

        result = {
            "history": self.memory.history,
            "discovered_vulnerabilities": self.memory.discovered_vulns,
            "context_notes": self.memory.context_notes,
            "completed_deliverables": self.memory.completed_deliverables,
            "blocked_deliverables": self.memory.blocked_deliverables,
            "next_focus": self.memory.next_focus,
            "report": report,
            "stop_reason": stop_reason,
            "schema_version": SCHEMA_VERSION,
            "provider": self.provider,
            "execution_mode": execution_mode,
            "loop_mode": active_loop_mode,
            "targets": target_hints_list,
            "verbosity": self.policy.verbosity,
            "run_id": run_id,
            "report_path": os.path.abspath(report_path),
            "run_result_path": os.path.abspath(run_result_path_session),
        }

        try:
            with open(run_result_path_session, "w", encoding="utf-8") as handle:
                json.dump(result, handle, indent=2)
        except Exception as exc:
            if emit_console:
                print(f"error: failed to write session run_result ({exc})")

        if saved_paths and emit_console:
            print(f"saved: {saved_paths[0]}")
        self._push_event(
            event_callback,
            {
                "type": "completed",
                "run_id": run_id,
                "stop_reason": stop_reason,
                "result": result,
            },
        )
        return result


# ----------------------------------------------------------------------------
# CLI helpers
# ----------------------------------------------------------------------------


class CLIEventPrinter:
    def __init__(self) -> None:
        self.console = Console() if RICH_AVAILABLE else None
        self.sep = "─" * 80

    def _console_print(self, text: str) -> None:
        if self.console:
            self.console.print(text)
        else:
            print(text)

    def __call__(self, event: Dict[str, Any]) -> None:
        etype = event.get("type")
        if etype == "status":
            message = event.get("message", "")
            if message:
                self._console_print(f"[dim]{message}[/dim]" if self.console else _color(message, DIM))
        elif etype == "intent":
            return
        elif etype == "decision":
            command = event.get("command")
            if command:
                if self.console:
                    self.console.print(f"[yellow]> {command}[/yellow]")
                else:
                    print(_color(f"> {command}", Fore.YELLOW))
        elif etype == "output":
            line = (event.get("line") or "").strip()
            if line:
                if self.console:
                    self.console.print(f"[dim]{line}[/dim]")
                else:
                    print(_color(line, DIM))
        elif etype == "observation":
            obs = event.get("observation", {})
            rc = obs.get("returncode")
            if rc not in (None, 0):
                message = f"command failed (rc={rc})"
                if self.console:
                    self.console.print(f"[red]{message}[/red]")
                else:
                    print(_color(message, Fore.RED))
        elif etype == "report":
            report = event.get("report", "")
            if report:
                if self.console:
                    self.console.print("[green]Reply:[/green]")
                    self.console.print(report)
                else:
                    print(_color("Reply:", Fore.GREEN))
                    print(report)
        elif etype == "completed":
            return
        elif etype == "error":
            if self.console:
                self.console.print(f"[red]error:[/] {event.get('error', 'unknown error')}")
            else:
                print(_color(f"error: {event.get('error', 'unknown error')}", Fore.RED))


def print_banner() -> None:
    banner_lines = [
        "                     Uxarion CLI",
        "",
    ]
    builder_line = "Open-source AI pentesting copilot for authorized security testing."
    mission_line = "Uxarion is an AI pentesting copilot, open-source for the pentesting community."
    quick_actions_line = "Tip: run /addkey in chat to update API keys."
    website_line = "Official site: https://uxarion.com/"

    console = Console() if RICH_AVAILABLE else None

    if console:
        for line in banner_lines:
            console.print(line, style="cyan")
        console.print(builder_line, style="magenta")
        console.print()
        console.print(mission_line, style="cyan")
        console.print(website_line, style="cyan")
        console.print(quick_actions_line, style="cyan")
        console.print()
    else:
        for line in banner_lines:
            print(_color(line, getattr(Fore, "CYAN", "")))
        print(_color(builder_line, getattr(Fore, "MAGENTA", "")))
        print()
        print(_color(mission_line, getattr(Fore, "CYAN", "")))
        print(_color(website_line, getattr(Fore, "CYAN", "")))
        print(_color(quick_actions_line, getattr(Fore, "CYAN", "")))
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Uxarion AI Pentesting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uxarion --addKey
  uxarion --doctor
  uxarion --addKey sk-...
  uxarion --prompt "Scan http://localhost:8080 with nmap"
  uxarion --prompt "Enumerate directories on https://target.example"
        """,
    )
    parser.add_argument("--prompt", help="Pentesting objective or instructions")
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Run local environment checks and exit",
    )
    parser.add_argument(
        "--addKey",
        "--add-key",
        dest="add_key",
        nargs="?",
        const="",
        help="Set or replace OPENAI_API_KEY. Pass value directly or omit value for secure prompt.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing shells")
    parser.add_argument("--provider", choices=[DEFAULT_PROVIDER], default=DEFAULT_PROVIDER, help="AI backend")
    parser.add_argument(
        "--loop-mode",
        choices=sorted(LOOP_MODES),
        default=LOOP_MODE_DIRECT,
        help="Execution loop style (direct only: verbatim task passthrough with iterative AI actions).",
    )
    parser.add_argument("--max-commands", type=int, help="Stop after N executed commands")
    parser.add_argument(
        "--no-command-timeouts",
        action="store_true",
        help="Let tools run to completion (still subject to idle & wall-clock)",
    )
    parser.add_argument(
        "--idle-timeout",
        type=int,
        default=IDLE_TIMEOUT_S,
        help="Idle-output watchdog in seconds (0 disables)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Hide the ASCII banner",
    )
    parser.add_argument(
        "--jsonl",
        dest="jsonl_path",
        help="Append each observation as JSONL to the given file",
    )
    parser.add_argument(
        "--verbosity",
        choices=["quiet", "normal", "verbose"],
        default="normal",
        help="Output detail level",
    )
    parser.add_argument(
        "--scope",
        help="Comma-separated list of in-scope hosts (defaults to target host, localhost, 127.0.0.1)",
    )
    parser.add_argument(
        "--allow-tools",
        help="Comma-separated tools to add to the allow-list",
    )
    parser.add_argument(
        "--deny-tools",
        help="Comma-separated tools to explicitly deny",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip command validation (power users only)",
    )
    parser.add_argument(
        "--scope-cidr",
        help="Comma-separated CIDR ranges host IPs must stay within (e.g. 10.0.0.0/8,192.168.0.0/16)",
    )
    parser.add_argument(
        "--exit-on-first-finding",
        action="store_true",
        help="Stop immediately after the first confirmed finding",
    )
    parser.add_argument(
        "--out",
        help="Write final report to this path and JSON to <path>.run_result.json",
    )
    args = parser.parse_args()

    if args.add_key is not None:
        try:
            configured = set_openai_api_key(args.add_key or None)
            print(_color("✅ OpenAI API key saved:", Fore.GREEN) + f" {_mask_secret(configured)}")
            print("   Stored in .env and loaded into current session.")
        except ValueError as exc:
            print(_color(f"error: {exc}", Fore.RED))
            return 1
        except Exception as exc:
            print(_color(f"error: failed to update API key ({exc})", Fore.RED))
            return 1
        if not args.prompt:
            return 0

    if args.doctor:
        return run_doctor()

    if not args.prompt:
        parser.print_usage()
        print("error: --prompt is required unless using --addKey or --doctor")
        return 2

    idle_timeout = args.idle_timeout if args.idle_timeout is not None else IDLE_TIMEOUT_S
    if idle_timeout < 0:
        idle_timeout = 0

    policy = Policy(
        dry_run=args.dry_run,
        no_command_timeouts=args.no_command_timeouts,
        idle_timeout_s=idle_timeout,
        show_banner=not args.no_banner,
        jsonl_path=args.jsonl_path,
        verbosity=args.verbosity,
        loop_mode=args.loop_mode,
    )

    if policy.show_banner:
        print_banner()
    if policy.dry_run:
        print(_color("Dry-run mode: commands will not execute.", DIM))

    agent = Agent(policy=policy, provider=args.provider)
    scope_hosts = (
        {host.strip() for host in args.scope.split(",") if host.strip()}
        if args.scope
        else None
    )
    allow_tools = (
        {tool.strip() for tool in args.allow_tools.split(",") if tool.strip()}
        if args.allow_tools
        else None
    )
    deny_tools = (
        {tool.strip() for tool in args.deny_tools.split(",") if tool.strip()}
        if args.deny_tools
        else None
    )
    scope_cidrs = None
    if args.scope_cidr:
        cidr_values: List[ipaddress._BaseNetwork] = []
        for cidr in args.scope_cidr.split(","):
            cidr = cidr.strip()
            if not cidr:
                continue
            try:
                cidr_values.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                print(f"warning: ignoring invalid CIDR: {cidr}")
        if cidr_values:
            scope_cidrs = cidr_values

    report_out_path = args.out
    event_printer = CLIEventPrinter()
    try:
        agent.run(
            args.prompt,
            max_commands=args.max_commands,
            scope_hosts=scope_hosts,
            allow_tools=allow_tools,
            deny_tools=deny_tools,
            scope_cidrs=scope_cidrs,
            exit_on_first_finding=args.exit_on_first_finding,
            report_out_path=report_out_path,
            validate=not args.no_validate,
            loop_mode=args.loop_mode,
            event_callback=event_printer,
        )
    except Exception as exc:
        print(_color(f"error: {exc}", Fore.RED))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
