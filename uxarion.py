#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Unified entrypoint for Uxarion.

Usage:
  uxarion                             -> launch interactive chat UI
  uxarion "objective" [flags]         -> run single-shot agent and exit
  uxarion --prompt "obj" ...          -> run single-shot agent and exit
  uxarion --prompt "obj" --chat-after -> run then enter interactive chat UI
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List

from importlib.machinery import SourceFileLoader

from uxarion_cli.update_check import maybe_print_update_notice


def _load_agent_module():
    loader = SourceFileLoader("uxarion_cli_main", str(Path(__file__).resolve().parent / "uxarion_cli.py"))
    return loader.load_module()  # type: ignore[deprecated-attr]


_AGENT_MODULE = _load_agent_module()
run_agent_main = getattr(_AGENT_MODULE, "main")

from uxarion_cli.ui.chat_ui import ChatUI


def _run_agent(args: List[str]) -> int:
    # Insert --prompt if the user passed a bare objective.
    if args and not args[0].startswith("-") and not any(arg in {"--prompt", "-p"} for arg in args):
        args = ["--prompt", args[0], *args[1:]]
    sys.argv = ["uxarion", *args]
    try:
        return run_agent_main()
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        return 0 if code is None else 1
    except KeyboardInterrupt:
        print("\nSession interrupted by user.")
        return 130
    except Exception as exc:
        print(f"error: {exc}")
        return 1


def _launch_chat() -> int:
    ui = ChatUI()
    ui.run()
    return 0


def _parse_wrapper_args(args: List[str]) -> tuple[List[str], bool]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--chat-after", action="store_true")
    known, passthrough = parser.parse_known_args(args)
    return passthrough, bool(known.chat_after)


def _has_openai_key() -> bool:
    try:
        loader = getattr(_AGENT_MODULE, "load_api_keys", None)
        if callable(loader):
            keys = loader()
            if isinstance(keys, dict) and keys.get("openai"):
                return True
    except Exception:
        pass
    return bool(os.environ.get("OPENAI_API_KEY"))


def _should_skip_key_bootstrap(args: List[str]) -> bool:
    passthrough = set(args)
    if "-h" in passthrough or "--help" in passthrough:
        return True
    if "--doctor" in passthrough:
        return True
    return any(
        arg == "--addKey" or arg.startswith("--addKey=") or arg == "--add-key" or arg.startswith("--add-key=")
        for arg in args
    )


def _bootstrap_api_key_interactive(*, allow_skip: bool) -> bool:
    if _has_openai_key():
        return True

    if not sys.stdin.isatty():
        print("OPENAI_API_KEY is not configured.")
        print("Run `uxarion --addKey` (or set OPENAI_API_KEY) before starting a direct run.")
        return False

    print("No OpenAI API key found.")
    if allow_skip:
        answer = input("Set it now? [Y/n] ").strip().lower()
        if answer in {"n", "no"}:
            return False
    setter = getattr(_AGENT_MODULE, "set_openai_api_key", None)
    if not callable(setter):
        print("Key setup helper is unavailable. Run `uxarion --addKey`.")
        return False
    try:
        setter(None)
    except Exception as exc:
        print(f"Failed to configure API key: {exc}")
        return False
    print("OpenAI API key configured.")
    return True


def main() -> int:
    maybe_print_update_notice()
    passthrough_args, chat_after = _parse_wrapper_args(sys.argv[1:])

    # No non-wrapper args means interactive mode.
    if not passthrough_args:
        _bootstrap_api_key_interactive(allow_skip=True)
        return _launch_chat()

    show_help = any(arg in {"-h", "--help"} for arg in passthrough_args)
    if not _should_skip_key_bootstrap(passthrough_args):
        ready = _bootstrap_api_key_interactive(allow_skip=False)
        if not ready:
            return 1

    run_rc = _run_agent(passthrough_args)
    if show_help and run_rc == 0:
        print("\nWrapper options:")
        print("  --chat-after   Run direct task, then open interactive chat.")

    if chat_after:
        print("\nSwitching to interactive chat (`--chat-after`).")
        _launch_chat()
    return run_rc


if __name__ == "__main__":
    sys.exit(main())
