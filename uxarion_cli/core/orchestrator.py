# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import importlib.util
import sys
import uuid
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Optional, Set

_AGENT_MODULE = None


def _load_agent_module():
    global _AGENT_MODULE
    if _AGENT_MODULE is not None:
        return _AGENT_MODULE
    script_path = Path(__file__).resolve().parents[2] / "uxarion_cli.py"
    module_name = "uxarion_cli_runtime"
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load agent entrypoint from {script_path}")
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise RuntimeError(f"Agent loader not available for {script_path}")
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    _AGENT_MODULE = module
    return module


class AutonomousOrchestrator:
    """Coordinates Agent runs and streams structured events to consumers."""

    def __init__(
        self,
        model_provider: Optional[str] = None,
        approval_mode: Optional[str] = None,
    ) -> None:
        module = _load_agent_module()
        self._policy_cls = getattr(module, "Policy")
        self._agent_cls = getattr(module, "Agent")
        default_provider = getattr(module, "DEFAULT_PROVIDER", "openai")
        requested_provider = (model_provider or default_provider).strip().lower()
        if requested_provider != default_provider:
            raise ValueError(f"Unsupported provider '{model_provider}'. Only '{default_provider}' is available.")
        self.provider = default_provider
        self.session_id: Optional[str] = None
        self.objective: Optional[str] = None
        self.scope: Set[str] = set()
        self.allow_tools: Optional[Set[str]] = None
        self.deny_tools: Optional[Set[str]] = None
        self.conversation_context: Optional[Dict[str, Any]] = None
        self.loop_mode: str = "direct"
        self._agent = None
        self._stop_requested = False

    def switch_provider(self, provider_name: str) -> bool:
        normalized = (provider_name or "").strip().lower()
        if not normalized:
            return False
        if normalized != self.provider:
            raise ValueError(f"Unsupported provider '{provider_name}'. Only '{self.provider}' is available.")
        return True

    def get_provider_info(self) -> Dict[str, Any]:
        return {"provider": self.provider}

    def create_session(
        self,
        objective: str,
        target: Optional[str],
        *,
        allow_tools: Optional[Set[str]] = None,
        deny_tools: Optional[Set[str]] = None,
        scope_hosts: Optional[Set[str]] = None,
        conversation_context: Optional[Dict[str, Any]] = None,
        loop_mode: Optional[str] = None,
    ) -> str:
        self.session_id = uuid.uuid4().hex
        self.objective = objective
        self.scope = set(scope_hosts or set())
        if target:
            self.scope.add(target)
        self.allow_tools = set(allow_tools) if allow_tools else None
        self.deny_tools = set(deny_tools) if deny_tools else None
        self.conversation_context = dict(conversation_context) if conversation_context else None
        normalizer = getattr(_load_agent_module(), "normalize_loop_mode", None)
        if callable(normalizer):
            self.loop_mode = normalizer(loop_mode, default="direct")
        else:
            self.loop_mode = (loop_mode or "direct").strip().lower()
        policy = self._policy_cls(show_banner=False)
        self._agent = self._agent_cls(policy=policy, provider=self.provider)
        return self.session_id

    async def start_autonomous_loop(self) -> AsyncGenerator[Dict[str, Any], None]:
        if not self.objective or self._agent is None or not self.session_id:
            raise RuntimeError("No session active; call create_session first.")

        queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        loop = asyncio.get_running_loop()

        def callback(event: Dict[str, Any]) -> None:
            loop.call_soon_threadsafe(queue.put_nowait, event)

        kwargs = self._build_run_kwargs()

        def worker():
            try:
                self._agent.run(self.objective, event_callback=callback, **kwargs)
            except Exception as exc:
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {"type": "error", "error": str(exc), "session_id": self.session_id},
                )
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, {"type": "__done__"})

        yield {
            "type": "status",
            "message": f"Starting autonomous session for: {self.objective}",
            "session_id": self.session_id,
        }

        worker_future = loop.run_in_executor(None, worker)
        try:
            while True:
                event = await queue.get()
                if event.get("type") == "__done__":
                    break
                event.setdefault("session_id", self.session_id)
                yield event
        finally:
            await worker_future

    def stop(self) -> None:
        self._stop_requested = True

    def _build_run_kwargs(self) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {}
        if self.scope:
            kwargs["scope_hosts"] = set(self.scope)
        if self.allow_tools:
            kwargs["allow_tools"] = set(self.allow_tools)
        if self.deny_tools:
            kwargs["deny_tools"] = set(self.deny_tools)
        if self.conversation_context:
            kwargs["conversation_context"] = dict(self.conversation_context)
        kwargs["loop_mode"] = self.loop_mode
        return kwargs


_orch_singleton: Optional[AutonomousOrchestrator] = None


def init_orchestrator(provider: Optional[str] = None, approval_mode: Optional[str] = None) -> AutonomousOrchestrator:
    global _orch_singleton
    if provider and provider.strip().lower() != "openai":
        raise ValueError(f"Unsupported provider '{provider}'. Only 'openai' is available.")
    if _orch_singleton is None:
        _orch_singleton = AutonomousOrchestrator(model_provider=provider, approval_mode=approval_mode)
    return _orch_singleton


def get_orchestrator() -> AutonomousOrchestrator:
    return _orch_singleton or init_orchestrator()
