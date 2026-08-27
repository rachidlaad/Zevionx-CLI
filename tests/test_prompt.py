# SPDX-License-Identifier: Apache-2.0
import io
import os
import tempfile
import unittest
from unittest import mock

import importlib.util
import sys
from pathlib import Path


def _load_cli_module():
    root = Path(__file__).resolve().parents[1]
    module_path = root / "uxarion_cli.py"
    spec = importlib.util.spec_from_file_location("uxarion_cli_cli", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module


uxarion_cli = _load_cli_module()


FORBIDDEN_TERMS = ("verbosity", "internal telemetry")
REQUIRED_CONTEXT_SECTIONS = (
    "Context_memory",
    "Conversation_turn_context",
    "Deliverables_state",
    "Recent_step_briefs",
    "Last_command_result",
    "Last_command_output",
    "Terminal_capabilities",
    "Timeout_seconds",
)


class DecisionPromptTests(unittest.TestCase):
    def test_decision_prompt_excludes_internal_terms(self) -> None:
        prompt_lower = uxarion_cli.DIRECT_EXECUTION_PROMPT.lower()
        for term in FORBIDDEN_TERMS:
            self.assertNotIn(term, prompt_lower)
        for section in REQUIRED_CONTEXT_SECTIONS:
            self.assertIn(section, uxarion_cli.DIRECT_EXECUTION_PROMPT)


class PlannerRuntimeTests(unittest.TestCase):
    def test_request_decision_payload_clean(self) -> None:
        policy = uxarion_cli.Policy()
        agent = uxarion_cli.Agent(policy=policy, provider="openai")

        captured = {}

        def fake_chat_json(prompt: str, payload: dict, provider: str, **kwargs):
            captured["prompt"] = prompt
            captured["payload"] = payload
            captured["provider"] = provider
            return {"stop": True, "reason": "noop"}

        with mock.patch.object(uxarion_cli, "chat_json", side_effect=fake_chat_json):
            agent._request_decision_direct("scan http://example.com")

        self.assertEqual(captured["payload"], {})
        prompt_lower = captured["prompt"].lower()
        for term in FORBIDDEN_TERMS:
            self.assertNotIn(term, prompt_lower)
        for section in REQUIRED_CONTEXT_SECTIONS:
            self.assertIn(section, captured["prompt"])

    def test_request_decision_includes_conversation_turn_context(self) -> None:
        policy = uxarion_cli.Policy()
        agent = uxarion_cli.Agent(policy=policy, provider="openai")
        captured = {}

        def fake_chat_json(prompt: str, payload: dict, provider: str, **kwargs):
            captured["prompt"] = prompt
            return {"stop": True, "reason": "done"}

        turn_context = {
            "session_goal": "Web recon on localhost",
            "recent_user_tasks": ["enumerate paths"],
            "carry_over_notes": ["/robots.txt returned 200"],
            "pending_items": ["check auth flow"],
            "last_known_target": "localhost",
        }

        with mock.patch.object(uxarion_cli, "chat_json", side_effect=fake_chat_json):
            agent._request_decision_direct("continue with auth checks", conversation_context=turn_context)

        prompt = captured["prompt"]
        self.assertIn("Conversation_turn_context", prompt)
        self.assertIn("session_goal: Web recon on localhost", prompt)
        self.assertIn("pending: check auth flow", prompt)

    def test_run_uses_context_memory(self) -> None:
        policy = uxarion_cli.Policy(dry_run=True)
        agent = uxarion_cli.Agent(policy=policy, provider="openai")

        user_text = "Run safe recon on http://localhost:8080 and provide key findings."

        decisions = [
            {
                "stop": False,
                "reason": "collect baseline headers",
                "command": "curl -i http://localhost:8080",
            },
            {
                "stop": False,
                "reason": "collect DNS signal",
                "command": "dig +short localhost",
            },
            {
                "stop": True,
                "reason": "done",
                "final_reply": "Task completed with safe recon outputs.",
            },
        ]
        summaries = [
            {
                "step_summary": "HTTP headers captured from localhost target.",
                "valuable_observations": ["HTTP probe executed on localhost:8080."],
                "completed_deliverables": ["Baseline header check completed."],
                "blocked_deliverables": [],
                "next_focus": ["Gather DNS-level confirmation."],
            },
            {
                "step_summary": "DNS lookup completed for localhost.",
                "valuable_observations": ["localhost resolved successfully."],
                "completed_deliverables": ["DNS confirmation completed."],
                "blocked_deliverables": [],
                "next_focus": [],
            },
        ]
        decision_prompts = []

        def fake_chat_json(prompt: str, payload: dict, provider: str, **kwargs):
            if "compress one command result into high-value memory" in prompt.lower():
                return summaries.pop(0)
            decision_prompts.append((prompt, payload))
            return decisions.pop(0)

        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                with mock.patch.object(uxarion_cli, "chat_json", side_effect=fake_chat_json), mock.patch.object(
                    uxarion_cli, "chat_text", return_value="Test report"
                ):
                    result = agent.run(user_text, max_commands=3)
            finally:
                os.chdir(cwd)

        self.assertEqual(result.get("loop_mode"), "direct")
        self.assertEqual(len(decision_prompts), 3)
        decision_prompt, payload = decision_prompts[0]
        self.assertEqual(payload, {})
        self.assertIn("User_task_verbatim:\n" + user_text.strip(), decision_prompt)
        self.assertIn("Context_memory", decision_prompt)
        self.assertIn("Deliverables_state", decision_prompt)
        self.assertIn("Recent_step_briefs", decision_prompt)
        self.assertIn("Last_command_result", decision_prompt)
        self.assertIn("Last_command_output", decision_prompt)
        prompt_lower = decision_prompt.lower()
        for term in FORBIDDEN_TERMS:
            self.assertNotIn(term, prompt_lower)

        second_prompt, _ = decision_prompts[1]
        self.assertIn("HTTP headers captured from localhost target.", second_prompt)
        self.assertIn("Baseline header check completed.", second_prompt)

        third_prompt, _ = decision_prompts[2]
        self.assertIn("DNS lookup completed for localhost.", third_prompt)
        self.assertNotIn("[DRY-RUN] Would execute: curl -i http://localhost:8080", third_prompt)

    def test_direct_loop_uses_raw_task_and_model_final_reply(self) -> None:
        policy = uxarion_cli.Policy(dry_run=True, loop_mode="direct")
        agent = uxarion_cli.Agent(policy=policy, provider="openai")

        user_text = "Run recon on http://localhost:8080 and stop when task is fully done."

        decisions = [
            {
                "stop": False,
                "reason": "collect baseline headers",
                "command": "curl -i http://localhost:8080",
            },
            {
                "stop": True,
                "reason": "task complete",
                "final_reply": "Task completed with baseline reconnaissance results.",
            },
        ]
        captured_prompts = []

        def fake_chat_json(prompt: str, payload: dict, provider: str, **kwargs):
            if "compress one command result into high-value memory" in prompt.lower():
                return {
                    "step_summary": "Baseline headers captured.",
                    "valuable_observations": ["HTTP probe completed."],
                    "completed_deliverables": ["Header baseline done."],
                    "blocked_deliverables": [],
                    "next_focus": [],
                }
            captured_prompts.append((prompt, payload))
            return decisions.pop(0)

        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                with mock.patch.object(uxarion_cli, "chat_json", side_effect=fake_chat_json), mock.patch.object(
                    uxarion_cli, "chat_text", return_value="Fallback report"
                ):
                    result = agent.run(user_text, max_commands=2, validate=True)
            finally:
                os.chdir(cwd)

        self.assertEqual(len(captured_prompts), 2)
        first_prompt, first_payload = captured_prompts[0]
        self.assertEqual(first_payload, {})
        self.assertIn("User_task_verbatim:\n" + user_text, first_prompt)
        self.assertIn("Context_memory", first_prompt)
        self.assertIn("Deliverables_state", first_prompt)
        self.assertIn("Recent_step_briefs", first_prompt)
        self.assertIn("Last_command_result", first_prompt)
        self.assertIn("Last_command_output", first_prompt)
        self.assertIn("Terminal_capabilities", first_prompt)
        self.assertIn("Timeout_seconds", first_prompt)
        self.assertEqual(result.get("loop_mode"), "direct")
        self.assertEqual(result.get("report"), "Task completed with baseline reconnaissance results.")
        self.assertGreaterEqual(len(result.get("history", [])), 1)
        first_validator = result["history"][0].get("validator", {})
        self.assertEqual(first_validator.get("reason"), "prompt-governed direct mode")

    def test_duplicate_commands_are_not_blocked(self) -> None:
        policy = uxarion_cli.Policy(dry_run=True)
        agent = uxarion_cli.Agent(policy=policy, provider="openai")

        decisions = [
            {"stop": False, "reason": "do A", "command": "curl -i http://x"},
            {"stop": False, "reason": "repeat", "command": "curl -i http://x"},
            {"stop": True, "reason": "done", "final_reply": "done"},
        ]

        def fake_chat_json(prompt: str, payload: dict, provider: str, **kwargs):
            if "compress one command result into high-value memory" in prompt.lower():
                return {
                    "step_summary": "probe executed",
                    "valuable_observations": ["probe completed"],
                    "completed_deliverables": [],
                    "blocked_deliverables": [],
                    "next_focus": [],
                }
            return decisions.pop(0)

        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                with mock.patch.object(uxarion_cli, "chat_json", side_effect=fake_chat_json), mock.patch.object(
                    uxarion_cli, "chat_text", return_value="Test report"
                ):
                    buf = io.StringIO()
                    original_stdout = sys.stdout
                    sys.stdout = buf
                    try:
                        result = agent.run("scan http://x", max_commands=3)
                    finally:
                        sys.stdout = original_stdout
                    output_text = buf.getvalue()
            finally:
                os.chdir(cwd)

        history = result.get("history", [])
        commands = [item.get("observation", {}).get("command") for item in history]
        self.assertEqual(commands.count("curl -i http://x"), 2)
        self.assertNotIn("thinking: trying alternative (duplicate)", output_text)

    def test_direct_question_without_commands_uses_direct_reply_fallback(self) -> None:
        policy = uxarion_cli.Policy(dry_run=True)
        agent = uxarion_cli.Agent(policy=policy, provider="openai")

        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                with mock.patch.object(
                    uxarion_cli,
                    "chat_json",
                    return_value={"stop": True, "reason": "plain question answered"},
                ), mock.patch.object(
                    uxarion_cli,
                    "chat_text",
                    return_value="Hello. How can I help you today?",
                ) as chat_text_mock:
                    result = agent.run("hi", max_commands=3)
            finally:
                os.chdir(cwd)

        self.assertEqual(result.get("history"), [])
        self.assertEqual(result.get("report"), "Hello. How can I help you today?")
        self.assertTrue(chat_text_mock.called)
        called_prompt = chat_text_mock.call_args[0][0]
        self.assertIn("Respond directly to the user's message", called_prompt)


class ExecutionUtilityTests(unittest.TestCase):
    def test_should_prefix_stdbuf_skips_compound_shell(self) -> None:
        self.assertTrue(
            uxarion_cli._should_prefix_stdbuf(
                "curl -sS -I https://example.com",
                "curl",
                has_stdbuf=True,
            )
        )
        self.assertFalse(
            uxarion_cli._should_prefix_stdbuf(
                "for i in 1 2; do echo $i; done",
                "for",
                has_stdbuf=True,
            )
        )
        self.assertFalse(
            uxarion_cli._should_prefix_stdbuf(
                "(echo hi); echo there",
                "(",
                has_stdbuf=True,
            )
        )

    def test_stream_output_is_bounded(self) -> None:
        result = uxarion_cli.stream_command_execution(
            "yes A | head -n 1300",
            timeout=10,
            idle_timeout=5,
            emit_console=False,
        )
        self.assertEqual(result["returncode"], 0)
        lines = result["output"].splitlines()
        self.assertLessEqual(len(lines), uxarion_cli.MAX_STREAM_CAPTURE_LINES + 1)
        self.assertIn(
            f"... (output truncated after {uxarion_cli.MAX_STREAM_CAPTURE_LINES} lines) ...",
            result["output"],
        )

    def test_stream_handles_non_utf8_output(self) -> None:
        result = uxarion_cli.stream_command_execution(
            "printf '\\xff\\xfe\\xfd\\n'",
            timeout=5,
            idle_timeout=3,
            emit_console=False,
        )
        self.assertEqual(result["returncode"], 0)
        self.assertIn("\ufffd", result["output"])

    def test_deliverables_match_with_variant_phrasing(self) -> None:
        self.assertTrue(
            uxarion_cli._deliverables_match(
                "DNS records for lovable.dev",
                "DNS records (A/AAAA/TXT/CAA) gathered for lovable.dev",
            )
        )
        self.assertTrue(
            uxarion_cli._deliverables_match(
                "TLS certificate basics (retry leaf cert extraction/parsing)",
                "TLS details: leaf cert subject/issuer/dates/SAN/fingerprint for lovable.dev:443.",
            )
        )
        self.assertTrue(
            uxarion_cli._deliverables_match(
                "HTTP status and title for https://lovable.dev/discover",
                "HTTP status and title for /robots.txt, /sitemap.xml, /discover, /auth",
            )
        )
        self.assertFalse(
            uxarion_cli._deliverables_match(
                "TLS certificate basics",
                "robots.txt fetch completed",
            )
        )

    def test_next_focus_pruned_by_completed_deliverables(self) -> None:
        policy = uxarion_cli.Policy(dry_run=True)
        agent = uxarion_cli.Agent(policy=policy, provider="openai")

        agent._apply_step_context(
            {
                "step_summary": "Initial planning",
                "valuable_observations": [],
                "completed_deliverables": [],
                "blocked_deliverables": [],
                "next_focus": [
                    "DNS records for lovable.dev",
                    "TLS certificate basics for lovable.dev",
                ],
            }
        )
        agent._apply_step_context(
            {
                "step_summary": "DNS done",
                "valuable_observations": [],
                "completed_deliverables": ["DNS records (A/AAAA/TXT/CAA) gathered for lovable.dev"],
                "blocked_deliverables": [],
                "next_focus": ["HTTP headers for GET / on lovable.dev"],
            }
        )

        self.assertNotIn("DNS records for lovable.dev", agent.memory.next_focus)
        self.assertIn("TLS certificate basics for lovable.dev", agent.memory.next_focus)
        self.assertIn("HTTP headers for GET / on lovable.dev", agent.memory.next_focus)

        agent._apply_step_context(
            {
                "step_summary": "path checks done",
                "valuable_observations": [],
                "completed_deliverables": ["HTTP status and title for /robots.txt, /sitemap.xml, /discover, /auth"],
                "blocked_deliverables": [],
                "next_focus": [
                    "HTTP status and title for https://lovable.dev/discover",
                    "HTTP status and title for https://lovable.dev/auth",
                ],
            }
        )
        self.assertNotIn("HTTP status and title for https://lovable.dev/discover", agent.memory.next_focus)
        self.assertNotIn("HTTP status and title for https://lovable.dev/auth", agent.memory.next_focus)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
