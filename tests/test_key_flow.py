# SPDX-License-Identifier: Apache-2.0
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import importlib.util


def _load_module(module_path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module


class KeyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        cls.root = root
        cls.agent_module = _load_module(root / "uxarion_cli.py", "uxarion_cli_keyflow")
        cls.wrapper_module = _load_module(root / "uxarion.py", "uxarion_wrapper_keyflow")

    def test_set_openai_api_key_updates_env_file_and_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            previous = os.environ.get("OPENAI_API_KEY")
            try:
                self.agent_module.openai_client = object()
                value = "sk-test-1234567890"
                returned = self.agent_module.set_openai_api_key(value)
                self.assertEqual(returned, value)
                self.assertEqual(os.environ.get("OPENAI_API_KEY"), value)
                self.assertIsNone(self.agent_module.openai_client)
                env_data = Path(".env").read_text(encoding="utf-8")
                self.assertIn(f"OPENAI_API_KEY={value}", env_data)
            finally:
                if previous is None:
                    os.environ.pop("OPENAI_API_KEY", None)
                else:
                    os.environ["OPENAI_API_KEY"] = previous
                os.chdir(cwd)

    def test_set_openai_api_key_non_tty_uses_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            previous = os.environ.get("OPENAI_API_KEY")
            try:
                with mock.patch("sys.stdin.isatty", return_value=False), mock.patch(
                    "builtins.input", return_value="sk-nontty-2222"
                ) as prompt:
                    returned = self.agent_module.set_openai_api_key(None)
                self.assertEqual(returned, "sk-nontty-2222")
                self.assertEqual(os.environ.get("OPENAI_API_KEY"), "sk-nontty-2222")
                prompt.assert_called_once()
            finally:
                if previous is None:
                    os.environ.pop("OPENAI_API_KEY", None)
                else:
                    os.environ["OPENAI_API_KEY"] = previous
                os.chdir(cwd)

    def test_load_api_keys_prefers_environment_over_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            previous = os.environ.get("OPENAI_API_KEY")
            try:
                Path(".env").write_text("OPENAI_API_KEY=sk-from-env-file\n", encoding="utf-8")
                os.environ["OPENAI_API_KEY"] = "sk-from-environment"
                keys = self.agent_module.load_api_keys()
                self.assertEqual(keys.get("openai"), "sk-from-environment")
            finally:
                if previous is None:
                    os.environ.pop("OPENAI_API_KEY", None)
                else:
                    os.environ["OPENAI_API_KEY"] = previous
                os.chdir(cwd)

    def test_main_addkey_mode_without_prompt(self) -> None:
        argv_backup = sys.argv[:]
        try:
            sys.argv = ["uxarion_cli.py", "--addKey", "sk-inline"]
            with mock.patch.object(self.agent_module, "set_openai_api_key", return_value="sk-inline") as setter:
                rc = self.agent_module.main()
            self.assertEqual(rc, 0)
            setter.assert_called_once_with("sk-inline")
        finally:
            sys.argv = argv_backup

    def test_main_requires_prompt_without_addkey(self) -> None:
        argv_backup = sys.argv[:]
        stdout = io.StringIO()
        try:
            sys.argv = ["uxarion_cli.py"]
            with mock.patch("sys.stdout", new=stdout):
                rc = self.agent_module.main()
            self.assertEqual(rc, 2)
            self.assertIn("--prompt is required unless using --addKey", stdout.getvalue())
        finally:
            sys.argv = argv_backup

    def test_main_doctor_mode_without_prompt(self) -> None:
        argv_backup = sys.argv[:]
        try:
            sys.argv = ["uxarion_cli.py", "--doctor"]
            with mock.patch.object(self.agent_module, "run_doctor", return_value=0) as doctor:
                rc = self.agent_module.main()
            self.assertEqual(rc, 0)
            doctor.assert_called_once()
        finally:
            sys.argv = argv_backup

    def test_main_handles_agent_runtime_error_without_traceback(self) -> None:
        argv_backup = sys.argv[:]
        stdout = io.StringIO()
        try:
            sys.argv = ["uxarion_cli.py", "--prompt", "hello"]
            fake_agent = mock.Mock()
            fake_agent.run.side_effect = RuntimeError("boom")
            with mock.patch.object(self.agent_module, "Agent", return_value=fake_agent), mock.patch(
                "sys.stdout", new=stdout
            ):
                rc = self.agent_module.main()
            self.assertEqual(rc, 1)
            out = stdout.getvalue()
            self.assertIn("error: boom", out)
            self.assertNotIn("Traceback", out)
        finally:
            sys.argv = argv_backup

    def test_wrapper_preserves_addkey_flag_without_prompt_injection(self) -> None:
        argv_backup = sys.argv[:]
        captured = {"argv": None}

        def fake_run_agent_main():
            captured["argv"] = sys.argv[:]
            return 0

        try:
            with mock.patch.object(self.wrapper_module, "run_agent_main", side_effect=fake_run_agent_main):
                rc = self.wrapper_module._run_agent(["--addKey", "sk-wrapper"])
            self.assertEqual(rc, 0)
            self.assertEqual(captured["argv"], ["uxarion", "--addKey", "sk-wrapper"])
        finally:
            sys.argv = argv_backup

    def test_wrapper_direct_run_aborts_when_key_not_configured(self) -> None:
        argv_backup = sys.argv[:]
        try:
            sys.argv = ["uxarion", "--prompt", "quick check"]
            with mock.patch.object(self.wrapper_module, "_should_skip_key_bootstrap", return_value=False), mock.patch.object(
                self.wrapper_module, "_bootstrap_api_key_interactive", return_value=False
            ) as bootstrap, mock.patch.object(self.wrapper_module, "run_agent_main") as run_agent:
                rc = self.wrapper_module.main()
            self.assertEqual(rc, 1)
            bootstrap.assert_called_once_with(allow_skip=False)
            run_agent.assert_not_called()
        finally:
            sys.argv = argv_backup

    def test_wrapper_direct_run_continues_after_key_bootstrap(self) -> None:
        argv_backup = sys.argv[:]
        captured = {"argv": None}

        def fake_run_agent_main():
            captured["argv"] = sys.argv[:]
            return 0

        try:
            sys.argv = ["uxarion", "--prompt", "quick check"]
            with mock.patch.object(self.wrapper_module, "_should_skip_key_bootstrap", return_value=False), mock.patch.object(
                self.wrapper_module, "_bootstrap_api_key_interactive", return_value=True
            ) as bootstrap, mock.patch.object(
                self.wrapper_module, "run_agent_main", side_effect=fake_run_agent_main
            ):
                rc = self.wrapper_module.main()
            self.assertEqual(rc, 0)
            bootstrap.assert_called_once_with(allow_skip=False)
            self.assertEqual(captured["argv"], ["uxarion", "--prompt", "quick check"])
        finally:
            sys.argv = argv_backup

    def test_wrapper_no_args_opens_chat(self) -> None:
        argv_backup = sys.argv[:]
        chat_instance = mock.Mock()
        try:
            sys.argv = ["uxarion"]
            with mock.patch.object(self.wrapper_module, "ChatUI", return_value=chat_instance), mock.patch.object(
                self.wrapper_module, "run_agent_main"
            ) as run_agent:
                rc = self.wrapper_module.main()
            self.assertEqual(rc, 0)
            chat_instance.run.assert_called_once()
            run_agent.assert_not_called()
        finally:
            sys.argv = argv_backup

    def test_wrapper_chat_after_runs_agent_then_chat(self) -> None:
        argv_backup = sys.argv[:]
        captured = {"argv": None}
        chat_instance = mock.Mock()

        def fake_run_agent_main():
            captured["argv"] = sys.argv[:]
            return 7

        try:
            sys.argv = ["uxarion", "--prompt", "quick check", "--chat-after"]
            with mock.patch.object(self.wrapper_module, "run_agent_main", side_effect=fake_run_agent_main), mock.patch.object(
                self.wrapper_module, "ChatUI", return_value=chat_instance
            ):
                rc = self.wrapper_module.main()
            self.assertEqual(rc, 7)
            self.assertEqual(captured["argv"], ["uxarion", "--prompt", "quick check"])
            chat_instance.run.assert_called_once()
        finally:
            sys.argv = argv_backup

    def test_wrapper_help_shows_chat_after_note(self) -> None:
        argv_backup = sys.argv[:]
        out = io.StringIO()

        try:
            sys.argv = ["uxarion", "--help"]
            with mock.patch.object(self.wrapper_module, "run_agent_main", return_value=0), mock.patch(
                "sys.stdout", new=out
            ):
                rc = self.wrapper_module.main()
            self.assertEqual(rc, 0)
            self.assertIn("Wrapper options:", out.getvalue())
            self.assertIn("--chat-after", out.getvalue())
        finally:
            sys.argv = argv_backup

    def test_chat_addkey_command_uses_inline_value(self) -> None:
        from uxarion_cli.ui.chat_ui import ChatUI

        ui = ChatUI()
        with mock.patch.object(ui, "_apply_api_key") as apply_key, mock.patch.object(ui, "_prompt_for_key") as ask_key:
            ui._handle_command("/addkey sk-inline")
        apply_key.assert_called_once_with("OPENAI_API_KEY", "OpenAI", "sk-inline")
        ask_key.assert_not_called()

    def test_chat_addkey_command_masks_context_and_prompts(self) -> None:
        from uxarion_cli.ui.chat_ui import ChatUI

        ui = ChatUI()
        with mock.patch.object(ui, "_prompt_for_key", return_value="sk-typed"), mock.patch.object(
            ui, "_apply_api_key"
        ) as apply_key:
            ui._process_user_input("/addkey")
        apply_key.assert_called_once_with("OPENAI_API_KEY", "OpenAI", "sk-typed")
        self.assertTrue(ui.context.messages)
        self.assertEqual(ui.context.messages[-1]["content"], "/addkey [hidden]")

    def test_chat_prompt_template_is_minimal(self) -> None:
        from uxarion_cli.ui.chat_ui import ChatUI

        ui = ChatUI()
        self.assertEqual(ui.prompt_template, "> ")

    def test_chat_hides_status_intent_and_completed_events(self) -> None:
        from uxarion_cli.ui.chat_ui import ChatUI

        ui = ChatUI()
        for event in (
            {"type": "status", "message": "Starting autonomous session"},
            {"type": "intent", "intent": "hello"},
            {"type": "completed", "stop_reason": "done"},
        ):
            formatted, report = ui._format_event_for_display(event)
            self.assertIsNone(formatted)
            self.assertIsNone(report)

    def test_chat_report_event_returns_reply_payload_without_banner_line(self) -> None:
        from uxarion_cli.ui.chat_ui import ChatUI

        ui = ChatUI()
        formatted, report = ui._format_event_for_display({"type": "report", "report": "hello"})
        self.assertIsNone(formatted)
        self.assertEqual(report, "hello")

    def test_chat_context_stores_compact_command_summary_only(self) -> None:
        from uxarion_cli.ui.chat_ui import ConversationContext

        ctx = ConversationContext()
        ctx.add_command_execution(
            "curl -i http://localhost:5002",
            0,
            step_summary="HTTP 200 with server header",
            evidence=["HTTP/1.1 200 OK", "Server: uvicorn"],
        )
        payload = ctx.as_agent_context()
        self.assertTrue(payload["carry_over_notes"])
        self.assertIn("curl -i http://localhost:5002", payload["carry_over_notes"][0])
        self.assertIn("HTTP/1.1 200 OK", payload["carry_over_findings"])
        self.assertNotIn("Output:", payload["carry_over_notes"][0])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
