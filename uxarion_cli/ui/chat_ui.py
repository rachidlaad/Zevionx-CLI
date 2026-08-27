# SPDX-License-Identifier: Apache-2.0
"""
Interactive terminal chat UI for Uxarion
Enhanced with code execution, conversation context, and streaming responses.
"""
import asyncio
import sys
import os
import subprocess
import json
import time
import re
from datetime import datetime
from importlib import metadata
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import getpass

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt
    from rich.syntax import Syntax
    from rich.live import Live
    from rich.markdown import Markdown
    from rich import box
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

PROMPT_TOOLKIT_AVAILABLE = False

from ..core.orchestrator import init_orchestrator

try:  # Stay aligned with single-shot OpenAI default
    loader = SourceFileLoader(
        "uxarion_cli_module",
        str(Path(__file__).resolve().parents[2] / "uxarion_cli.py"),
    )
    legacy_agent = loader.load_module()  # type: ignore[deprecated-attr]
    CHAT_DEFAULT_PROVIDER = getattr(legacy_agent, "DEFAULT_PROVIDER", "openai")
except Exception:  # pragma: no cover - defensive
    CHAT_DEFAULT_PROVIDER = os.getenv("DEFAULT_PROVIDER", "openai")


class ConversationContext:
    """Maintains conversation history and context"""

    def __init__(self):
        self.messages: List[Dict[str, Any]] = []
        self.session_start = datetime.now()
        self.command_history: List[str] = []
        self.session_goal: str = ""
        self.recent_user_tasks: List[str] = []
        self.recent_agent_replies: List[str] = []
        self.carry_over_notes: List[str] = []
        self.carry_over_findings: List[str] = []
        self.pending_items: List[str] = []
        self.last_known_target: str = ""

    @staticmethod
    def _append_unique(target: List[str], values: List[str], *, limit: int) -> None:
        for value in values:
            compact = " ".join((value or "").split()).strip()
            if not compact:
                continue
            if any(existing.lower() == compact.lower() for existing in target):
                continue
            target.append(compact[:220])
        if len(target) > limit:
            del target[:-limit]

    def add_user_message(self, content: str):
        """Add user message to context"""
        self.messages.append({
            "role": "user",
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
        self._append_unique(self.recent_user_tasks, [content], limit=8)
        if not self.session_goal:
            self.session_goal = content

    def add_assistant_message(self, content: str):
        """Add assistant response to context"""
        self.messages.append({
            "role": "assistant",
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
        self._append_unique(self.recent_agent_replies, [content], limit=6)

    def add_command_execution(
        self,
        command: str,
        returncode: int,
        *,
        step_summary: str = "",
        evidence: Optional[List[str]] = None,
    ):
        """Add command execution summary to context (no raw output retention)."""
        self.command_history.append(command)
        note = f"{command} (rc={returncode})"
        if step_summary:
            note = f"{note}: {step_summary}"
        self._append_unique(self.carry_over_notes, [note], limit=24)
        self._append_unique(self.carry_over_findings, list(evidence or []), limit=20)
        self.messages.append({
            "role": "system",
            "content": note,
            "timestamp": datetime.now().isoformat(),
            "type": "command_execution"
        })

    def apply_run_result(self, objective: str, reply: str, result: Optional[Dict[str, Any]]) -> None:
        if objective:
            self._append_unique(self.recent_user_tasks, [objective], limit=8)
            if not self.session_goal:
                self.session_goal = objective
        if reply:
            self._append_unique(self.recent_agent_replies, [reply], limit=6)
        if not isinstance(result, dict):
            return

        completed = [str(item) for item in result.get("completed_deliverables", []) if isinstance(item, str)]
        blocked = [str(item) for item in result.get("blocked_deliverables", []) if isinstance(item, str)]
        next_focus = [str(item) for item in result.get("next_focus", []) if isinstance(item, str)]
        notes = [str(item) for item in result.get("context_notes", []) if isinstance(item, str)]

        self._append_unique(self.carry_over_notes, notes[-10:], limit=24)
        self._append_unique(self.carry_over_findings, completed[-8:] + blocked[-6:], limit=20)
        self.pending_items = next_focus[-12:]

    def as_agent_context(self) -> Dict[str, Any]:
        return {
            "session_goal": self.session_goal,
            "recent_user_tasks": self.recent_user_tasks[-6:],
            "recent_agent_replies": self.recent_agent_replies[-4:],
            "carry_over_notes": self.carry_over_notes[-16:],
            "carry_over_findings": self.carry_over_findings[-12:],
            "pending_items": self.pending_items[-12:],
            "last_known_target": self.last_known_target,
        }

    def get_recent_context(self, max_messages: int = 10) -> List[Dict[str, Any]]:
        """Get recent conversation context"""
        return self.messages[-max_messages:] if self.messages else []


class ChatUI:
    """Interactive terminal chat interface"""

    def __init__(self):
        if not RICH_AVAILABLE:
            print("Error: Rich library required. Run: pip install rich")
            sys.exit(1)

        self.console = Console()
        self.context = ConversationContext()
        self.current_directory = os.getcwd()
        self.version, self.build_label = self._resolve_build_metadata()

        # Settings
        # Default to no target so scope isn’t unintentionally restricted
        self.target = ""
        self.objective = "Security assessment"
        self.provider = "openai"
        self.enable_advanced = False
        self.prompt_template = "> "

    def _resolve_build_metadata(self) -> tuple[str, str]:
        """Return package version and build identifier."""
        version = "dev"
        for dist_name in ("uxarion", "uxarion-cli"):
            try:
                version = metadata.version(dist_name)
                break
            except metadata.PackageNotFoundError:
                continue
        build = (
            os.environ.get("UXARION_BUILD_ID")
            or os.environ.get("POWN_BUILD_ID")
            or os.environ.get("GIT_COMMIT")
            or os.environ.get("BUILD_ID")
            or "local"
        )
        return version, build

    def run(self):
        """Main interactive loop"""
        self._show_welcome()

        try:
            while True:
                user_input = self._get_user_input()

                if user_input.lower() in ["quit", "exit", "/quit"]:
                    self._show_goodbye()
                    break

                self._process_user_input(user_input)

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Session interrupted. Goodbye![/]")

    def _show_welcome(self):
        """Render the primary header with branding and mission info."""
        banner = Text("                         Uxarion CLI\n", style="bold cyan")

        mission = Text(
            "Uxarion is an AI pentesting copilot, open-source for the pentesting community.",
            style="bright_cyan",
        )
        quick_tip = Text(
            "Tip: press '/' or run /addkey to update API keys quickly.",
            style="bright_cyan",
        )
        website = Text(
            "Official site: https://uxarion.com/",
            style="bright_cyan",
        )

        self.console.print(banner)
        self.console.print(mission)
        self.console.print(website)
        self.console.print(quick_tip)
        self.console.print()

    def _get_user_input(self) -> str:
        """Get user input with the chat-style prompt"""
        try:
            return self.console.input(f"\n{self.prompt_template}").strip()
        except EOFError:
            return "quit"

    def _process_user_input(self, user_input: str):
        """Process user input and generate responses"""
        if user_input == "/":
            self._open_quick_actions_menu()
            return

        if user_input.lower().startswith("/addkey"):
            self.context.add_user_message("/addkey [hidden]")
            self._handle_command(user_input)
            return

        self.context.add_user_message(user_input)

        # Handle special commands
        if user_input.startswith("/"):
            self._handle_command(user_input)
        else:
            # Regular chat interaction
            self._handle_chat_message(user_input)

    def _handle_command(self, command: str):
        """Handle special commands"""
        parts = command.split(" ", 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd == "/":
            self._open_quick_actions_menu()
        elif cmd == "/help":
            self._show_help()
        elif cmd == "/settings":
            self._show_settings()
        elif cmd == "/exec":
            if args:
                self._execute_command(args)
            else:
                self.console.print("[red]Usage: /exec <command>[/]")
        elif cmd == "/pentest":
            self._start_pentest()
        elif cmd == "/context":
            self._show_context()
        elif cmd == "/clear":
            self._clear_screen()
        elif cmd == "/pwd":
            self._show_current_directory()
        elif cmd == "/ls":
            self._execute_command("ls -la")
        elif cmd == "/cd":
            if args:
                self._change_directory(args)
            else:
                self.console.print("[red]Usage: /cd <directory>[/]")
        elif cmd == "/addkey":
            self._handle_addkey_command(args)
        else:
            self.console.print(f"[red]Unknown command: {cmd}[/]")
            self.console.print("[dim]Type /help for available commands[/]")

    def _handle_chat_message(self, message: str):
        """Treat free-form input as an objective and orchestrate an agent run."""
        cleaned = message.strip()
        if not cleaned:
            return
        target_hint = self._extract_target_hint(cleaned)
        if target_hint:
            self.context.last_known_target = target_hint
        try:
            reply = asyncio.run(self._run_agent_session(cleaned))
            if reply:
                self.console.print(reply)
                self.context.add_assistant_message(reply)
            else:
                self.context.add_assistant_message("No reply generated.")
        except KeyboardInterrupt:
            self.console.print("[yellow]Session interrupted by user[/]")
        except Exception as exc:
            self.console.print(f"[red]Session failed: {exc}[/]")
            cause = exc.__cause__
            if cause and str(cause):
                self.console.print(f"[dim]Reason: {cause}[/dim]")
            self.context.add_assistant_message(f"Session error: {exc}")

    async def _run_agent_session(self, objective: str) -> Optional[str]:
        orchestrator = init_orchestrator(provider="openai")
        target = self._normalized_target()
        allow_tools = {"sqlmap", "nmap", "gobuster", "nikto"} if self.enable_advanced else None
        conversation_context = self.context.as_agent_context()
        session_id = orchestrator.create_session(
            objective,
            target,
            allow_tools=allow_tools,
            conversation_context=conversation_context,
            loop_mode="direct",
        )
        final_report: Optional[str] = None
        final_result: Optional[Dict[str, Any]] = None
        spinner_index = 0
        spinner_frames = ["|", "/", "-", "\\"]

        async def spinner_task(stop_event: asyncio.Event, live: Live) -> None:
            nonlocal spinner_index
            while not stop_event.is_set():
                live.update(f"[dim]running {spinner_frames[spinner_index]}[/]")
                spinner_index = (spinner_index + 1) % len(spinner_frames)
                await asyncio.sleep(0.16)

        with Live(console=self.console, transient=True, refresh_per_second=10) as live:
            stop_event = asyncio.Event()
            spinner_handle = asyncio.create_task(spinner_task(stop_event, live))
            spinner_stopped = False
            async for event in orchestrator.start_autonomous_loop():
                formatted, report_candidate = self._format_event_for_display(event)

                if event.get("type") == "observation":
                    obs = event.get("observation", {})
                    context_summary = obs.get("context_summary", {}) if isinstance(obs, dict) else {}
                    step_summary = context_summary.get("step_summary", "") if isinstance(context_summary, dict) else ""
                    self.context.add_command_execution(
                        obs.get("command", ""),
                        obs.get("returncode", 0),
                        step_summary=step_summary,
                        evidence=obs.get("evidence", []),
                    )

                if report_candidate:
                    final_report = report_candidate

                if event.get("type") == "completed":
                    result_payload = event.get("result")
                    if isinstance(result_payload, dict):
                        final_result = result_payload

                if event.get("type") in {"completed", "error"} and not spinner_stopped:
                    stop_event.set()
                    await spinner_handle
                    spinner_stopped = True
                    live.update("")

                if formatted:
                    lines = formatted if isinstance(formatted, list) else [formatted]
                    for line in lines:
                        if isinstance(line, str) and line.strip():
                            self.console.print(line)

            if not spinner_stopped:
                stop_event.set()
                await spinner_handle
                live.update("")
        self.context.apply_run_result(objective, final_report or "", final_result)
        return final_report

    def _format_event_for_display(self, event: Dict[str, Any]) -> tuple[Optional[Any], Optional[str]]:
        etype = event.get("type")
        if etype == "status":
            return None, None
        if etype == "intent":
            return None, None
        if etype == "decision":
            command = event.get("command", "")
            reason = event.get("reason", "")
            return [
                f"[bright_cyan]> {command}[/]",
                f"[grey58]   {reason}[/]" if reason else "",
            ], None
        if etype == "output":
            line = (event.get("line") or "").strip()
            if not line:
                return None, None
            return [f"[grey50]{line}[/]"], None
        if etype == "rejected":
            reason = event.get("reason", "")
            validator = event.get("validator", {})
            detail = validator.get("tool") or ""
            return [
                f"[red]Rejected[/]: {event.get('command', '')}",
                f"[red]   Reason:[/] {reason}",
                f"[red]   Detail:[/] {detail}" if detail else "",
            ], None
        if etype == "observation":
            obs = event.get("observation", {})
            rc = obs.get("returncode", "")
            duration_value = obs.get("duration")
            if isinstance(duration_value, (int, float)):
                duration = f"{duration_value:.2f}s"
            else:
                duration = str(duration_value) if duration_value not in (None, "") else ""
            snippet = (obs.get("output", "") or "").splitlines()
            display = snippet[0][:120] if snippet else ""
            lines = [
                f"[grey58]rc={rc} duration={duration}[/]" if duration else f"[grey58]rc={rc}[/]",
            ]
            if display:
                lines.append(f"[grey62]   {display}[/]")
            if obs.get("evidence"):
                lines.append(f"[yellow]   Evidence:[/] {', '.join(obs['evidence'])}")
            return lines, None
        if etype == "report":
            return None, event.get("report")
        if etype == "completed":
            return None, None
        if etype == "error":
            return [f"[red]Error:[/] {event.get('error', 'unknown error')}"], None
        return None, None

    def _normalized_target(self) -> Optional[str]:
        if not self.target:
            return None
        if self.target.startswith(("http://", "https://")):
            parsed = urlparse(self.target)
            return parsed.hostname or self.target
        return self.target

    def _extract_target_hint(self, text: str) -> Optional[str]:
        url_match = re.search(r"https?://([A-Za-z0-9\.\-]+)", text)
        if url_match:
            return url_match.group(1).strip().lower()

        host_match = re.search(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", text)
        if host_match:
            return host_match.group(0).strip().lower()

        if "localhost" in text.lower():
            return "localhost"
        return None

    def _execute_command(self, command: str):
        """Execute shell command and display results"""
        self.console.print(f"\n[dim]Executing:[/] [bold]{command}[/]")

        try:
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=self.current_directory,
                timeout=30
            )

            # Display results
            if result.stdout:
                syntax = Syntax(result.stdout, "bash", theme="monokai", line_numbers=False)
                self.console.print(Panel(syntax, title="Output", border_style="green"))

            if result.stderr:
                self.console.print(Panel(result.stderr, title="Error", border_style="red"))

            # Show return code
            if result.returncode != 0:
                self.console.print(f"[red]Exit code: {result.returncode}[/]")
            else:
                self.console.print("[green]Command completed successfully[/]")

            # Add to context
            self.context.add_command_execution(command, result.stdout + result.stderr, result.returncode)

        except subprocess.TimeoutExpired:
            self.console.print("[red]Command timed out (30s limit)[/]")
        except Exception as e:
            self.console.print(f"[red]Error executing command: {e}[/]")

    def _show_help(self):
        """Show help information"""
        help_table = Table(
            title="[cyan]Interactive Commands[/]",
            box=box.MINIMAL_DOUBLE_HEAD,
            show_header=True,
            header_style="bright_cyan",
        )
        help_table.add_column("Command", style="cyan")
        help_table.add_column("Description", style="white")

        help_table.add_row("/help", "Show this help message")
        help_table.add_row("/settings", "Show current settings")
        help_table.add_row("/exec <cmd>", "Execute shell command")
        help_table.add_row("/pentest", "Start AI-driven pentest")
        help_table.add_row("/context", "Show conversation context")
        help_table.add_row("/clear", "Clear screen")
        help_table.add_row("/pwd", "Show current directory")
        help_table.add_row("/ls", "List files in current directory")
        help_table.add_row("/cd <dir>", "Change directory")
        help_table.add_row("/addkey [sk-...]", "Add or replace OpenAI API key")
        help_table.add_row("/quit", "Exit the program")

        self.console.print(help_table)

    def _show_settings(self):
        """Show current settings"""
        settings = Text()
        settings.append("Target: ", style="bright_cyan")
        settings.append(f"{self.target}\n", style="white")
        settings.append("Model: ", style="bright_cyan")
        settings.append("gpt-5.2\n", style="white")
        settings.append("Advanced Tools: ", style="bright_cyan")
        settings.append("Enabled\n" if self.enable_advanced else "Disabled\n", style="white")
        settings.append("Working Directory: ", style="bright_cyan")
        settings.append(f"{self.current_directory}\n", style="white")
        settings.append("Messages in Context: ", style="bright_cyan")
        settings.append(str(len(self.context.messages)), style="white")

        self.console.print(
            Panel(
                settings,
                border_style="magenta",
                box=box.SQUARE,
                title="[magenta]Session Settings[/]",
                padding=(1, 2),
            )
        )

    def _show_context(self):
        """Show conversation context"""
        recent_messages = self.context.get_recent_context(5)

        if not recent_messages:
            self.console.print("[dim]No conversation context yet.[/]")
            return

        context_text = ""
        for msg in recent_messages:
            role = msg["role"]
            content = msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
            context_text += f"**{role.title()}:** {content}\n\n"

        self.console.print(Panel(Markdown(context_text), title="Recent Context", border_style="blue"))

    def _clear_screen(self):
        """Clear the screen"""
        try:
            self.console.clear()
        except Exception:
            os.system('clear' if os.name == 'posix' else 'cls')
        self._show_welcome()

    def _show_current_directory(self):
        """Show current working directory"""
        self.console.print(f"[cyan]Current directory:[/] {self.current_directory}")

    def _change_directory(self, path: str):
        """Change current directory"""
        try:
            new_path = os.path.abspath(os.path.join(self.current_directory, path))
            if os.path.exists(new_path) and os.path.isdir(new_path):
                self.current_directory = new_path
                self.console.print(f"[green]Changed to:[/] {self.current_directory}")
            else:
                self.console.print(f"[red]Directory not found:[/] {path}")
        except Exception as e:
            self.console.print(f"[red]Error changing directory:[/] {e}")

    def _start_pentest(self):
        """Start penetration testing"""
        self.console.print("\n[bold green]Starting AI-driven session...[/]")
        try:
            reply = asyncio.run(self._run_agent_session(self.objective))
            if reply:
                self.console.print(reply)
                self.context.add_assistant_message(reply)
            else:
                self.context.add_assistant_message("Session completed without a reply.")
        except Exception as exc:
            self.console.print(f"[red]Session failed: {exc}[/]")

    def _show_goodbye(self):
        """Show goodbye message"""
        session_duration = datetime.now() - self.context.session_start

        goodbye_text = f"""
[bold green]Session Summary[/]

**Messages exchanged:** {len(self.context.messages)}
**Commands executed:** {len(self.context.command_history)}
**Session duration:** {str(session_duration).split('.')[0]}

[dim]Thank you for using Uxarion.[/]
"""
        self.console.print(Panel(goodbye_text, title="Goodbye", border_style="green"))

    @staticmethod
    def _update_env_file(env_var: str, value: str) -> None:
        env_path = Path(".env")
        lines: List[str] = []
        if env_path.exists():
            lines = env_path.read_text(encoding="utf-8").splitlines()
        updated = False
        for idx, line in enumerate(lines):
            if line.startswith(f"{env_var}="):
                lines[idx] = f"{env_var}={value}"
                updated = True
                break
        if not updated:
            lines.append(f"{env_var}={value}")
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _open_quick_actions_menu(self) -> None:
        self.console.print("\n[cyan]Quick Actions[/]")
        self.console.print("  1) Add/replace OpenAI API key")
        self.console.print("  2) Use OpenAI provider")
        self.console.print("  3) Cancel")
        choice = self.console.input("Select option: ").strip()

        if choice == "1":
            key = self._prompt_for_key("OpenAI")
            if key:
                self._apply_api_key("OPENAI_API_KEY", "OpenAI", key)
        elif choice == "2":
            self.provider = "openai"
            self.console.print("[green]Provider set to OpenAI (gpt-5.2).[/]")
        else:
            self.console.print("[dim]Menu cancelled.[/]")

    def _handle_addkey_command(self, args: str) -> None:
        inline_value = (args or "").strip()
        key = inline_value if inline_value else self._prompt_for_key("OpenAI")
        if not key:
            self.console.print("[yellow]No key entered. Nothing changed.[/]")
            return
        self._apply_api_key("OPENAI_API_KEY", "OpenAI", key)

    def _prompt_for_key(self, label: str) -> Optional[str]:
        try:
            return getpass.getpass(f"Enter new {label} API key: ").strip()
        except Exception:
            return self.console.input(f"Enter new {label} API key: ").strip()

    def _apply_api_key(self, env_var: str, label: str, value: str) -> None:
        os.environ[env_var] = value
        self._update_env_file(env_var, value)
        try:
            module_loader = SourceFileLoader(
                "uxarion_cli_module",
                str(Path(__file__).resolve().parents[2] / "uxarion_cli.py"),
            )
            agent_module = module_loader.load_module()  # type: ignore[deprecated-attr]

            if env_var == "OPENAI_API_KEY":
                agent_module.openai_client = None
        except Exception:
            pass
        self.console.print(f"[green]{label} API key updated.[/]")
