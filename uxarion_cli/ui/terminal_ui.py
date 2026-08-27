# SPDX-License-Identifier: Apache-2.0
"""
Terminal UI for Uxarion AI Agent
Rich-based interface with live event streaming
"""
import asyncio
import json
import sys
import os
from typing import List, Dict, Any

try:
    import httpx
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


BANNER = """                           Uxarion CLI

Open-source AI pentesting copilot for authorized security testing.

Uxarion is an AI pentesting copilot, open-source for the pentesting community.
Bring your own API key and drive proven CLI tools (sqlmap, gobuster, nikto, nmap)
through a safe, single-command loop.

# Chat mode started. Type your objective/instructions
# Ctrl-C interrupts a running loop; 'quit' to exit
# Type '/' + Enter to see menu, then type option number + Enter

> """


class TerminalUI:
    """Rich-based terminal interface for AI agent control"""

    def __init__(self, api_base: str = "http://127.0.0.1:8000"):
        if not RICH_AVAILABLE:
            print("Error: Rich and httpx required. Run: pip install rich httpx")
            sys.exit(1)

        self.console = Console()
        self.api_base = api_base
        self.target = "127.0.0.1"
        self.objective = "Map open ports and services"
        self.current_session = None
        self.log_lines: List[str] = []
        self.event_count = 0

    def run(self):
        """Main UI loop"""
        self.console.print(BANNER)

        try:
            asyncio.run(self._main_loop())
        except KeyboardInterrupt:
            self.console.print("\nGoodbye.")
            sys.exit(0)

    async def _main_loop(self):
        """Main async UI loop"""
        while True:
            try:
                command = self.console.input("> ").strip()

                if command == "quit":
                    break
                elif command == "/":
                    self._show_menu()
                elif command.startswith("/set target "):
                    self.target = command.split(" ", 2)[2]
                    self.console.print(f"[bold green]Target set:[/] {self.target}")
                elif command.startswith("/set objective "):
                    self.objective = command.split(" ", 2)[2]
                    self.console.print(f"[bold green]Objective set:[/] {self.objective}")
                elif command in {"/start", "3"}:
                    await self._start_session()
                elif command in {"1"}:
                    new_target = self.console.input("Enter target: ").strip()
                    if new_target:
                        self.target = new_target
                        self.console.print(f"[bold green]Target set:[/] {self.target}")
                elif command in {"2"}:
                    new_objective = self.console.input("Enter objective: ").strip()
                    if new_objective:
                        self.objective = new_objective
                        self.console.print(f"[bold green]Objective set:[/] {self.objective}")
                elif command in {"4"}:
                    break
                elif command:
                    # Treat as new objective
                    self.objective = command
                    self.console.print(f"[bold cyan]Queued:[/] {self.objective}")

            except KeyboardInterrupt:
                if self.current_session:
                    self.console.print("\n[yellow]Session interrupted[/]")
                    self.current_session = None
                else:
                    break
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/]")

    def _show_menu(self):
        """Show menu options"""
        self.console.print("""
[bold cyan]Menu Options:[/]
1) Set target
2) Set objective
3) Start reconnaissance
4) Quit

[bold yellow]Current Settings:[/]
Target: {target}
Task: {objective}
""".format(target=self.target, objective=self.objective))

    async def _start_session(self):
        """Start reconnaissance session with live streaming"""
        self.console.print(f"[bold green]Starting AI reconnaissance...[/]")
        self.console.print(f"[cyan]Target:[/] {self.target}")

        try:
            # Start the session
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(f"{self.api_base}/start", json={
                    "target": self.target,
                    "objective": self.objective
                })

                if response.status_code != 200:
                    self.console.print(f"[red]Failed to start session: {response.text}[/]")
                    return

                result = response.json()
                session_id = result["session_id"]
                self.current_session = session_id

            self.console.print(f"[green]Session started: {session_id}[/]")
            self.console.print("[dim]Streaming live events... (Press Ctrl+C to stop)[/]")

            # Start live streaming
            await self._stream_session_events(session_id)

        except httpx.RequestError as e:
            self.console.print(f"[red]Connection error: {e}[/]")
            self.console.print("[yellow]Make sure the API server is running on {self.api_base}[/]")
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/]")
        finally:
            self.current_session = None

    async def _stream_session_events(self, session_id: str):
        """Stream events with live UI updates"""
        self.log_lines = []
        self.event_count = 0

        # Create layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", ratio=1),
            Layout(name="main", ratio=8),
            Layout(name="footer", ratio=1),
        )

        layout["main"].split_row(
            Layout(name="logs", ratio=2),
            Layout(name="status", ratio=1),
        )

        try:
            async with httpx.AsyncClient(timeout=None) as client:
                with Live(layout, refresh_per_second=2, transient=False):
                    async with client.stream("GET", f"{self.api_base}/events/{session_id}") as response:
                        async for line in response.aiter_lines():
                            if not line or line.startswith(":"):
                                continue

                            if line.startswith("data: "):
                                try:
                                    event_data = json.loads(line[6:])
                                    await self._process_event(event_data, layout)
                                except json.JSONDecodeError:
                                    continue

                                self.event_count += 1

                                # Update layout
                                self._update_layout(layout, session_id)

                                # Check for session completion
                                if event_data.get("type") == "session.completed":
                                    await asyncio.sleep(2)  # Show final state
                                    break

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.console.print(f"\n[red]Streaming error: {e}[/]")

        self.console.print(f"\n[green]Session completed. Events processed: {self.event_count}[/]")

    async def _process_event(self, event: Dict[str, Any], layout: Layout):
        """Process incoming event and update state"""
        event_type = event.get("type", "")
        data = event.get("data", {})

        if event_type == "log.append":
            stream = data.get("stream", "stdout")
            text = data.get("text", "")
            prefix = "[red]ERR[/]" if stream == "stderr" else "[dim]OUT[/]"
            self.log_lines.append(f"{prefix} {text}")

        elif event_type == "step.started":
            step_id = data.get("id", "")
            command = data.get("command", "")
            reason = data.get("reason", "")
            self.log_lines.append(f"[bold cyan]{reason}[/]")
            self.log_lines.append(f"[yellow]$ {command}[/]")

        elif event_type == "step.finished":
            exit_code = data.get("exit_code", 0)
            duration = data.get("duration", 0)
            status = "[green]ok[/]" if exit_code == 0 else "[red]fail[/]"
            self.log_lines.append(f"{status} Command finished (exit: {exit_code}, {duration:.1f}s)")

        elif event_type == "vulnerability.found":
            vuln_type = data.get("type", "")
            severity = data.get("severity", "")
            target = data.get("target", "")
            severity_color = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}.get(severity, "white")
            self.log_lines.append(f"[bold {severity_color}]{severity.upper()}: {vuln_type} at {target}[/]")

        elif event_type == "ai.analysis":
            analysis = data.get("analysis", "")
            self.log_lines.append(f"[bold magenta]AI: {analysis}[/]")

        elif event_type == "error":
            message = data.get("message", "")
            self.log_lines.append(f"[red]Error: {message}[/]")

        # Keep only recent logs
        if len(self.log_lines) > 100:
            self.log_lines = self.log_lines[-100:]

    def _update_layout(self, layout: Layout, session_id: str):
        """Update the live layout with current state"""
        # Header
        layout["header"].update(Panel(
            f"[bold cyan]Uxarion AI Agent[/] - Session: {session_id}",
            style="cyan"
        ))

        # Logs panel
        recent_logs = self.log_lines[-30:] if self.log_lines else ["[dim]Waiting for events...[/]"]
        layout["logs"].update(Panel(
            "\n".join(recent_logs),
            title="Live Agent Logs",
            border_style="blue"
        ))

        # Status panel
        status_text = f"""[bold]Target:[/] {self.target}
[bold]Task:[/] {self.objective}
[bold]Events:[/] {self.event_count}
[bold]Log Lines:[/] {len(self.log_lines)}

[dim]Press Ctrl+C to stop[/]"""

        layout["status"].update(Panel(
            status_text,
            title="Session Status",
            border_style="green"
        ))

        # Footer
        layout["footer"].update(Panel(
            "[dim]Uxarion AI Pentesting Agent - Streaming live reconnaissance results[/]",
            style="dim"
        ))


def main():
    """Entry point for terminal UI"""
    import argparse

    parser = argparse.ArgumentParser(description="Uxarion Terminal UI")
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="API server URL")
    args = parser.parse_args()

    ui = TerminalUI(api_base=args.api)
    ui.run()


if __name__ == "__main__":
    main()
