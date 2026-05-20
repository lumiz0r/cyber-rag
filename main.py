#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           CYBER-RAG // AI PENTESTING ASSISTANT               ║
║    HackTheBox × Notion Knowledge Base × Claude Sonnet        ║
╚══════════════════════════════════════════════════════════════╝
"""
import os
import readline  # noqa: F401 — enables arrow-key editing in Prompt.ask()
import sys
import threading
from pathlib import Path
from typing import Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.markup import escape as markup_escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from config import get_config, save_config
from notion_client import NotionClient
from rag_engine import RAGEngine
from scanner import check_tools
from agent import CyberAgent

# ──────────────────────────────────────────────────────────────
# Theme constants
# ──────────────────────────────────────────────────────────────

SESSION_DIR = Path.home() / ".config" / "htb-rag" / "sessions"

C_PRIMARY   = "bold bright_cyan"
C_SECONDARY = "bold bright_magenta"
C_SUCCESS   = "bold bright_green"
C_WARN      = "bold bright_yellow"
C_ERROR     = "bold bright_red"
C_DIM       = "dim white"
C_WHITE     = "bold white"

console = Console()

# ──────────────────────────────────────────────────────────────
# ASCII banner
# ──────────────────────────────────────────────────────────────

BANNER = r"""
  ██████╗██╗   ██╗██████╗ ███████╗██████╗       ██████╗  █████╗  ██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗      ██╔══██╗██╔══██╗██╔════╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╗██████╔╝███████║██║  ███╗
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════╝██╔══██╗██╔══██║██║   ██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║      ██║  ██║██║  ██║╚██████╔╝
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝
"""

TAGLINE = "/// AI PENTESTING ASSISTANT · HACKTHEBOX · NOTION RAG · CLAUDE SONNET ///"


def print_banner():
    console.print(f"[{C_PRIMARY}]{BANNER}[/{C_PRIMARY}]")
    console.print(f"[{C_SECONDARY}]{TAGLINE.center(80)}[/{C_SECONDARY}]")
    console.print()


# ──────────────────────────────────────────────────────────────
# Main menu
# ──────────────────────────────────────────────────────────────

def print_menu():
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style=C_PRIMARY, width=5)
    table.add_column(style=C_WHITE, width=20)
    table.add_column(style=C_DIM)

    table.add_row("[1]", "MACHINE MODE",  "Start solving a HackTheBox machine")
    table.add_row("[2]", "QUERY MODE",    "Ask the AI anything (RAG-assisted)")
    table.add_row("[3]", "SYNC NOTION",   "Fetch & index Notion notes")
    table.add_row("[4]", "KB STATUS",     "Knowledge base statistics")
    table.add_row("[5]", "TOOLS STATUS",  "Check installed pentesting tools")
    table.add_row("[6]", "SETTINGS",      "View/update configuration")
    table.add_row("[0]", "EXIT",          "Disconnect")

    console.print(Panel(
        table,
        title=f"[{C_PRIMARY}]▶  MAIN MENU[/{C_PRIMARY}]",
        border_style="bright_cyan",
        padding=(0, 1),
    ))


# ──────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────

def confirm_command(cmd: str) -> bool:
    console.print(f"\n[{C_WARN}]⚠  POTENTIALLY DANGEROUS COMMAND:[/{C_WARN}]")
    console.print(Syntax(cmd, "bash", theme="monokai", word_wrap=True))
    return Confirm.ask(f"[{C_ERROR}]Execute?[/{C_ERROR}]", default=False)


def on_tool_start(name: str, inp: dict):
    icons = {
        "rag_search":       "[RAG]",
        "htb_recon":        "[NMAP]",
        "web_enum":         "[DIR]",
        "web_fingerprint":  "[FING]",
        "subdomain_enum":   "[DNS]",
        "smb_enum":         "[SMB]",
        "search_exploit":   "[EXP]",
        "udp_scan":         "[UDP]",
        "run_command":      "[CMD]",
        "add_hosts_entry":  "[HOST]",
        "store_credential": "[CRED]",
        "get_credentials":  "[CRED]",
    }
    icon = icons.get(name, "[???]")
    detail = ""
    if name == "rag_search":
        detail = f": \"{inp.get('query', '')[:70]}\""
    elif name == "run_command":
        detail = f": {inp.get('command', '')[:80]}"
    elif name == "htb_recon":
        detail = f": {inp.get('machine_name', '')} @ {inp.get('ip', '')}"
    elif name in ("web_enum", "web_fingerprint"):
        detail = f": {inp.get('url', '')[:60]}"
    elif name == "subdomain_enum":
        detail = f": FUZZ.{inp.get('domain', '')}"
    elif name in ("smb_enum", "udp_scan"):
        detail = f": {inp.get('target', '')}"
    elif name == "search_exploit":
        detail = f": \"{inp.get('term', '')}\""
    elif name == "add_hosts_entry":
        detail = f": {inp.get('ip', '')}  {' '.join(inp.get('hostnames', []))}"
    elif name == "store_credential":
        detail = f": {inp.get('username', '')} / {inp.get('secret', '')[:20]}… [{inp.get('service', '?')}]"
    console.print(f"\n  [{C_SECONDARY}]{icon} {name}{detail}[/{C_SECONDARY}]")


def on_tool_end(name: str, result: str):
    if not result or not result.strip():
        console.print(f"    [{C_DIM}]→ (empty result)[/{C_DIM}]")
        return
    lines = result.strip().splitlines()
    lines = [l for l in lines if l.strip()]
    shown = lines[:12]
    text = markup_escape("\n".join(f"    {l}" for l in shown))
    console.print(f"[{C_DIM}]{text}[/{C_DIM}]")
    if len(lines) > 12:
        console.print(f"    [{C_DIM}]… ({len(lines) - 12} more lines)[/{C_DIM}]")


def on_token_usage(call_in: int, call_out: int, total_in: int, total_out: int, cache_read: int = 0, cache_write: int = 0):
    parts = [f"tokens: {call_in:,} in / {call_out:,} out"]
    if cache_write:
        parts.append(f"cache write: {cache_write:,}")
    if cache_read:
        parts.append(f"[bold green]cache hit: {cache_read:,}[/bold green]")
    parts.append(f"session: {total_in:,} in / {total_out:,} out")
    console.print(f"  [{C_DIM}]↳ {' │ '.join(parts)}[/{C_DIM}]")


def display_response(response: str, title: str = "◈ CYBER-RAG"):
    console.print(Panel(
        Markdown(response),
        title=f"[{C_SECONDARY}]{title}[/{C_SECONDARY}]",
        border_style="bright_magenta",
        padding=(1, 2),
    ))


def get_image_path(prompt_text: str = "") -> Optional[str]:
    """Parse img:<path> from a message string."""
    if prompt_text.startswith("img:"):
        parts = prompt_text.split(" ", 1)
        path = parts[0][4:].strip()
        msg = parts[1] if len(parts) > 1 else "Analyze this screenshot"
        return path, msg
    return None, prompt_text


# ──────────────────────────────────────────────────────────────
# Mode: Machine solver
# ──────────────────────────────────────────────────────────────

def machine_mode(agent: CyberAgent):
    console.print(Panel(
        f"[{C_PRIMARY}]MACHINE SOLVER MODE[/{C_PRIMARY}]\n"
        f"[{C_DIM}]Provide machine info → automated recon → guided exploitation[/{C_DIM}]",
        border_style="bright_cyan",
    ))

    name       = Prompt.ask(f"[{C_PRIMARY}]Machine name[/{C_PRIMARY}]")
    ip         = Prompt.ask(f"[{C_PRIMARY}]Target IP[/{C_PRIMARY}]")
    os_hint    = Prompt.ask(f"[{C_PRIMARY}]OS hint[/{C_PRIMARY}]", default="Unknown")

    diff_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    diff_table.add_column(style=C_PRIMARY, width=5)
    diff_table.add_column(style=C_WHITE, width=10)
    diff_table.add_column(style=C_DIM)
    diff_table.add_row("[1]", "EASY",   "Default creds, known CVEs, simple misconfigs")
    diff_table.add_row("[2]", "MEDIUM", "1-2 pivot steps, moderate enumeration")
    diff_table.add_row("[3]", "HARD",   "Multi-stage, custom payloads, deep enumeration")
    diff_table.add_row("[4]", "INSANE", "Creative chaining, obscure vulns, no limits")
    console.print(Panel(
        diff_table,
        title=f"[{C_PRIMARY}]▶  DIFFICULTY[/{C_PRIMARY}]",
        border_style="bright_cyan",
        padding=(0, 1),
    ))
    diff_choice = Prompt.ask(f"[{C_PRIMARY}]Difficulty[/{C_PRIMARY}]", choices=["1", "2", "3", "4"], default="1")
    difficulty  = {"1": "Easy", "2": "Medium", "3": "Hard", "4": "Insane"}[diff_choice]

    screenshot = Prompt.ask(f"[{C_PRIMARY}]Screenshot path[/{C_PRIMARY}] [{C_DIM}](optional)[/{C_DIM}]", default="")

    screenshot = screenshot if screenshot and os.path.exists(screenshot) else None
    session_path = str(SESSION_DIR / f"{name.lower()}.json")

    # Save after every tool call so crashes don't lose progress
    agent.session_save_cb = lambda: agent.save_session(session_path)

    # ── Session resume ──────────────────────────────────────
    resumed = False
    if Path(session_path).exists():
        console.print(f"\n[{C_WARN}]▶ Existing session found for {name}[/{C_WARN}]")
        if Confirm.ask(f"[{C_PRIMARY}]Resume previous session?[/{C_PRIMARY}]", default=True):
            if agent.load_session(session_path):
                s = agent.get_resume_summary()
                sum_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
                sum_table.add_column(style=C_PRIMARY, width=20)
                sum_table.add_column(style=C_WHITE)
                sum_table.add_row("Machine:",    f"{s['name']} [{s['ip']}]  {s['os']}  {s['difficulty']}")
                sum_table.add_row("Open ports:", s["ports"] or "unknown")
                sum_table.add_row("Turns:",      str(s["turns"]))
                sum_table.add_row("Credentials:", f"{s['cred_count']} stored" + (f"  ({', '.join(s['cred_services'])})" if s["cred_services"] else ""))
                sum_table.add_row("Tokens used:", f"{s['tok_in']:,} in / {s['tok_out']:,} out")
                if s["last_text"]:
                    snippet = s["last_text"][:200].replace("\n", " ")
                    sum_table.add_row("Last AI msg:", f"[dim]{snippet}…[/dim]")
                console.print(Panel(
                    sum_table,
                    title=f"[{C_SUCCESS}]✓ SESSION RESUMED[/{C_SUCCESS}]",
                    border_style="bright_green",
                    padding=(0, 1),
                ))
                resumed = True
            else:
                console.print(f"[{C_ERROR}]✗ Failed to load session — starting fresh[/{C_ERROR}]")

    if not resumed:
        # Mode selection — guided is the default workflow
        console.print()
        mode_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        mode_table.add_column(style=C_PRIMARY, width=5)
        mode_table.add_column(style=C_WHITE, width=20)
        mode_table.add_column(style=C_DIM)
        mode_table.add_row("[1]", "GUIDED  [default]", "Auto recon + README → you exploit → ask AI when stuck")
        mode_table.add_row("[2]", "RECON ONLY",        "Port scan + fingerprint + CVE mapping → README only")
        mode_table.add_row("[3]", "FULL AUTO",         "Fully autonomous — recon + exploitation attempts")
        console.print(Panel(
            mode_table,
            title=f"[{C_PRIMARY}]▶  SELECT MODE[/{C_PRIMARY}]",
            border_style="bright_cyan",
            padding=(0, 1),
        ))
        mode_choice = Prompt.ask(f"[{C_PRIMARY}]Mode[/{C_PRIMARY}]", choices=["1", "2", "3"], default="1")
        mode = {"1": "guided", "2": "recon", "3": "full"}[mode_choice]

        console.print(f"\n[{C_WARN}]▶ INITIALIZING: {name} [{ip}]  difficulty={difficulty}[/{C_WARN}]")
        console.print(f"[{C_DIM}]Running recon — sit back, this will take a few minutes…[/{C_DIM}]\n")

        try:
            response = agent.start_machine(name, ip, os_hint, screenshot, mode=mode, difficulty=difficulty)
        except Exception as exc:
            agent.save_session(session_path)
            console.print(f"[{C_ERROR}]✗ Error during recon — session saved → {session_path}[/{C_ERROR}]")
            console.print(f"[{C_DIM}]{markup_escape(str(exc))}[/{C_DIM}]")
            console.print(f"[{C_WARN}]Restart and resume that session to continue.[/{C_WARN}]")
            return
        display_response(response, f"◈ {name} [{ip}]")
        agent.save_session(session_path)

        if mode in ("recon", "guided"):
            machine_dir = agent.machine_context.get("dir")
            if machine_dir:
                console.print(f"\n[{C_SECONDARY}]◈ Generating README…[/{C_SECONDARY}]")
                readme_content = agent.generate_readme()
                readme_path = Path(machine_dir).expanduser() / "README.md"
                readme_path.write_text(readme_content)
                agent.save_session(session_path)
                # Display README inline so no need to open the file
                console.print(Panel(
                    Markdown(readme_content),
                    title=f"[{C_PRIMARY}]◈ README — {name}[/{C_PRIMARY}]",
                    border_style="bright_cyan",
                    padding=(1, 2),
                ))
                console.print(f"[{C_DIM}]Saved → {readme_path}[/{C_DIM}]")

    # ── RECON COMPLETE banner ───────────────────────────────
    console.print()
    console.print(Panel(
        f"[{C_SUCCESS}]RECON COMPLETE[/{C_SUCCESS}]  ·  [{C_DIM}]explore on your own, ask when stuck[/{C_DIM}]\n"
        f"[{C_DIM}]Commands:  [bold]creds[/bold]  ·  [bold]hosts[/bold]  ·  [bold]readme[/bold]  ·  "
        f"[bold]img:<path> <msg>[/bold]  ·  [bold]reset[/bold]  ·  [bold]back[/bold][/{C_DIM}]",
        border_style="bright_green",
        padding=(0, 2),
    ))

    while True:
        try:
            raw = Prompt.ask(f"[{C_PRIMARY}]HTB/{name}[/{C_PRIMARY}][{C_SECONDARY}] ▶[/{C_SECONDARY}]")
        except KeyboardInterrupt:
            agent.save_session(session_path)
            if agent.history:
                agent.index_session()
            break

        if raw.lower() in ("back", "exit", "quit", "q", ""):
            agent.save_session(session_path)
            if agent.history:
                with console.status(f"[{C_DIM}]Indexing session for cross-session memory…[/{C_DIM}]"):
                    agent.index_session()
                console.print(f"[{C_SUCCESS}]✓ Session indexed — will inform future machines[/{C_SUCCESS}]")
            console.print(f"[{C_DIM}]Session saved → {session_path}[/{C_DIM}]")
            break

        if raw.lower() == "reset":
            agent.reset()
            Path(session_path).unlink(missing_ok=True)
            console.print(f"[{C_SUCCESS}]✓ Session reset and file deleted[/{C_SUCCESS}]")
            continue

        if raw.lower() == "creds":
            if not agent.credentials:
                console.print(f"[{C_DIM}]No credentials stored yet.[/{C_DIM}]")
            else:
                cred_table = Table(box=box.SIMPLE, padding=(0, 2), show_header=True)
                cred_table.add_column("USER",    style=C_PRIMARY,   width=18)
                cred_table.add_column("SECRET",  style=C_WHITE,     width=30)
                cred_table.add_column("TYPE",    style=C_DIM,       width=10)
                cred_table.add_column("SERVICE", style=C_SECONDARY, width=12)
                cred_table.add_column("NOTE",    style=C_DIM)
                for c in agent.credentials:
                    svc = c.get("service", "")
                    if c.get("port"):
                        svc += f":{c['port']}"
                    cred_table.add_row(c["username"], c["secret"], c["secret_type"], svc, c.get("note", ""))
                console.print(Panel(
                    cred_table,
                    title=f"[{C_PRIMARY}]◈ CREDENTIAL VAULT — {len(agent.credentials)} stored[/{C_PRIMARY}]",
                    border_style="bright_cyan",
                ))
            continue

        if raw.lower() == "readme":
            machine_dir = agent.machine_context.get("dir")
            if not machine_dir:
                console.print(f"[{C_WARN}]No machine dir in context — run recon first.[/{C_WARN}]")
            else:
                console.print(f"[{C_SECONDARY}]◈ Generating README…[/{C_SECONDARY}]")
                try:
                    readme_content = agent.generate_readme()
                    readme_path = Path(machine_dir).expanduser() / "README.md"
                    readme_path.write_text(readme_content)
                    console.print(Panel(
                        Markdown(readme_content),
                        title=f"[{C_PRIMARY}]◈ README — {name}[/{C_PRIMARY}]",
                        border_style="bright_cyan",
                        padding=(1, 2),
                    ))
                    console.print(f"[{C_DIM}]Saved → {readme_path}[/{C_DIM}]")
                    agent.save_session(session_path)
                except Exception as exc:
                    console.print(f"[{C_ERROR}]✗ Failed: {markup_escape(str(exc))}[/{C_ERROR}]")
            continue

        if raw.lower() == "hosts":
            ip = agent.machine_context.get("ip", "")
            try:
                hosts_content = Path("/etc/hosts").read_text()
                relevant = [l for l in hosts_content.splitlines() if ip and ip in l]
                if relevant:
                    console.print(Panel(
                        "\n".join(relevant),
                        title=f"[{C_PRIMARY}]◈ /etc/hosts entries for {ip}[/{C_PRIMARY}]",
                        border_style="bright_cyan",
                    ))
                else:
                    console.print(f"[{C_DIM}]No /etc/hosts entries for {ip} yet.[/{C_DIM}]")
            except Exception as exc:
                console.print(f"[{C_ERROR}]Could not read /etc/hosts: {exc}[/{C_ERROR}]")
            continue

        img, text = get_image_path(raw)

        console.print(f"[{C_DIM}]─────────────────────────────────────────[/{C_DIM}]")
        try:
            resp = agent.chat(text, image_path=img)
        except Exception as exc:
            agent.save_session(session_path)
            console.print(f"[{C_ERROR}]✗ Error — session saved → {session_path}[/{C_ERROR}]")
            console.print(f"[{C_DIM}]{markup_escape(str(exc))}[/{C_DIM}]")
            continue
        display_response(resp, f"◈ {name}")
        agent.save_session(session_path)


# ──────────────────────────────────────────────────────────────
# Mode: Direct query
# ──────────────────────────────────────────────────────────────

def query_mode(agent: CyberAgent):
    console.print(Panel(
        f"[{C_PRIMARY}]QUERY MODE[/{C_PRIMARY}]\n"
        f"[{C_DIM}]Ask about hacking techniques, your notes, CTF challenges…[/{C_DIM}]",
        border_style="bright_cyan",
    ))
    console.print(f"[{C_DIM}]Type [bold]back[/bold] to return. Prefix with [bold]img:<path>[/bold] to attach a screenshot.[/{C_DIM}]\n")

    while True:
        try:
            raw = Prompt.ask(f"[{C_PRIMARY}]QUERY[/{C_PRIMARY}][{C_SECONDARY}] ▶[/{C_SECONDARY}]")
        except KeyboardInterrupt:
            break

        if raw.lower() in ("back", "exit", "quit", "q", ""):
            break

        if raw.lower() == "reset":
            agent.reset()
            console.print(f"[{C_SUCCESS}]✓ Conversation cleared[/{C_SUCCESS}]")
            continue

        img, text = get_image_path(raw)

        with console.status(f"[{C_SECONDARY}]◈ Processing…[/{C_SECONDARY}]", spinner="bouncingBall"):
            resp = agent.chat(text, image_path=img)

        display_response(resp)


# ──────────────────────────────────────────────────────────────
# Mode: Notion sync
# ──────────────────────────────────────────────────────────────

def sync_notion(config: dict, rag: RAGEngine):
    console.print(Panel(
        f"[{C_PRIMARY}]NOTION SYNC[/{C_PRIMARY}]\n"
        f"[{C_DIM}]Fetches all pages your integration can access and indexes them[/{C_DIM}]",
        border_style="bright_cyan",
    ))

    notion = NotionClient(config["notion_token"])

    with console.status(f"[{C_PRIMARY}]Searching pages (paginating through all results)…[/{C_PRIMARY}]", spinner="dots"):
        pages = notion.search_pages()  # no limit — fetches all via cursor pagination

    if not pages:
        console.print(f"[{C_ERROR}]✗ No pages found. Check your token and integration sharing.[/{C_ERROR}]")
        return

    console.print(f"[{C_SUCCESS}]✓ Found {len(pages)} pages[/{C_SUCCESS}]")

    total_chunks = 0
    errors: list[str] = []

    with Progress(
        SpinnerColumn(style="bright_cyan"),
        TextColumn(f"[{C_PRIMARY}]{{task.description}}"),
        BarColumn(style="bright_cyan", complete_style="bright_magenta"),
        TextColumn(f"[{C_WHITE}]{{task.completed}}/{{task.total}}"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task("Syncing…", total=len(pages))

        for page in pages:
            title   = notion.get_page_title(page)
            page_id = page["id"]
            url     = notion.get_page_url(page)
            tags    = notion.get_page_tags(page)

            prog.update(task, description=f"[{C_PRIMARY}]{title[:45]}…")

            try:
                content = notion.get_page_content(page_id)
                if content.strip():
                    n = rag.add_document(
                        doc_id=page_id,
                        content=f"# {title}\n\n{content}",
                        metadata={"title": title, "url": url, "tags": ",".join(tags), "source": "notion"},
                    )
                    total_chunks += n
                # Empty pages are silently skipped
            except Exception as exc:
                errors.append(f"{title}: {exc}")

            prog.advance(task)

    notion.close()

    console.print(f"\n[{C_SUCCESS}]✓ Sync complete![/{C_SUCCESS}]")

    summary = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    summary.add_column(style=C_PRIMARY, width=25)
    summary.add_column(style=C_WHITE)
    summary.add_row("Pages processed:", str(len(pages) - len(errors)))
    summary.add_row("Chunks indexed:", str(total_chunks))
    summary.add_row("Errors:", str(len(errors)))
    console.print(summary)

    if errors:
        console.print(f"[{C_WARN}]Errors:[/{C_WARN}]")
        for e in errors[:5]:
            console.print(f"  [{C_DIM}]{e}[/{C_DIM}]")


# ──────────────────────────────────────────────────────────────
# Mode: KB status
# ──────────────────────────────────────────────────────────────

def show_kb_status(rag: RAGEngine):
    stats = rag.get_stats()
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style=C_PRIMARY, width=25)
    table.add_column(style=C_WHITE)
    table.add_row("Total chunks stored:", str(stats["total_chunks"]))
    table.add_row("Status:", f"[{C_SUCCESS}]ONLINE[/{C_SUCCESS}]" if stats["total_chunks"] > 0 else f"[{C_WARN}]EMPTY — run SYNC NOTION[/{C_WARN}]")

    console.print(Panel(table, title=f"[{C_PRIMARY}]◈ KNOWLEDGE BASE[/{C_PRIMARY}]", border_style="bright_cyan"))


# ──────────────────────────────────────────────────────────────
# Mode: Tools status
# ──────────────────────────────────────────────────────────────

def show_tools():
    tools = check_tools()
    table = Table(box=box.SIMPLE, padding=(0, 2))
    table.add_column("TOOL", style=C_PRIMARY, width=18)
    table.add_column("STATUS", width=16)

    for tool, avail in sorted(tools.items()):
        status = f"[{C_SUCCESS}]● AVAILABLE[/{C_SUCCESS}]" if avail else f"[{C_ERROR}]○ NOT FOUND[/{C_ERROR}]"
        table.add_row(tool.upper(), status)

    console.print(Panel(table, title=f"[{C_PRIMARY}]◈ TOOLS STATUS[/{C_PRIMARY}]", border_style="bright_cyan"))


# ──────────────────────────────────────────────────────────────
# Mode: Settings
# ──────────────────────────────────────────────────────────────

def show_settings(config: dict):
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style=C_PRIMARY, width=25)
    table.add_column(style=C_WHITE)

    def mask(val: str) -> str:
        return ("*" * max(0, len(val) - 4) + val[-4:]) if val else f"[{C_ERROR}]NOT SET[/{C_ERROR}]"

    table.add_row("Claude model:",      config.get("claude_model", ""))
    table.add_row("Embed model:",       config.get("embed_model", ""))
    table.add_row("Ollama host:",       config.get("ollama_host", ""))
    table.add_row("Notion token:",      mask(config.get("notion_token", "")))
    table.add_row("Claude API key:",    mask(config.get("claude_api_key", "")))
    table.add_row("Auto-confirm cmds:", str(config.get("auto_confirm_commands", False)))
    table.add_row("Notion page limit:", str(config.get("notion_search_limit", 200)))

    console.print(Panel(table, title=f"[{C_PRIMARY}]◈ SETTINGS[/{C_PRIMARY}]", border_style="bright_cyan"))

    if Confirm.ask(f"\n[{C_PRIMARY}]Update settings?[/{C_PRIMARY}]", default=False):
        config["claude_model"]           = Prompt.ask("Claude model", default=config.get("claude_model", "claude-sonnet-4-6"))
        config["auto_confirm_commands"]  = Confirm.ask("Auto-confirm all commands?", default=False)
        config["notion_search_limit"]    = int(Prompt.ask("Max Notion pages to sync", default=str(config.get("notion_search_limit", 200))))

        if Confirm.ask("Update API keys?", default=False):
            config["notion_token"]   = Prompt.ask("Notion token", default=config.get("notion_token", ""), password=True)
            config["claude_api_key"] = Prompt.ask("Claude API key", default=config.get("claude_api_key", ""), password=True)

        save_config(config)
        console.print(f"[{C_SUCCESS}]✓ Settings saved[/{C_SUCCESS}]")


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────

def main():
    os.system("clear")
    print_banner()

    # Load config (triggers setup wizard on first run — must run outside any Live/status context)
    config = get_config()

    # Init RAG
    with console.status(f"[{C_PRIMARY}]Connecting to knowledge base…[/{C_PRIMARY}]", spinner="dots"):
        rag = RAGEngine(config)

    # Init agent
    agent = CyberAgent(
        config, rag,
        confirm_cb=confirm_command,
        tool_start_cb=on_tool_start,
        tool_end_cb=on_tool_end,
        token_cb=on_token_usage,
    )

    kb = rag.count()
    kb_str = f"[{C_SUCCESS}]{kb} chunks[/{C_SUCCESS}]" if kb > 0 else f"[{C_WARN}]EMPTY — sync Notion first[/{C_WARN}]"
    console.print(f"[{C_SUCCESS}]✓ CYBER-RAG ONLINE[/{C_SUCCESS}]  │  KB: {kb_str}  │  Model: [{C_PRIMARY}]{config['claude_model']}[/{C_PRIMARY}]")
    console.print()

    while True:
        try:
            print_menu()
            choice = Prompt.ask(
                f"[{C_PRIMARY}]SELECT[/{C_PRIMARY}][{C_SECONDARY}] ▶[/{C_SECONDARY}]",
                choices=["0", "1", "2", "3", "4", "5", "6"],
                show_choices=False,
            )
            console.print()

            if choice == "0":
                console.print(f"[{C_PRIMARY}]>>> DISCONNECTING… STAY ETHICAL <<<[/{C_PRIMARY}]")
                break
            elif choice == "1":
                machine_mode(agent)
            elif choice == "2":
                query_mode(agent)
            elif choice == "3":
                sync_notion(config, rag)
            elif choice == "4":
                show_kb_status(rag)
            elif choice == "5":
                show_tools()
            elif choice == "6":
                show_settings(config)

            console.print()

        except KeyboardInterrupt:
            console.print(f"\n[{C_PRIMARY}]>>> CTRL+C — returning to menu… (press again to exit)[/{C_PRIMARY}]")
            try:
                pass
            except KeyboardInterrupt:
                console.print(f"[{C_PRIMARY}]>>> DISCONNECTING <<<[/{C_PRIMARY}]")
                break


if __name__ == "__main__":
    main()
