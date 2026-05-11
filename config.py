"""
CYBER-RAG Configuration Manager
"""
import json
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

console = Console()
CONFIG_PATH = Path.home() / ".config" / "htb-rag" / "config.json"

DEFAULT_CONFIG = {
    "notion_token": "",
    "claude_api_key": "",
    "ollama_host": "http://localhost:11434",
    "embed_model": "nomic-embed-text",
    "claude_model": "claude-sonnet-4-6",
    "chroma_path": str(Path(__file__).parent / "chroma_db"),
    "notion_search_limit": 200,
    "rag_top_k": 6,
    "auto_confirm_commands": False,
    "work_dir": "~/Desktop/Hackthebox/Machines",
}


def load_config() -> dict:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            if k not in config:
                config[k] = v
        return config
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)


def setup_wizard(config: dict) -> dict:
    console.print(Panel(
        "[bold bright_cyan]FIRST RUN SETUP[/bold bright_cyan]\n"
        "[dim]Configure your API keys to initialize CYBER-RAG[/dim]",
        border_style="bright_cyan"
    ))

    if not config.get("notion_token"):
        console.print("[dim]  → Create a Notion integration at notion.so/my-integrations[/dim]")
        console.print("[dim]  → Share the pages/databases you want to index with your integration[/dim]")
        config["notion_token"] = Prompt.ask(
            "\n[bold bright_magenta]NOTION_TOKEN[/bold bright_magenta]",
            password=True
        )

    if not config.get("claude_api_key"):
        console.print("\n[dim]  → Get your API key at console.anthropic.com[/dim]")
        config["claude_api_key"] = Prompt.ask(
            "[bold bright_magenta]CLAUDE_API_KEY[/bold bright_magenta]",
            password=True
        )

    save_config(config)
    console.print("\n[bold bright_green]✓ Configuration saved[/bold bright_green]")
    return config


def get_config() -> dict:
    config = load_config()
    if not config.get("notion_token") or not config.get("claude_api_key"):
        config = setup_wizard(config)
    return config
