"""
CYBER-RAG Agent
Claude Sonnet with tool use for autonomous pentesting assistance
"""
import base64
import json
import os
import time
from pathlib import Path
from typing import Callable, Optional

import anthropic

from rag_engine import RAGEngine
from scanner import (
    add_hosts_entry, format_result, htb_recon, is_dangerous,
    run_command, search_exploit, smb_enum,
    subdomain_enum, udp_scan, web_enum, whatweb,
)


# ──────────────────────────────────────────────────────────
# Tool definitions for Claude
# ──────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "rag_search",
        "description": (
            "Search the personal knowledge base (synced from Notion notes). "
            "Use this to find relevant techniques, writeups, payloads, commands, "
            "and methodologies from the user's own notes. Always search before "
            "suggesting an approach."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "What to search for"},
                "n": {"type": "integer", "description": "Number of results (default 5)", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "run_command",
        "description": (
            "Execute a shell command on the operator's machine. "
            "Commands run in the machine's workspace directory when a session is active. "
            "Use for manual exploitation steps, reading files, crafting payloads, "
            "post-exploitation, pivoting, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)", "default": 120},
            },
            "required": ["command"],
        },
    },
    {
        "name": "htb_recon",
        "description": (
            "Full HTB reconnaissance workflow — always use this at the start of a machine. "
            "It runs 4 steps automatically:\n"
            "  1. mkt — creates nmap/ content/ exploits/ workspace\n"
            "  2. nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv → allPorts (grepable)\n"
            "  3. extractPorts — parses open ports, copies to clipboard\n"
            "  4. nmap -p<ports> -sCV → targeted (service/version/script scan)\n"
            "Returns full output plus the list of open ports."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "machine_name": {"type": "string", "description": "Machine name (used as workspace folder name)"},
                "ip": {"type": "string", "description": "Target IP address"},
            },
            "required": ["machine_name", "ip"],
        },
    },
    {
        "name": "web_enum",
        "description": (
            "Directory/file enumeration on a web server using feroxbuster (preferred), "
            "gobuster, or ffuf as fallback. Run this for every HTTP/HTTPS service found."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (e.g. http://10.10.10.1)"},
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist",
                    "default": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "subdomain_enum",
        "description": (
            "Fuzz for virtual-host / subdomain enumeration using wfuzz (Host header fuzzing). "
            "Run this whenever a domain name is identified on a web service. "
            "Pass the bare domain (e.g. 'example.htb') and optionally the target IP "
            "if the domain isn't in /etc/hosts yet."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Base domain to fuzz (e.g. example.htb)"},
                "ip": {"type": "string", "description": "Target IP (optional — used when domain not in /etc/hosts)"},
                "wordlist": {
                    "type": "string",
                    "description": "Path to subdomain wordlist",
                    "default": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "web_fingerprint",
        "description": "Fingerprint web technologies on a URL using whatweb or curl.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "smb_enum",
        "description": "Enumerate SMB shares and users on a target (enum4linux / smbclient).",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "search_exploit",
        "description": "Search for public exploits using searchsploit (Exploit-DB).",
        "input_schema": {
            "type": "object",
            "properties": {
                "term": {"type": "string", "description": "Search term (e.g. 'vsftpd 2.3.4', 'Apache 2.4.49')"},
            },
            "required": ["term"],
        },
    },
    {
        "name": "udp_scan",
        "description": "Scan common UDP ports on a target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "ports": {"type": "string", "description": "UDP ports to scan", "default": "161,162,137,138,139,500"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "add_hosts_entry",
        "description": (
            "Add a hostname to /etc/hosts. Call this as soon as you discover any domain or vhost "
            "(from nmap, SSL certs, HTTP headers, web fingerprinting, or subdomain enum). "
            "Must be done before subdomain_enum can resolve the domain."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip":        {"type": "string", "description": "Target IP address"},
                "hostnames": {"type": "array", "items": {"type": "string"},
                              "description": "Hostnames to add (e.g. ['machine.htb', 'sub.machine.htb'])"},
            },
            "required": ["ip", "hostnames"],
        },
    },
    {
        "name": "store_credential",
        "description": (
            "Store a discovered credential in the session vault. Call this IMMEDIATELY whenever you find "
            "a username, password, hash, API key, or any secret — in config files, source code, responses, "
            "or after a successful login. Other tools will check the vault before attempting auth."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "username":    {"type": "string"},
                "secret":      {"type": "string", "description": "Password, hash, key, or token"},
                "secret_type": {"type": "string", "enum": ["password", "hash", "key", "token"], "default": "password"},
                "service":     {"type": "string", "description": "Service this works on (ssh, http, smb, ftp, mysql…)"},
                "port":        {"type": "integer"},
                "note":        {"type": "string", "description": "Where/how it was found"},
            },
            "required": ["username", "secret"],
        },
    },
    {
        "name": "get_credentials",
        "description": (
            "Retrieve all credentials stored in the session vault. Always check this before attempting "
            "any authentication — the password may already be known."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Filter by service (optional)"},
            },
            "required": [],
        },
    },
]


# ──────────────────────────────────────────────────────────
# System Prompt
# ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are CYBER-RAG, an elite AI pentesting assistant specialized in HackTheBox machines and CTF challenges. \
You operate with a structured, methodical approach and have access to a personal knowledge base of hacking notes \
(synced from Notion) as well as live scanning tools.

RECON WORKFLOW (follow this order for every machine):
1. Search the knowledge base for techniques related to the machine/OS type
2. Run htb_recon — this does mkt + full port scan + extractPorts + targeted scan automatically
3. Analyze open ports/services found in the targeted scan
4. For each service, search the knowledge base AND searchsploit for known vulns
5. For every HTTP/HTTPS port found:
   a. web_fingerprint — identify technologies and domain names
   b. web_enum — feroxbuster directory/file enumeration
   c. subdomain_enum — wfuzz vhost/subdomain fuzzing (use the domain from fingerprint; pass IP if domain not in /etc/hosts)
6. Enumerate SMB if 139/445 found
7. Formulate exploitation approach based on findings + notes

RESPONSE FORMAT:
🔍 **FINDINGS** — What was discovered
💡 **ANALYSIS** — What it means, potential attack vectors
📓 **FROM YOUR NOTES** — Relevant knowledge base snippets
⚡ **NEXT STEPS** — Concrete prioritised actions
🔧 **COMMANDS** — Ready-to-run commands in code blocks

DIFFICULTY-AWARE STRATEGY:
- Easy: Go for the obvious — default credentials, exact-version CVEs, common misconfigs. \
If a path fails after 2-3 attempts, STOP and pivot. Complex chaining is wrong on Easy machines.
- Medium: Expect 1-2 lateral steps. Enumerate carefully, check credential reuse and non-default configs.
- Hard: Multi-stage exploitation is expected. Deep rabbit holes, custom payloads, privesc chains are normal. Persistence pays off.
- Insane: No limits. Creative chaining, obscure services, race conditions. Search notes exhaustively before every attempt.

WHEN STUCK: Always search the knowledge base for "<difficulty> machine <service>" patterns. \
On Easy/Medium, if something feels overly complex, assume you missed a simpler path and search for it before going deeper.

RULES:
- You are assisting with authorized HackTheBox / CTF environments only
- The machine workspace is at ~/Desktop/Hackthebox/Machines/<machine_name>/ — reference files there
- After recon, all scan files are in ~/Desktop/Hackthebox/Machines/<machine_name>/nmap/
- Be specific: always show exact commands, exact file paths
- When a technique fails, check the knowledge base for alternatives
"""

GUIDED_SYSTEM_PROMPT = """\
You are CYBER-RAG, an elite AI pentesting mentor specialized in HackTheBox machines and CTF challenges.
You are in GUIDED MENTOR MODE. Your role is split into two phases:

━━━ PHASE 1 — AUTONOMOUS RECON (use your tools freely) ━━━
Run the full recon workflow automatically:
1. Search the knowledge base for techniques related to the machine/OS type and difficulty
2. Run htb_recon (full port scan + extractPorts + targeted scan)
3. Analyze open ports/services
4. For each service version found, run search_exploit to map CVEs/public exploits
5. For every HTTP/HTTPS port: web_fingerprint → web_enum → subdomain_enum (if a domain is identified)
6. Run smb_enum if 139/445 is open
After all recon is complete, present a structured findings report, then move to Phase 2.

━━━ PHASE 2 — MENTOR MODE (no more auto-exploitation) ━━━
CRITICAL RULE: After the initial recon, do NOT call run_command, web_enum, smb_enum, \
search_exploit, htb_recon, subdomain_enum, or web_fingerprint again. \
You MAY still call rag_search at any time to look up techniques and hints from the notes.

Instead of running exploits yourself:
- Suggest 2-3 prioritised attack vectors the user should try themselves
- For each vector, provide the exact command(s) to run in a code block, with an explanation of WHY it is worth trying
- Wait for the user to run commands and share their output
- When they share output, analyze it fully and guide the next step
- If they get stuck, give progressive hints: vague → specific → near-answer (3 levels before fully revealing)
- Celebrate wins and explain the underlying concept when they succeed

RESPONSE FORMAT:
🔍 **FINDINGS** — What was discovered during recon
💡 **ANALYSIS** — What the services/versions mean, likely attack surface
📓 **FROM YOUR NOTES** — Relevant snippets from the knowledge base
🎯 **TRY THIS** — Exact commands for the user to run (with explanation of why)
💬 **MENTOR NOTE** — Teaching point, hint, or analysis of what the user shared

TEACHING PRINCIPLES:
- Explain WHY a vector is promising, not just what to run
- Reference the underlying concept (e.g. "this binary has SUID and calls popen without a full path")
- Three hint levels before giving the answer: conceptual → narrowed → near-explicit
- When the user pastes output, always extract every useful detail before responding
- Reinforce what they learned when they succeed — make it stick

DIFFICULTY-AWARE MENTORING:
- Easy: Guide toward the obvious first — default creds, known CVE. Great for building pattern recognition.
- Medium: Prompt them to enumerate thoroughly before hinting at the pivot.
- Hard/Insane: Teach the methodology. Complex chains are expected — walk them through the reasoning.

RULES:
- Authorized HackTheBox / CTF environments only
- Machine workspace: ~/Desktop/Hackthebox/Machines/<machine_name>/
- Always show exact commands with exact flags in code blocks — ready to copy-paste
- After Phase 1 recon, you are a MENTOR, not an autonomous agent
"""


# ──────────────────────────────────────────────────────────
# Difficulty hints (injected into each machine's first message)
# ──────────────────────────────────────────────────────────

_DIFFICULTY_HINTS = {
    "Easy": (
        "DIFFICULTY: Easy — target the obvious first: default credentials, known CVEs for exact versions, "
        "simple misconfigs. Search the knowledge base for previous Easy machines with similar services and "
        "reuse those patterns. If any attack path requires complex chaining or custom exploit dev, STOP and "
        "search for a simpler vector; it always exists on Easy machines."
    ),
    "Medium": (
        "DIFFICULTY: Medium — expect 1-2 lateral steps before foothold. Enumerate carefully, look for "
        "credential reuse, non-default configs, and slightly obscure service versions. Search the knowledge "
        "base for previous Medium machine patterns with similar services. If stuck after 3 attempts, pivot "
        "and search for an alternative path before going deeper."
    ),
    "Hard": (
        "DIFFICULTY: Hard — multi-stage exploitation is expected and normal. Deep enumeration, custom "
        "payloads, and privesc chains are the standard here. Search notes for Hard machine techniques. "
        "Persistence pays off; go deeper before pivoting."
    ),
    "Insane": (
        "DIFFICULTY: Insane — no limits. Creative exploit chaining, obscure services, race conditions, "
        "tight attack windows. Search the knowledge base exhaustively before and after every step. "
        "Nothing is too complex — but always verify basics aren't missed first."
    ),
}


# ──────────────────────────────────────────────────────────
# Agent
# ──────────────────────────────────────────────────────────

# Per-tool character limits for what gets stored in history.
# Keeping these tight is the biggest lever on input token growth.
_TOOL_MAX_CHARS: dict[str, int] = {
    "htb_recon":        4000,
    "run_command":      2500,
    "rag_search":       1800,
    "web_enum":         2000,
    "smb_enum":         1500,
    "subdomain_enum":   1200,
    "search_exploit":   1000,
    "web_fingerprint":   700,
    "udp_scan":          700,
}
_DEFAULT_TOOL_MAX   = 2000
_HISTORY_KEEP_RECENT = 3    # keep last N tool-result messages uncompressed
_HISTORY_COMPRESS_TO = 400  # chars kept per old tool result after compaction


class CyberAgent:
    def __init__(
        self,
        config: dict,
        rag: RAGEngine,
        confirm_cb: Optional[Callable[[str], bool]] = None,
        tool_start_cb: Optional[Callable[[str, dict], None]] = None,
        tool_end_cb: Optional[Callable[[str, str], None]] = None,
        token_cb: Optional[Callable[[int, int, int, int, int, int], None]] = None,
    ):
        self.config = config
        self.rag = rag
        self.confirm_cb = confirm_cb
        self.tool_start_cb = tool_start_cb
        self.tool_end_cb = tool_end_cb
        self.token_cb = token_cb
        self.session_save_cb: Optional[Callable[[], None]] = None
        self.auto_confirm = config.get("auto_confirm_commands", False)
        self.work_dir = config.get("work_dir", "~/Desktop/Hackthebox/Machines/")

        self._client = anthropic.Anthropic(api_key=config["claude_api_key"])
        self._model = config.get("claude_model", "claude-sonnet-4-6")
        self._active_system_prompt = SYSTEM_PROMPT
        self.history: list[dict] = []
        self.machine_context: dict = {}
        self.credentials: list[dict] = []
        self.session_input_tokens: int = 0
        self.session_output_tokens: int = 0
        self.session_cache_read_tokens: int = 0

    # ── Token-saving helpers ───────────────────────────────

    @staticmethod
    def _truncate_result(name: str, result: str) -> str:
        """Cap tool output before storing in history. Keeps head + tail so context isn't lost."""
        limit = _TOOL_MAX_CHARS.get(name, _DEFAULT_TOOL_MAX)
        if len(result) <= limit:
            return result
        half = limit // 2
        omitted = len(result) - limit
        return result[:half] + f"\n\n[…{omitted:,} chars omitted…]\n\n" + result[-half:]

    def _compact_history(self):
        """Shrink old tool-result messages in-place to reduce context size on long sessions."""
        tool_msg_idx = [
            i for i, m in enumerate(self.history)
            if m["role"] == "user"
            and isinstance(m["content"], list)
            and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in m["content"])
        ]
        for i in tool_msg_idx[:-_HISTORY_KEEP_RECENT]:
            new_blocks = []
            for block in self.history[i]["content"]:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    content = block.get("content", "")
                    if isinstance(content, str) and len(content) > _HISTORY_COMPRESS_TO:
                        block = {
                            **block,
                            "content": content[:_HISTORY_COMPRESS_TO]
                            + f"\n[…{len(content) - _HISTORY_COMPRESS_TO:,} chars — summarised by assistant above]",
                        }
                new_blocks.append(block)
            self.history[i] = {**self.history[i], "content": new_blocks}

    # ── Tool execution ─────────────────────────────────────

    def _exec_tool(self, name: str, inp: dict) -> str:
        if self.tool_start_cb:
            try:
                self.tool_start_cb(name, inp)
            except Exception:
                pass

        result = self._dispatch(name, inp)
        result = self._truncate_result(name, result)

        if self.tool_end_cb:
            try:
                self.tool_end_cb(name, result)
            except Exception:
                pass

        return result

    def _dispatch(self, name: str, inp: dict) -> str:
        machine_dir = self.machine_context.get("dir")

        if name == "rag_search":
            hits = self.rag.search(inp["query"], n=inp.get("n", 3))
            if not hits:
                return "No relevant notes found in the knowledge base."
            parts = []
            for h in hits:
                title = h["metadata"].get("title", "Unknown")
                chunk = h["content"]
                if len(chunk) > 600:
                    chunk = chunk[:600] + "…"
                parts.append(f"[score={h['score']:.2f}] **{title}**\n{chunk}")
            return "\n\n---\n\n".join(parts)

        elif name == "run_command":
            cmd = inp["command"]
            timeout = inp.get("timeout", 120)
            if is_dangerous(cmd) and not self.auto_confirm and self.confirm_cb:
                if not self.confirm_cb(cmd):
                    return f"Command rejected by operator: {cmd}"
            result = run_command(cmd, timeout=timeout, cwd=machine_dir)
            return format_result(result)

        elif name == "htb_recon":
            machine_name = inp["machine_name"]
            ip = inp["ip"]
            r = htb_recon(machine_name, ip, self.work_dir)
            # Store machine dir so run_command uses it as cwd
            self.machine_context["dir"] = r["machine_dir"]
            self.machine_context["ports"] = r["ports"]
            return r["output"]

        elif name == "web_enum":
            result = web_enum(
                inp["url"],
                inp.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"),
            )
            return format_result(result)

        elif name == "web_fingerprint":
            result = whatweb(inp["url"])
            return format_result(result)

        elif name == "subdomain_enum":
            result = subdomain_enum(
                inp["domain"],
                ip=inp.get("ip"),
                wordlist=inp.get("wordlist", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
            )
            return format_result(result)

        elif name == "smb_enum":
            result = smb_enum(inp["target"])
            return format_result(result)

        elif name == "search_exploit":
            result = search_exploit(inp["term"])
            return format_result(result)

        elif name == "udp_scan":
            result = udp_scan(inp["target"], inp.get("ports", "161,162,137,138,139,500"))
            return format_result(result)

        elif name == "add_hosts_entry":
            ip = inp["ip"]
            hostnames = inp["hostnames"]
            preview = f"echo '{ip}  {' '.join(hostnames)}' | sudo tee -a /etc/hosts"
            if not self.auto_confirm and self.confirm_cb:
                if not self.confirm_cb(preview):
                    return "Skipped — /etc/hosts not modified."
            result = add_hosts_entry(ip, hostnames)
            return format_result(result)

        elif name == "store_credential":
            import datetime
            cred = {
                "username":    inp["username"],
                "secret":      inp["secret"],
                "secret_type": inp.get("secret_type", "password"),
                "service":     inp.get("service", ""),
                "port":        inp.get("port"),
                "note":        inp.get("note", ""),
                "found_at":    datetime.datetime.now().isoformat(timespec="seconds"),
            }
            self.credentials.append(cred)
            svc = f" [{cred['service']}:{cred['port']}]" if cred.get("port") else (f" [{cred['service']}]" if cred["service"] else "")
            return f"[VAULT] Stored{svc}: {cred['username']} / {cred['secret']} ({cred['secret_type']})"

        elif name == "get_credentials":
            if not self.credentials:
                return "Credential vault is empty."
            svc_filter = inp.get("service", "").lower()
            creds = [c for c in self.credentials if not svc_filter or c.get("service", "").lower() == svc_filter]
            if not creds:
                return f"No credentials stored for service '{svc_filter}'."
            lines = []
            for c in creds:
                svc = f" [{c['service']}:{c['port']}]" if c.get("port") else (f" [{c['service']}]" if c.get("service") else "")
                note = f" — {c['note']}" if c.get("note") else ""
                lines.append(f"{c['username']} / {c['secret']} ({c['secret_type']}){svc}{note}")
            return "\n".join(lines)

        return f"Unknown tool: {name}"

    # ── Agentic loop ───────────────────────────────────────

    def chat(self, message: str, image_path: Optional[str] = None) -> str:
        content: list = []

        if image_path and os.path.exists(image_path):
            ext = Path(image_path).suffix.lower()
            mt = {".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                  ".png": "image/png", ".gif": "image/gif",
                  ".webp": "image/webp"}.get(ext, "image/png")
            with open(image_path, "rb") as f:
                b64 = base64.standard_b64encode(f.read()).decode()
            content.append({"type": "image", "source": {"type": "base64", "media_type": mt, "data": b64}})

        content.append({"type": "text", "text": message})
        self.history.append({"role": "user", "content": content})

        final = ""
        while True:
            self._compact_history()

            for attempt in range(5):
                try:
                    resp = self._client.messages.create(
                        model=self._model,
                        max_tokens=8192,
                        system=[{
                            "type": "text",
                            "text": self._active_system_prompt,
                            "cache_control": {"type": "ephemeral"},
                        }],
                        tools=TOOLS,
                        messages=self.history,
                    )
                    break
                except anthropic.RateLimitError:
                    if attempt == 4:
                        raise
                    wait = 60 * (attempt + 1)
                    print(f"\n[rate limit] waiting {wait}s before retry ({attempt + 1}/5)...", flush=True)
                    time.sleep(wait)

            cache_read  = getattr(resp.usage, "cache_read_input_tokens", 0) or 0
            cache_write = getattr(resp.usage, "cache_creation_input_tokens", 0) or 0
            self.session_input_tokens  += resp.usage.input_tokens
            self.session_output_tokens += resp.usage.output_tokens
            self.session_cache_read_tokens += cache_read
            if self.token_cb:
                self.token_cb(
                    resp.usage.input_tokens, resp.usage.output_tokens,
                    self.session_input_tokens, self.session_output_tokens,
                    cache_read, cache_write,
                )

            if resp.stop_reason == "tool_use":
                self.history.append({"role": "assistant", "content": resp.content})
                tool_results = []
                for block in resp.content:
                    if block.type == "tool_use":
                        output = self._exec_tool(block.name, block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": output,
                        })
                self.history.append({"role": "user", "content": tool_results})
                if self.session_save_cb:
                    try:
                        self.session_save_cb()
                    except Exception:
                        pass
                continue

            for block in resp.content:
                if hasattr(block, "text"):
                    final += block.text
            self.history.append({"role": "assistant", "content": resp.content})
            break

        return final

    def _load_existing_workspace(self, name: str) -> str:
        """Read any existing recon files from the machine workspace and return a summary."""
        machine_dir = Path(self.work_dir).expanduser() / name
        if not machine_dir.exists():
            return ""

        parts: list[str] = ["EXISTING WORKSPACE FILES FOUND — read these before running any scans:\n"]

        nmap_targeted = machine_dir / "nmap" / "targeted"
        nmap_allports = machine_dir / "nmap" / "allPorts"

        if nmap_targeted.exists() and nmap_targeted.stat().st_size > 0:
            content = nmap_targeted.read_text()
            parts.append(f"--- nmap/targeted (service scan) ---\n{content[:6000]}")

        if nmap_allports.exists() and nmap_allports.stat().st_size > 0:
            content = nmap_allports.read_text()
            parts.append(f"--- nmap/allPorts (grepable) ---\n{content[:2000]}")

        for subdir in ("exploits", "content"):
            d = machine_dir / subdir
            if d.exists():
                files = [f for f in d.iterdir() if f.is_file()]
                if files:
                    parts.append(f"--- {subdir}/ ---")
                    for f in files[:10]:
                        parts.append(f"  {f.name} ({f.stat().st_size} bytes)")
                        if f.suffix in (".txt", ".md", ".py", ".sh", ".xml", "") and f.stat().st_size < 4000:
                            parts.append(f.read_text(errors="replace"))

        if len(parts) == 1:
            return ""

        parts.append("\nDo NOT re-run scans for data already present above. Use htb_recon only if the nmap files are missing.\n")
        return "\n".join(parts)

    def start_machine(self, name: str, ip: str, os_hint: str = "", screenshot: Optional[str] = None, mode: str = "full", difficulty: str = "Easy") -> str:
        self.machine_context = {"name": name, "ip": ip, "os": os_hint, "mode": mode, "difficulty": difficulty}
        diff_hint = _DIFFICULTY_HINTS.get(difficulty, _DIFFICULTY_HINTS["Easy"])
        existing = self._load_existing_workspace(name)
        header = (
            f"TARGET: {name} | IP: {ip}"
            + (f" | OS: {os_hint}" if os_hint else "")
            + f"\nWorkspace: {self.work_dir}/{name}\n"
            f"{diff_hint}\n\n"
            + (existing + "\n" if existing else "")
        )
        if mode == "recon":
            self._active_system_prompt = SYSTEM_PROMPT
            msg = (
                header
                + "RECON-ONLY MODE — do NOT attempt exploitation.\n"
                "Steps (in order):\n"
                "1. Search the knowledge base for techniques relevant to this target/OS and difficulty\n"
                "2. Run htb_recon (port scan)\n"
                "3. For every HTTP/HTTPS port found, run web_fingerprint\n"
                "4. For every identified service version, run search_exploit to map CVEs/public exploits\n"
                "5. Produce a structured recon report covering open ports, technologies, and exploit candidates\n"
                "Stop after the report — no exploitation steps."
            )
        elif mode == "guided":
            self._active_system_prompt = GUIDED_SYSTEM_PROMPT
            msg = (
                header
                + "GUIDED MENTOR MODE — run the complete Phase 1 recon workflow autonomously "
                "(knowledge base search → htb_recon → web_fingerprint → web_enum → subdomain_enum if applicable → "
                "smb_enum if 139/445 open → searchsploit for each service version). "
                "When all recon is complete, present a structured findings report and suggest 2-3 specific attack "
                "vectors for the user to attempt themselves, with exact commands and explanations. "
                "Do not attempt exploitation — stop there and wait for the user."
            )
        else:
            self._active_system_prompt = SYSTEM_PROMPT
            msg = (
                header
                + "Search the knowledge base for relevant techniques and past machines at this difficulty, "
                "then run htb_recon to start reconnaissance."
            )
        return self.chat(msg, image_path=screenshot)

    def generate_readme(self) -> str:
        name = self.machine_context.get("name", "Machine")
        prompt = (
            f"Based on your recon findings above, generate a README.md for the {name} machine folder. "
            "Output ONLY the raw markdown — no explanation, no code fences. Use these sections:\n"
            f"# {name}\n"
            "## Target Info\n"
            "## Open Ports & Services\n"
            "## Technologies Identified\n"
            "## CVEs / Public Exploits\n"
            "## Attack Surface Summary\n"
            "Keep it concise and factual."
        )
        return self.chat(prompt)

    def get_resume_summary(self) -> dict:
        """Extract a session summary from local state — no API call."""
        ctx = self.machine_context
        turns = len([m for m in self.history if m["role"] == "assistant"])

        # Pull the last assistant text block
        last_text = ""
        for msg in reversed(self.history):
            if msg["role"] != "assistant":
                continue
            content = msg["content"]
            blocks = content if isinstance(content, list) else [{"type": "text", "text": str(content)}]
            for block in blocks:
                text = block.get("text", "") if isinstance(block, dict) else getattr(block, "text", "")
                if text and text.strip():
                    last_text = text.strip()[:400]
                    break
            if last_text:
                break

        cred_services = list({c["service"] for c in self.credentials if c.get("service")})

        return {
            "name":         ctx.get("name", ""),
            "ip":           ctx.get("ip", ""),
            "os":           ctx.get("os", ""),
            "difficulty":   ctx.get("difficulty", ""),
            "ports":        ctx.get("ports", ""),
            "turns":        turns,
            "cred_count":   len(self.credentials),
            "cred_services": cred_services,
            "last_text":    last_text,
            "tok_in":       self.session_input_tokens,
            "tok_out":      self.session_output_tokens,
        }

    def index_session(self) -> bool:
        """Index this session into the vector store for cross-session recall."""
        ctx = self.machine_context
        name = ctx.get("name", "")
        if not name or not self.history:
            return False

        ip         = ctx.get("ip", "")
        os_hint    = ctx.get("os", "")
        difficulty = ctx.get("difficulty", "")
        ports      = ctx.get("ports", "")

        # Prefer the README on disk; fall back to last assistant message
        readme_path = Path(self.work_dir).expanduser() / name / "README.md"
        if readme_path.exists():
            body = readme_path.read_text()[:4000]
        else:
            body = ""
            for msg in reversed(self.history):
                if msg["role"] != "assistant":
                    continue
                content = msg["content"]
                blocks = content if isinstance(content, list) else [{"type": "text", "text": str(content)}]
                for block in blocks:
                    text = block.get("text", "") if isinstance(block, dict) else getattr(block, "text", "")
                    if text and len(text) > 100:
                        body = text[:4000]
                        break
                if body:
                    break

        cred_services = list({c["service"] for c in self.credentials if c.get("service")})

        doc = (
            f"# HTB Session: {name}\n"
            f"Machine: {name} | IP: {ip} | OS: {os_hint} | Difficulty: {difficulty}\n"
            f"Open ports: {ports}\n"
            + (f"Authenticated services: {', '.join(cred_services)}\n" if cred_services else "")
            + f"\n{body}"
        )

        self.rag.add_document(
            doc_id=f"session_{name.lower()}",
            content=doc,
            metadata={
                "source":     "session",
                "title":      f"HTB {name} ({difficulty})",
                "machine":    name,
                "ip":         ip,
                "os":         os_hint,
                "difficulty": difficulty,
                "ports":      ports,
            },
        )
        return True

    def reset(self):
        self.history = []
        self.machine_context = {}
        self.credentials = []
        self._active_system_prompt = SYSTEM_PROMPT
        self.session_input_tokens = 0
        self.session_output_tokens = 0
        self.session_cache_read_tokens = 0

    # ── Session persistence ────────────────────────────────

    def _serialize_history(self) -> list[dict]:
        result = []
        for msg in self.history:
            content = msg["content"]
            if isinstance(content, list):
                serialized = []
                for block in content:
                    if hasattr(block, "model_dump"):
                        serialized.append(block.model_dump())
                    elif isinstance(block, dict):
                        serialized.append(block)
                    else:
                        serialized.append({"type": "text", "text": str(block)})
                result.append({"role": msg["role"], "content": serialized})
            else:
                result.append(msg)
        return result

    def save_session(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        data = {
            "machine_context": self.machine_context,
            "history": self._serialize_history(),
            "credentials": self.credentials,
            "session_input_tokens": self.session_input_tokens,
            "session_output_tokens": self.session_output_tokens,
            "session_cache_read_tokens": self.session_cache_read_tokens,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load_session(self, path: str) -> bool:
        try:
            with open(path) as f:
                data = json.load(f)
            self.history = data["history"]
            self.machine_context = data["machine_context"]
            self.credentials = data.get("credentials", [])
            self.session_input_tokens = data.get("session_input_tokens", 0)
            self.session_output_tokens = data.get("session_output_tokens", 0)
            self.session_cache_read_tokens = data.get("session_cache_read_tokens", 0)
            return True
        except (FileNotFoundError, KeyError, json.JSONDecodeError):
            return False
