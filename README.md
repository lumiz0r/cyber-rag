# CYBER-RAG

AI-powered pentesting assistant for HackTheBox and CTF challenges. Combines your personal Notion notes with Claude Sonnet and live security tools to guide you through machine exploitation step by step.

```
  ██████╗██╗   ██╗██████╗ ███████╗██████╗       ██████╗  █████╗  ██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗      ██╔══██╗██╔══██╗██╔════╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╗██████╔╝███████║██║  ███╗
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════╝██╔══██╗██╔══██║██║   ██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║      ██║  ██║██║  ██║╚██████╔╝
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝
```

---

## How it works

Three layers that work together:

1. **Knowledge base** — your Notion notes are synced and indexed into a local ChromaDB vector store using Ollama embeddings (`nomic-embed-text`). Past machine sessions are also indexed, so findings from previous machines inform new ones automatically.

2. **Agent** — Claude Sonnet acts as the brain. It runs recon autonomously, searches your notes, calls tools in a loop, manages a credential vault, and updates `/etc/hosts` when new domains are discovered. You see every tool call as it happens.

3. **Tools** — wrappers around your pentesting toolchain the agent can invoke without manual typing. Results feed back into the agent's context for reasoning.

---

## Architecture

```
main.py          — terminal UI (Rich), menu routing, mode entry points
config.py        — config management (~/.config/htb-rag/config.json)
notion_client.py — Notion REST API: paginated page fetch + block text extraction
rag_engine.py    — ChromaDB collection + custom Ollama embedding function
agent.py         — Claude agent with agentic tool-use loop
scanner.py       — shell wrappers: htb_recon workflow + individual tools
```

Config is stored at `~/.config/htb-rag/config.json`. Machine workspaces land in `~/Desktop/Hackthebox/Machines/<name>/`.

---

## Installation

**Requirements:** Python 3.11+, Ollama running locally with `nomic-embed-text` pulled.

```bash
git clone https://github.com/yourusername/cyber-rag
cd cyber-rag

pip install -r requirements.txt --break-system-packages

ollama pull nomic-embed-text
```

**API keys needed:**
- **Notion integration token** — create at [notion.so/my-integrations](https://www.notion.so/my-integrations), then share each page/database with it
- **Claude API key** — get one at [console.anthropic.com](https://console.anthropic.com)

---

## First run

```bash
python3 main.py
```

On first launch the setup wizard asks for your Notion token and Claude API key. They are saved to `~/.config/htb-rag/config.json`.

After that, **sync your Notion notes** (option 3 in the main menu) before starting machines.

---

## Modes

### Machine Mode (main workflow)

Provide machine name, IP, OS hint, and difficulty. The tool then:

**Guided (default)** — runs full recon autonomously, generates a `README.md` in the machine folder with findings, drops into interactive chat. You explore and exploit; ask the AI when stuck.

**Recon Only** — port scan + fingerprint + CVE mapping + README. No exploitation.

**Full Auto** — autonomous recon and exploitation attempts.

Difficulty (Easy / Medium / Hard / Insane) adjusts the agent's strategy: on Easy it targets obvious vectors first and pivots quickly when stuck; on Hard/Insane it goes deeper before pivoting.

#### Chat commands inside a session

```
creds       show credential vault
hosts       show /etc/hosts entries for this machine IP
reset       clear conversation and delete session file
back        save + index session, return to menu
img:<path> <msg>    attach a screenshot to your next message
```

### Query Mode

Direct chat with the agent, RAG-assisted. For general technique lookups, payload generation, or anything not tied to an active machine.

### Sync Notion

Fetches all pages your integration can access, embeds them, and stores them in ChromaDB. Safe to re-run — existing chunks are upserted.

---

## Recon workflow

`htb_recon` runs these steps automatically — **skips steps whose output files already exist**, so resuming after a crash doesn't re-scan:

```bash
# 1. Create workspace (idempotent)
mkdir -p <machine>/nmap <machine>/content <machine>/exploits

# 2. Full port scan
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv <ip> -oG nmap/allPorts

# 3. Extract open ports (your extractPorts zsh function)
extractPorts nmap/allPorts

# 4. Targeted service scan
nmap -p<ports> -sCV <ip> -oN nmap/targeted
```

For every HTTP/HTTPS port found, the agent then runs:
- `web_fingerprint` — technology identification
- `web_enum` — directory brute-force (feroxbuster preferred)
- `subdomain_enum` — vhost fuzzing via wfuzz
- `add_hosts_entry` — adds discovered domains to `/etc/hosts` automatically

---

## Agent tools

| Tool | What it does |
|---|---|
| `rag_search` | Semantic search over Notion notes + past machine sessions |
| `htb_recon` | Full recon workflow (skips if output already exists) |
| `run_command` | Execute any shell command |
| `web_enum` | Directory brute-force (feroxbuster → gobuster → ffuf → dirsearch) |
| `web_fingerprint` | Technology fingerprinting via whatweb / curl |
| `subdomain_enum` | Vhost fuzzing via wfuzz (Host header) |
| `smb_enum` | SMB enumeration via enum4linux / smbclient |
| `search_exploit` | Exploit-DB search via searchsploit |
| `udp_scan` | UDP port scan |
| `add_hosts_entry` | Append discovered domains to `/etc/hosts` (confirms before writing) |
| `store_credential` | Save found credentials to the session vault |
| `get_credentials` | Retrieve vault contents before attempting auth |

---

## Session features

**Auto-save on crash** — session is saved after every tool call, not just when `chat()` returns. Crashing mid-recon loses at most the current in-flight tool.

**Resume summary** — resuming a saved session shows a panel: open ports, turn count, credentials found, token usage, and the last thing the AI said — so you're immediately re-oriented.

**Cross-session memory** — when you exit (`back`), the session is indexed into ChromaDB alongside your Notion notes. Future machines with similar services will surface these findings in RAG search results automatically.

**Credential vault** — `store_credential` is called by the agent whenever it finds a username/password/hash. Persisted in the session file. View anytime with `creds`.

---

## Dependency overview

| Component | Library |
|---|---|
| AI agent | `anthropic` (Claude Sonnet 4.6) |
| Embeddings | Ollama HTTP API (`nomic-embed-text`) |
| Vector store | `chromadb` 1.5.x |
| Notion API | `httpx` (direct REST, no SDK) |
| Terminal UI | `rich` |

---

## Troubleshooting

**Notion sync finds 0 pages** — the integration isn't shared with any pages. In Notion: open a page → `···` → *Connect to* → select your integration.

**ChromaDB `embed_query` error** — ChromaDB 1.5.x requires `name()` and `embed_query()` on custom embedding functions. Both are implemented in `OllamaEmbeddingFunction`.

**`extractPorts` not found** — it's a zsh function in `~/.zshrc`. The tool sources it via `zsh -c "source ~/.zshrc && extractPorts ..."`. Port parsing falls back to a native Python implementation if it fails.

**Rich markup crash on tool output** — tool output containing `[brackets]` is escaped before printing. If you hit this on an older version, update to current.
