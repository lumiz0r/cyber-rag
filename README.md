# CYBER-RAG

AI-powered pentesting and binary exploitation assistant for HackTheBox and CTF challenges. Combines your personal Notion notes with Claude Sonnet and a full live toolchain to guide you through machine exploitation and pwn challenges step by step.

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

1. **Knowledge base** — your Notion notes are synced and indexed into a local ChromaDB vector store using Ollama embeddings (`nomic-embed-text`). Retrieval uses BM25 + semantic hybrid scoring so keyword-exact matches (CVE numbers, tool names) rank alongside conceptual matches. Past machine sessions are also indexed, so findings from previous machines inform new ones automatically.

2. **Agent** — Claude Sonnet acts as the brain. It runs recon autonomously, searches your notes, calls tools in a loop, manages a credential vault, and updates `/etc/hosts` when new domains are discovered. Independent tool calls (e.g. `web_fingerprint` + `search_exploit` for different services) are dispatched in parallel — up to 4 concurrent workers — and streamed to the terminal as they arrive.

3. **Tools** — wrappers around your pentesting and RE/pwn toolchain the agent can invoke without manual typing. Results feed back into the agent's context for reasoning.

---

## Architecture

```
main.py          — terminal UI (Rich), menu routing, mode entry points
config.py        — config management (~/.config/htb-rag/config.json)
notion_client.py — Notion REST API: paginated page fetch + block text extraction
rag_engine.py    — ChromaDB + BM25 hybrid retrieval, Ollama embedding function
agent.py         — Claude agent with agentic tool-use loop, streaming, cost tracking
scanner.py       — shell wrappers: htb_recon, web/SMB/UDP tools, full RE/pwn suite
```

Config is stored at `~/.config/htb-rag/config.json`. Machine workspaces land in `~/Desktop/Hackthebox/Machines/<name>/`.

---

## Installation

**Requirements:** Python 3.11+, Ollama running locally with `nomic-embed-text` pulled.

```bash
git clone https://github.com/lumiz0r/cyber-rag
cd cyber-rag

pip install -r requirements.txt --break-system-packages

ollama pull nomic-embed-text
```

**Pentesting tools** (Arch / BlackArch):
```bash
sudo pacman -S nmap feroxbuster wfuzz whatweb enum4linux smbclient nikto exploitdb
```

**RE/pwn tools** (Arch / BlackArch):
```bash
sudo pacman -S radare2 gdb ltrace strace binutils pwntools ROPgadget ropper
gem install one_gadget          # requires ruby

# pwndbg (GDB extension)
git clone https://github.com/pwndbg/pwndbg ~/pwndbg
cd ~/pwndbg && sudo ./setup.sh
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

After that, **sync your Notion notes** (option 4 in the main menu) before starting machines.

---

## Modes

### [1] Machine Mode

Provide machine name, IP, OS hint, and difficulty. Three sub-modes:

| Sub-mode | Behaviour |
|---|---|
| **Guided** (default) | Full autonomous recon → structured findings report → drops into interactive mentor chat. Agent suggests attack vectors with exact commands; you execute and report back. |
| **Recon Only** | Port scan + fingerprint + CVE mapping + README. No exploitation. |
| **Full Auto** | Autonomous recon and exploitation attempts without hand-holding. |

Difficulty (Easy / Medium / Hard / Insane) adjusts the agent's strategy:
- **Easy** — targets obvious vectors first, pivots quickly if stuck
- **Medium** — deeper enumeration, credential reuse, 1-2 lateral steps expected
- **Hard / Insane** — extended thinking mode enabled (Claude reasons before acting), complex chains are expected

#### Chat commands inside a machine session

```
creds           show credential vault
hosts           show /etc/hosts entries for this machine IP
reset           clear conversation and delete session file
back            save + index session, return to menu
img:<path> msg  attach a screenshot to your next message
```

---

### [2] Binary Mode

Dedicated reverse engineering and binary exploitation workflow. Provide the binary path, challenge name, optional libc, optional remote host/port, and difficulty.

The agent follows a mandatory methodology:

1. `analyze_binary` + `rag_search` in parallel — static survey + notes lookup
2. `run_r2 'aaa; afl'` — list all functions
3. `disassemble` — inspect key functions
4. `trace_binary` — observe runtime behaviour (ltrace / strace)
5. Identify vulnerability class (BOF, format string, heap, strcmp sidechannel…)
6. `cyclic_pattern` + `debug_gdb` — find exact RIP/EIP offset
7. `find_gadgets` / `find_one_gadget` — build ROP chain
8. Generate a complete, runnable **pwntools exploit script**
9. Test locally, adapt for remote

#### Chat commands inside a binary session

```
context         show current binary profile (arch, protections, offset, libc, remote)
reset           clear conversation and delete session file
back            save session, return to menu
```

---

### [3] Query Mode

Direct RAG-assisted chat with the agent — no active machine or binary. Use for general technique lookups, payload generation, or anything not tied to a session.

### [4] Sync Notion

Fetches all pages your integration can access, embeds them (hybrid BM25 + semantic), and upserts into ChromaDB. Safe to re-run.

### [5] KB Status

Shows vector store statistics: total chunks, last sync time, top sources.

### [6] Tools

Shows all available tools split by mode — pentesting tools with install status, RE/pwn tools with install status.

### [7] Settings

Edit API keys, model, work directory, auto-confirm toggle.

---

## Recon workflow (Machine Mode)

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

For every HTTP/HTTPS port found, the agent then runs (in parallel):
- `web_fingerprint` — technology identification
- `web_enum` — directory brute-force (feroxbuster preferred)
- `subdomain_enum` — vhost fuzzing via wfuzz
- `add_hosts_entry` — adds discovered domains to `/etc/hosts` automatically

---

## Pentesting tools

| Tool | What it does |
|---|---|
| `rag_search` | Hybrid BM25 + semantic search over Notion notes + past machine sessions |
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
| `nikto_scan` | Nikto web vulnerability scanner |
| `privesc_enum` | Upload + run linPEAS/winPEAS via SSH on a compromised target |

## RE / Pwn tools (Binary Mode)

| Tool | What it does |
|---|---|
| `analyze_binary` | file + checksec + readelf + nm + strings — always run first |
| `disassemble` | Disassemble a function via radare2 (or objdump fallback) |
| `run_r2` | Batch radare2 commands (`aaa; afl`, `pdf @ sym.main`, `axt sym.imp.system`…) |
| `find_gadgets` | ROP gadget search via ROPgadget or ropper, with optional grep filter |
| `find_one_gadget` | Magic execve gadgets in libc via one_gadget |
| `trace_binary` | ltrace (library calls) or strace (syscalls) |
| `debug_gdb` | GDB batch mode — find offsets, inspect registers/stack, check canary |
| `cyclic_pattern` | Generate de Bruijn pattern or find BOF offset from a crash register value |
| `decompile_func` | Ghidra headless decompilation to C pseudocode |
| `search_exploit` | Exploit-DB search via searchsploit |

---

## Session features

**Streaming output** — Claude's response streams to the terminal token by token. You see reasoning as it happens rather than waiting for a full response.

**Live tool feedback** — after 8 seconds of a running tool, a heartbeat ticker shows elapsed time (`⟳ nmap running… 42s`). Fast tools are silent; slow ones (nmap, feroxbuster, linpeas) keep you informed.

**Parallel tool dispatch** — when Claude calls multiple independent tools in one turn (e.g. `web_fingerprint` + `search_exploit` for three services at once), they run in a `ThreadPoolExecutor` — up to 4 concurrent. Total wait time is the max, not the sum.

**Cost tracking** — after each turn, input/output/cache tokens and USD cost are displayed. Session totals shown on exit.

**Extended thinking** — Hard and Insane machines/challenges automatically enable Claude's extended thinking mode (8 000 budget tokens). The model reasons through complex chains before committing to a plan.

**Auto-save on crash** — session is saved after every tool call, not just when `chat()` returns. Crashing mid-recon loses at most the current in-flight tool.

**Resume summary** — resuming a saved session shows a panel: open ports, turn count, credentials found, token usage, and the last thing the AI said — so you're immediately re-oriented.

**Cross-session memory** — when you exit (`back`), the session is indexed into ChromaDB alongside your Notion notes. Future machines with similar services will surface these findings in RAG search results automatically.

**Credential vault** — `store_credential` is called by the agent whenever it finds a username/password/hash/token. Persisted in the session file. View anytime with `creds`.

**Binary session state** — arch, protections, confirmed BOF offset, libc path, and remote target are tracked in `binary_context` and injected as a compact system block on every API call. State survives history compaction.

---

## Dependency overview

| Component | Library |
|---|---|
| AI agent | `anthropic` (Claude Sonnet 4.6) |
| Embeddings | Ollama HTTP API (`nomic-embed-text`) |
| Vector store | `chromadb` 1.5.x |
| Hybrid retrieval | `rank_bm25` |
| Notion API | `httpx` (direct REST, no SDK) |
| Terminal UI | `rich` |
| Exploit scripting | `pwntools` |

---

## Troubleshooting

**Notion sync finds 0 pages** — the integration isn't shared with any pages. In Notion: open a page → `···` → *Connect to* → select your integration.

**ChromaDB `embed_query` error** — ChromaDB 1.5.x requires `name()` and `embed_query()` on custom embedding functions. Both are implemented in `OllamaEmbeddingFunction`.

**`extractPorts` not found** — it's a zsh function in `~/.zshrc`. The tool sources it via `zsh -c "source ~/.zshrc && extractPorts ..."`. Port parsing falls back to a native Python implementation if it fails.

**400 `Extra inputs are not permitted` on session resume** — caused by older session files where the Anthropic SDK's extra response fields (`citations`, `parsed_output`, `caller`) were serialized into the JSON. Fixed automatically: `load_session()` sanitizes every block on load and `save_session()` now strips extra fields before writing.

**pwndbg not loading in `debug_gdb`** — pwndbg must be installed via `sudo ./setup.sh` in the cloned repo. After setup, GDB will auto-load pwndbg. Verify with `gdb -q -batch -ex "python import pwndbg; print('ok')"`.

**`one_gadget` not found** — install via `gem install one_gadget` (requires ruby). On Arch: `sudo pacman -S ruby` first.
