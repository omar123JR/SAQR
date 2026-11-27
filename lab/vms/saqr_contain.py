#!/usr/bin/env python3
"""SAQR Windows Active Response — Race-Free Containment & Forensics (saqr_contain.py).

Dispatched by Wazuh Manager v4.14.11 via `PUT /active-response` (command: `saqr-contain`)
over the encrypted TCP/1514 channel, or executed directly via CLI for local testing.

Implements the exact 5-step race-free containment order:
  1. Wrong-PID Resolution + Critical-Process Denylist
     (redirects vssadmin/wmic/wbadmin/bcdedit triggers to parentProcessId;
      refuses System, lsass.exe, csrss.exe, wininit.exe, services.exe,
      svchost.exe, explorer.exe, wazuh-agent.exe, Sysmon64.exe, PID <= 4)
  2. Immediate Process Tree Freeze (Win32 ctypes ntdll!NtSuspendProcess)
     — halts encryption in milliseconds BEFORE volatile RAM is touched.
  3. IP + Port-Scoped Windows Firewall Quarantine (Group: "SAQR-Quarantine")
     — allows ONLY Wazuh Manager (TCP 1514, 1515) & SAQR Engine (TCP 5000),
       blocks all other inbound/outbound traffic, and severs SMB shares (`net use * /delete /y`).
  4. Forensic Memory Dump + Streaming SHA-256 + Chain-of-Custody Upload
     — dumps frozen root PID to C:\\ProgramData\\SAQR\\Vault via native Win32
       dbghelp!MiniDumpWriteDump (with procdump64.exe fallback), hashes with SHA-256,
       and streams to POST /api/v1/evidence/{incident_id}.
  5. Terminate Frozen Process Tree + Engine Callback + JSON Audit Log + Exit 0.

Dependencies: Python 3.12 standard library ONLY (ctypes Win32 on Windows).
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Short-lived Windows recovery utilities often spawned by ransomware (T1490).
# Freezing/killing vssadmin.exe alone leaves the parent ransomware alive!
UTILITY_TRIGGERS: frozenset[str] = frozenset({
    "vssadmin.exe",
    "wmic.exe",
    "wbadmin.exe",
    "bcdedit.exe",
})

# Immutable safety denylist — SAQR will NEVER freeze or kill these processes.
CRITICAL_PROCESS_DENYLIST: frozenset[str] = frozenset({
    "system",
    "system idle process",
    "idle",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "explorer.exe",
    "wazuh-agent.exe",
    "wazuh-execd.exe",
    "sysmon64.exe",
    "sysmon.exe",
})

FIREWALL_GROUP = "SAQR-Quarantine"
DEFAULT_VAULT_DIR = Path(r"C:\ProgramData\SAQR\Vault") if sys.platform == "win32" else Path("/tmp/saqr_rework/vault")
DEFAULT_AR_LOG = (
    Path(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log")
    if sys.platform == "win32"
    else Path("/tmp/saqr_rework/active-responses.log")
)

# Win32 access flags & constants
PROCESS_TERMINATE = 0x0001
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800
TH32CS_SNAPPROCESS = 0x00000002
MINI_DUMP_WITH_FULL_MEMORY = 0x00000002
GENERIC_WRITE = 0x40000000
CREATE_ALWAYS = 2
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def normalize_process_name(name_or_path: str) -> str:
    """Extract lowercase executable basename from Windows or POSIX path."""
    cleaned = (name_or_path or "").strip().strip('"').replace("\\", "/")
    return cleaned.rsplit("/", 1)[-1].lower() if cleaned else ""


def is_protected_process(
    pid: int,
    process_name: str = "",
    self_pids: Optional[Set[int]] = None,
) -> bool:
    """Return True if a PID is protected and MUST NOT be suspended or killed."""
    if pid <= 4:
        return True
    protected_ids = self_pids if self_pids is not None else {os.getpid(), os.getppid()}
    if pid in protected_ids:
        return True
    norm_name = normalize_process_name(process_name)
    return norm_name in CRITICAL_PROCESS_DENYLIST


def snapshot_processes() -> Dict[int, Dict[str, Any]]:
    """Capture a lightweight {pid: {'name': str, 'ppid': int}} table using stdlib/ctypes."""
    if sys.platform == "win32":
        return _snapshot_processes_windows()
    return _snapshot_processes_linux()


def _snapshot_processes_linux() -> Dict[int, Dict[str, Any]]:
    """Parse /proc/<pid>/stat on Linux (used for cross-platform testing)."""
    procs: Dict[int, Dict[str, Any]] = {}
    proc_root = Path("/proc")
    if not proc_root.exists():
        return procs
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            stat_text = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            lpar = stat_text.find("(")
            rpar = stat_text.rfind(")")
            if lpar == -1 or rpar == -1:
                continue
            comm = stat_text[lpar + 1 : rpar]
            fields = stat_text[rpar + 2 :].split()
            ppid = int(fields[1]) if len(fields) >= 2 else 0
            procs[pid] = {"name": comm, "ppid": ppid}
        except OSError:
            continue
    return procs


def _snapshot_processes_windows() -> Dict[int, Dict[str, Any]]:
    """Enumerate running processes on Windows via kernel32!CreateToolhelp32Snapshot."""
    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_uint32),
            ("cntUsage", ctypes.c_uint32),
            ("th32ProcessID", ctypes.c_uint32),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_uint32),
            ("cntThreads", ctypes.c_uint32),
            ("th32ParentProcessID", ctypes.c_uint32),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_uint32),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return {}

    procs: Dict[int, Dict[str, Any]] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                procs[int(entry.th32ProcessID)] = {
                    "name": str(entry.szExeFile),
                    "ppid": int(entry.th32ParentProcessID),
                }
                if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    return procs


def resolve_target_pid(
    target_pid: int,
    parent_pid: int,
    process_image: str,
    snapshot: Dict[int, Dict[str, Any]],
    self_pids: Optional[Set[int]] = None,
) -> Tuple[Optional[int], str]:
    """Step 1: Resolve utility child triggers to parent PID and enforce denylist.

    Returns (resolved_pid_or_None, human_readable_reason).
    """
    info = snapshot.get(target_pid, {})
    target_name = normalize_process_name(process_image or info.get("name", ""))

    chosen_pid = target_pid
    chosen_name = target_name
    note = f"target_pid={target_pid} ({target_name or 'unknown'})"

    # Wrong-PID Fix: if rule 100202 fired on vssadmin/wmic/wbadmin/bcdedit, pivot to parent!
    if target_name in UTILITY_TRIGGERS:
        effective_parent = parent_pid if parent_pid > 4 else int(info.get("ppid", 0))
        parent_info = snapshot.get(effective_parent, {})
        parent_name = normalize_process_name(parent_info.get("name", ""))
        if effective_parent > 4 and not is_protected_process(effective_parent, parent_name, self_pids=self_pids):
            chosen_pid = effective_parent
            chosen_name = parent_name
            note = (
                f"wrong_pid_resolved:{target_name}(pid={target_pid})"
                f"->parent_pid={effective_parent}({parent_name or 'unknown'})"
            )
        else:
            return None, (
                f"refused_utility_parent_protected:trigger={target_name}(pid={target_pid}),"
                f"parent_pid={effective_parent}({parent_name or 'unknown'})"
            )

    if chosen_pid <= 0:
        return None, "no_valid_target_pid"

    if is_protected_process(chosen_pid, chosen_name, self_pids=self_pids):
        return None, f"refused_critical_process:pid={chosen_pid}({chosen_name or 'protected'})"

    return chosen_pid, note


def collect_process_tree(
    root_pid: int,
    snapshot: Dict[int, Dict[str, Any]],
    self_pids: Optional[Set[int]] = None,
) -> List[int]:
    """Return root_pid followed by all non-protected descendant PIDs (BFS order)."""
    children_map: Dict[int, List[int]] = {}
    for pid, meta in snapshot.items():
        ppid = int(meta.get("ppid", 0))
        children_map.setdefault(ppid, []).append(pid)

    ordered: List[int] = []
    queue: List[int] = [root_pid]
    seen: Set[int] = set()

    while queue:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        proc_name = snapshot.get(current, {}).get("name", "")
        if is_protected_process(current, proc_name, self_pids=self_pids):
            continue
        ordered.append(current)
        for child_pid in sorted(children_map.get(current, [])):
            if child_pid not in seen:
                queue.append(child_pid)
    return ordered


def freeze_process_tree(pids: Sequence[int], dry_run: bool = False) -> Tuple[List[int], List[str]]:
    """Step 2: Immediately suspend every PID in the target process tree."""
    frozen: List[int] = []
    notes: List[str] = []
    if not pids:
        return frozen, notes

    if dry_run or sys.platform != "win32":
        frozen.extend(pids)
        notes.append(f"freeze_tree_dry_run:{list(pids)}")
        return frozen, notes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    for pid in pids:
        handle = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, int(pid))
        if not handle:
            notes.append(f"freeze_open_failed:pid={pid}:err={ctypes.get_last_error()}")
            continue
        try:
            status = ntdll.NtSuspendProcess(handle)
            if status == 0:
                frozen.append(int(pid))
            else:
                notes.append(f"freeze_ntstatus_failed:pid={pid}:status={status:#x}")
        finally:
            kernel32.CloseHandle(handle)

    notes.append(f"freeze_tree_ok:{frozen}")
    return frozen, notes


def validate_ip(raw_ip: str) -> str:
    """Strictly validate an IPv4/IPv6 literal to prevent PowerShell command injection."""
    return str(ipaddress.ip_address(raw_ip.strip()))


def resolve_host_ip(host_or_url: str, fallback: str = "") -> str:
    """Extract and validate an IP literal from a URL or IP string."""
    candidate = (host_or_url or "").strip()
    if "://" in candidate:
        parsed = urllib.parse.urlparse(candidate)
        candidate = parsed.hostname or ""
    if not candidate:
        candidate = fallback.strip()
    try:
        return validate_ip(candidate)
    except ValueError:
        if candidate:
            try:
                return validate_ip(socket.gethostbyname(candidate))
            except OSError:
                pass
    raise ValueError(f"Unable to resolve valid IP address from {host_or_url!r}")


def build_quarantine_commands(wazuh_ip: str, engine_ip: str) -> List[List[str]]:
    """Build injection-safe PowerShell & net.exe argv lists for Step 3 quarantine."""
    safe_wazuh = validate_ip(wazuh_ip)
    safe_engine = validate_ip(engine_ip)

    ps_script = (
        f"Remove-NetFirewallRule -Group '{FIREWALL_GROUP}' -ErrorAction SilentlyContinue; "
        f"New-NetFirewallRule -DisplayName 'SAQR Allow Wazuh 1514-1515' -Group '{FIREWALL_GROUP}' "
        f"-Direction Outbound -Action Allow -Protocol TCP -RemoteAddress '{safe_wazuh}' -RemotePort 1514,1515 | Out-Null; "
        f"New-NetFirewallRule -DisplayName 'SAQR Allow Engine 5000' -Group '{FIREWALL_GROUP}' "
        f"-Direction Outbound -Action Allow -Protocol TCP -RemoteAddress '{safe_engine}' -RemotePort 5000 | Out-Null; "
        f"Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block"
    )
    return [
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        ["net.exe", "use", "*", "/delete", "/y"],
    ]


def apply_firewall_quarantine(
    wazuh_ip: str,
    engine_ip: str,
    dry_run: bool = False,
) -> Tuple[bool, List[str]]:
    """Step 3: Apply IP+port-scoped Windows Firewall quarantine and drop SMB shares."""
    commands = build_quarantine_commands(wazuh_ip, engine_ip)
    if dry_run or sys.platform != "win32":
        return True, [f"quarantine_dry_run:wazuh={wazuh_ip},engine={engine_ip},smb_dropped=true"]

    notes: List[str] = []
    fw_ok = False
    for idx, argv in enumerate(commands):
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
        if idx == 0:
            fw_ok = proc.returncode == 0
            notes.append(f"firewall_quarantine:{'ok' if fw_ok else f'rc={proc.returncode}'}")
        else:
            # `net use * /delete /y` returns non-zero when no shares are mapped; both are safe.
            notes.append(f"smb_disconnect:rc={proc.returncode}")
    return fw_ok, notes


def safe_vault_path(vault_dir: Path, incident_id: str, pid: int) -> Path:
    """Construct a traversal-safe dump path strictly inside vault_dir."""
    vault_resolved = vault_dir.resolve()
    vault_resolved.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", incident_id).strip("._") or "incident"
    candidate = (vault_resolved / f"{safe_id}_pid{int(pid)}.dmp").resolve()
    if not candidate.is_relative_to(vault_resolved):
        raise ValueError(f"Path traversal blocked for dump target: {candidate}")
    return candidate


def sha256_file(path: Path) -> str:
    """Compute streaming SHA-256 digest of a file in 64 KiB chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def _minidump_windows(pid: int, dump_path: Path) -> bool:
    """Capture full-memory dump using native Win32 dbghelp!MiniDumpWriteDump."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

    proc_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not proc_handle:
        return False

    file_handle = kernel32.CreateFileW(
        str(dump_path),
        GENERIC_WRITE,
        0,
        None,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if file_handle == INVALID_HANDLE_VALUE:
        kernel32.CloseHandle(proc_handle)
        return False

    try:
        ok = bool(
            dbghelp.MiniDumpWriteDump(
                proc_handle,
                ctypes.c_uint32(int(pid)),
                file_handle,
                ctypes.c_uint32(MINI_DUMP_WITH_FULL_MEMORY),
                None,
                None,
                None,
            )
        )
        return ok
    finally:
        kernel32.CloseHandle(file_handle)
        kernel32.CloseHandle(proc_handle)


def _procdump_fallback(pid: int, dump_path: Path) -> bool:
    """Fallback memory dump via procdump64.exe if MiniDumpWriteDump fails."""
    candidates = [
        Path(r"C:\ProgramData\SAQR\Tools\procdump64.exe"),
        Path(r"C:\Sysinternals\procdump64.exe"),
    ]
    exe = next((str(p) for p in candidates if p.exists()), shutil.which("procdump64.exe"))
    if not exe:
        return False
    proc = subprocess.run(
        [exe, "-accepteula", "-ma", str(int(pid)), str(dump_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return proc.returncode == 0 and dump_path.exists() and dump_path.stat().st_size > 0


def capture_memory_dump(
    pid: int,
    incident_id: str,
    vault_dir: Path,
    dry_run: bool = False,
) -> Tuple[Optional[Path], Optional[str], str]:
    """Step 4a: Capture volatile RAM dump of frozen process and compute SHA-256."""
    dump_path = safe_vault_path(vault_dir, incident_id, pid)

    if dry_run or sys.platform != "win32":
        payload = f"SAQR-DRY-RUN-MEMDUMP incident={incident_id} pid={pid} utc={utc_now_iso()}\n".encode("utf-8")
        dump_path.write_bytes(payload)
        return dump_path, sha256_file(dump_path), "dump_dry_run_ok"

    if _minidump_windows(pid, dump_path) and dump_path.exists() and dump_path.stat().st_size > 0:
        return dump_path, sha256_file(dump_path), "dump_minidump_ok"

    if _procdump_fallback(pid, dump_path):
        return dump_path, sha256_file(dump_path), "dump_procdump_fallback_ok"

    return None, None, "dump_failed"


def stream_upload_evidence(
    engine_url: str,
    incident_id: str,
    agent_id: str,
    upload_token: str,
    dump_path: Path,
    dump_sha256: str,
    timeout: float = 30.0,
) -> Tuple[bool, str]:
    """Step 4b: Stream forensic dump to SAQR Engine with chain-of-custody headers."""
    parsed = urllib.parse.urlparse(engine_url.rstrip("/"))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False, f"upload_invalid_url:{engine_url}"

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    path = f"/api/v1/evidence/{urllib.parse.quote(incident_id, safe='')}"
    size_bytes = dump_path.stat().st_size

    headers = {
        "Authorization": f"Bearer {upload_token}",
        "X-SAQR-Agent-ID": agent_id,
        "X-SAQR-SHA256": dump_sha256,
        "X-SAQR-Filename": dump_path.name,
        "Content-Type": "application/octet-stream",
        "Content-Length": str(size_bytes),
    }

    conn = conn_cls(parsed.hostname, port, timeout=timeout)
    try:
        conn.putrequest("POST", path)
        for key, value in headers.items():
            conn.putheader(key, value)
        conn.endheaders()
        with dump_path.open("rb") as fh:
            while chunk := fh.read(65536):
                conn.send(chunk)
        resp = conn.getresponse()
        _ = resp.read()
        ok = 200 <= resp.status < 300
        return ok, f"evidence_upload:http_{resp.status}"
    except OSError as exc:
        return False, f"evidence_upload_error:{type(exc).__name__}"
    finally:
        conn.close()


def terminate_process_tree(pids: Sequence[int], dry_run: bool = False) -> Tuple[List[int], List[str]]:
    """Step 5a: Terminate frozen process tree (children first, root last)."""
    # Kill children before parent so no watcher respawns siblings mid-teardown
    kill_order = list(reversed(pids))
    killed: List[int] = []
    notes: List[str] = []
    if not kill_order:
        return killed, notes

    if dry_run or sys.platform != "win32":
        killed.extend(kill_order)
        notes.append(f"terminate_dry_run:{kill_order}")
        return killed, notes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for pid in kill_order:
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
        if not handle:
            notes.append(f"terminate_open_failed:pid={pid}:err={ctypes.get_last_error()}")
            continue
        try:
            if kernel32.TerminateProcess(handle, 1):
                killed.append(int(pid))
            else:
                notes.append(f"terminate_failed:pid={pid}:err={ctypes.get_last_error()}")
        finally:
            kernel32.CloseHandle(handle)

    notes.append(f"terminate_ok:{killed}")
    return killed, notes


def post_containment_callback(
    engine_url: str,
    incident_id: str,
    upload_token: str,
    payload: Dict[str, Any],
    timeout: float = 10.0,
) -> Tuple[bool, str]:
    """Step 5b: Report T3/T4 containment telemetry back to SAQR Engine."""
    parsed = urllib.parse.urlparse(engine_url.rstrip("/"))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False, f"callback_invalid_url:{engine_url}"

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    path = f"/api/v1/incidents/{urllib.parse.quote(incident_id, safe='')}/contained"
    body = json.dumps(payload).encode("utf-8")

    conn = conn_cls(parsed.hostname, port, timeout=timeout)
    try:
        conn.request(
            "POST",
            path,
            body=body,
            headers={
                "Authorization": f"Bearer {upload_token}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        resp = conn.getresponse()
        _ = resp.read()
        ok = 200 <= resp.status < 300
        return ok, f"callback:http_{resp.status}"
    except OSError as exc:
        return False, f"callback_error:{type(exc).__name__}"
    finally:
        conn.close()


def append_ar_log(record: Dict[str, Any], log_path: Path = DEFAULT_AR_LOG) -> None:
    """Append a single JSON line to Wazuh active-responses.log."""
    line = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        sys.stderr.write(line)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SAQR Stateless Windows Active Response Containment")
    parser.add_argument("--incident-id", default="", help="SAQR incident ID")
    parser.add_argument("--agent-id", default="001", help="Wazuh agent ID")
    parser.add_argument("--target-pid", type=int, default=0, help="Detected suspicious PID")
    parser.add_argument("--parent-pid", type=int, default=0, help="Detected parent PID")
    parser.add_argument("--process-image", default="", help="Executable path/name from Sysmon")
    parser.add_argument("--upload-token", default="", help="Scoped per-incident bearer token")
    parser.add_argument(
        "--engine-url",
        default=os.getenv("SAQR_ENGINE_URL", "http://192.168.56.1:5000"),
        help="SAQR Engine base URL",
    )
    parser.add_argument(
        "--wazuh-ip",
        default=os.getenv("SAQR_WAZUH_MANAGER_IP", "192.168.56.1"),
        help="Wazuh Manager IP allowed during quarantine (TCP 1514/1515)",
    )
    parser.add_argument(
        "--engine-ip",
        default=os.getenv("SAQR_ENGINE_IP", ""),
        help="SAQR Engine IP allowed during quarantine (TCP 5000)",
    )
    parser.add_argument("--vault-dir", default=os.getenv("SAQR_VAULT_DIR", str(DEFAULT_VAULT_DIR)))
    parser.add_argument("--log-file", default=os.getenv("SAQR_AR_LOG", str(DEFAULT_AR_LOG)))
    parser.add_argument("--dry-run", action="store_true", help="Simulate freeze/quarantine/dump/kill safely")
    parser.add_argument("--skip-network", action="store_true", help="Skip HTTP upload/callback (unit test mode)")
    return parser


def parse_invocation(argv: Sequence[str], stdin_line: Optional[str] = None) -> argparse.Namespace:
    """Parse either CLI arguments or a single Wazuh 4.x Active Response JSON stdin line."""
    parser = build_arg_parser()
    if argv:
        return parser.parse_args(list(argv))

    raw = stdin_line
    if raw is None and not sys.stdin.isatty():
        raw = sys.stdin.readline()

    if not raw or not raw.strip():
        return parser.parse_args([])

    msg = json.loads(raw)
    params = msg.get("parameters", {}) if isinstance(msg, dict) else {}
    extra_args = params.get("extra_args", [])
    if not isinstance(extra_args, list):
        extra_args = []

    ns, _ = parser.parse_known_args([str(x) for x in extra_args])

    # Enrich any missing fields directly from the attached Wazuh alert payload
    alert = params.get("alert", {}) if isinstance(params, dict) else {}
    if isinstance(alert, dict):
        win_ed = alert.get("data", {}).get("win", {}).get("eventdata", {})
        pid_from_alert = False
        if not ns.target_pid and win_ed.get("processId"):
            ns.target_pid = int(win_ed["processId"])
            pid_from_alert = True
        if not ns.parent_pid and win_ed.get("parentProcessId"):
            ns.parent_pid = int(win_ed["parentProcessId"])
        if pid_from_alert and not ns.process_image and win_ed.get("image"):
            ns.process_image = str(win_ed["image"])
        if ns.agent_id == "001" and alert.get("agent", {}).get("id"):
            ns.agent_id = str(alert["agent"]["id"])
        if not ns.incident_id and alert.get("id"):
            ns.incident_id = f"wazuh-{alert['id']}"

    return ns


def run_containment(
    ns: argparse.Namespace,
    process_snapshot: Optional[Dict[int, Dict[str, Any]]] = None,
    self_pids: Optional[Set[int]] = None,
) -> Dict[str, Any]:
    """Execute the full 5-step SAQR containment workflow and return telemetry summary."""
    actions: List[str] = []
    snapshot = process_snapshot if process_snapshot is not None else snapshot_processes()

    # Step 1: Wrong-PID resolution & critical-process denylist
    root_pid, resolve_note = resolve_target_pid(
        target_pid=ns.target_pid,
        parent_pid=ns.parent_pid,
        process_image=ns.process_image,
        snapshot=snapshot,
        self_pids=self_pids,
    )
    actions.append(resolve_note)

    # Step 2: Immediate process tree freeze
    frozen_pids: List[int] = []
    if root_pid is not None:
        tree_pids = collect_process_tree(root_pid, snapshot, self_pids=self_pids)
        frozen_pids, freeze_notes = freeze_process_tree(tree_pids, dry_run=ns.dry_run)
        actions.extend(freeze_notes)

    # Step 3: IP + port-scoped Windows Firewall quarantine + drop SMB shares
    engine_ip = resolve_host_ip(ns.engine_ip or ns.engine_url, fallback=ns.wazuh_ip)
    wazuh_ip = resolve_host_ip(ns.wazuh_ip, fallback=engine_ip)
    quarantined, fw_notes = apply_firewall_quarantine(wazuh_ip, engine_ip, dry_run=ns.dry_run)
    actions.extend(fw_notes)

    # Step 4: Volatile memory dump + SHA-256 + streaming upload
    dump_sha256: Optional[str] = None
    t3_utc: Optional[str] = None
    if root_pid is not None and frozen_pids:
        dump_path, dump_sha256, dump_note = capture_memory_dump(
            pid=root_pid,
            incident_id=ns.incident_id or f"inc-{root_pid}",
            vault_dir=Path(ns.vault_dir),
            dry_run=ns.dry_run,
        )
        actions.append(dump_note)
        t3_utc = utc_now_iso()
        if dump_path and dump_sha256 and not ns.skip_network and ns.upload_token and ns.incident_id:
            _, up_note = stream_upload_evidence(
                engine_url=ns.engine_url,
                incident_id=ns.incident_id,
                agent_id=ns.agent_id,
                upload_token=ns.upload_token,
                dump_path=dump_path,
                dump_sha256=dump_sha256,
            )
            actions.append(up_note)

    # Step 5: Terminate frozen tree + callback + audit log
    killed_pids, kill_notes = terminate_process_tree(frozen_pids, dry_run=ns.dry_run)
    actions.extend(kill_notes)
    t4_utc = utc_now_iso()

    callback_payload: Dict[str, Any] = {
        "agent_id": ns.agent_id,
        "frozen_pids": frozen_pids,
        "killed_pids": killed_pids,
        "quarantined": quarantined,
        "dump_sha256": dump_sha256,
        "t3_utc": t3_utc,
        "t4_utc": t4_utc,
        "actions_taken": actions,
    }

    if not ns.skip_network and ns.upload_token and ns.incident_id:
        _, cb_note = post_containment_callback(
            engine_url=ns.engine_url,
            incident_id=ns.incident_id,
            upload_token=ns.upload_token,
            payload=callback_payload,
        )
        actions.append(cb_note)

    audit_record = {
        "timestamp_utc": t4_utc,
        "command": "saqr-contain",
        "incident_id": ns.incident_id,
        **callback_payload,
    }
    append_ar_log(audit_record, log_path=Path(ns.log_file))
    return audit_record


def main(argv: Sequence[str] | None = None) -> int:
    ns = parse_invocation(list(sys.argv[1:] if argv is None else argv))
    run_containment(ns)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
