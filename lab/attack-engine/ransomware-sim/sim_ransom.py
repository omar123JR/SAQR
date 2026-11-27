"""SAQR Safe Lab Test Generator (Windows 10 & Linux).

Used ONLY inside the isolated SAQR lab VM (`C:\\SAQR-Test` or `/tmp` or a folder containing
`.saqr_lab_sandbox`) to generate controlled file-modification patterns and benign stress
workloads for evaluating MTTD, MTTC, blast radius, and False Positive Rate (FPR).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import List, Optional


def assert_sandbox(target_dir: Path) -> Path:
    resolved = Path(target_dir).resolve()
    s = str(resolved)
    allowed = (
        s.lower().startswith(r"c:\saqr-test")
        or s.startswith("/tmp/")
        or s.startswith("/var/tmp/")
        or (resolved / ".saqr_lab_sandbox").exists()
    )
    if not allowed:
        raise PermissionError(
            f"SAFETY BLOCK: '{resolved}' is outside C:\\SAQR-Test and /tmp and has no .saqr_lab_sandbox marker."
        )
    return resolved


def seed_test_files(target_dir: Path, count: int = 30) -> List[Path]:
    root = assert_sandbox(target_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / ".saqr_lab_sandbox").write_text("saqr-isolated-lab\n", encoding="utf-8")
    files: List[Path] = []
    for i in range(count):
        if i % 3 == 0:
            p = root / f"report_{i:02d}.txt"
            p.write_text(f"SAQR Lab Test Document #{i}\nRoutine finance summary text.\n" * 40, encoding="utf-8")
        elif i % 3 == 1:
            p = root / f"sheet_{i:02d}.csv"
            p.write_text("id,amount,status\n" + "\n".join(f"{j},100.00,OK" for j in range(80)), encoding="utf-8")
        else:
            p = root / f"contract_{i:02d}.docx"
            with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("word/document.xml", f"<doc>Contract #{i} " + ("Clause text. " * 100) + "</doc>")
        files.append(p)
    return files


def run_test_mode(
    target_dir: Path,
    mode: str = "fast",
    delay_ms: float = 50.0,
    smb_target: Optional[Path] = None,
) -> dict:
    root = assert_sandbox(target_dir)
    files = sorted(p for p in root.iterdir() if p.is_file() and p.name != ".saqr_lab_sandbox")
    touched = 0

    if mode == "benign":
        # 5 Benign Workloads for realistic False Positive Rate (FPR) evaluation
        zpath = root / "backup_archive.zip"
        with zipfile.ZipFile(zpath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                zf.write(f, arcname=f.name)
        copy_dir = root / "Copied_Docs"
        copy_dir.mkdir(exist_ok=True)
        for f in files[:10]:
            shutil.copy2(f, copy_dir / f.name)
        for f in files[10:18]:
            f.rename(f.with_name(f"2026_{f.name}"))
        git_dir = root / ".git" / "objects"
        git_dir.mkdir(parents=True, exist_ok=True)
        for i in range(15):
            (git_dir / f"obj_{i:02d}").write_bytes(b"BENIGN_GIT_OBJECT" * 64)
        for f in sorted(root.glob("*.txt"))[:5]:
            f.write_text(f.read_text(encoding="utf-8") + "\nApproved.\n", encoding="utf-8")
        return {"mode": "benign", "ops": len(files) + 25}

    # Optional non-destructive Windows shadow-query telemetry check in fast mode (logs Sysmon EID 1)
    if mode == "fast" and sys.platform == "win32":
        try:
            subprocess.run(
                ["vssadmin.exe", "list", "shadows"],
                capture_output=True,
                timeout=3,
                check=False,
            )
        except OSError:
            pass

    for f in files:
        if mode == "fast":
            f.write_bytes(secrets.token_bytes(4096))
            f.rename(f.with_name(f.name + ".locked"))
        elif mode == "shadowless":
            f.write_bytes(secrets.token_bytes(4096))
            f.rename(f.with_name(f.name + ".saqrlock"))
        elif mode == "inplace":
            f.write_bytes(secrets.token_bytes(4096))
        else:
            raise ValueError(f"Unsupported mode: {mode}")
        touched += 1
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    smb_result = "skipped"
    if smb_target is not None:
        try:
            probe = Path(smb_target) / "lateral_probe.txt"
            probe.write_text("SAQR_LATERAL_PROBE", encoding="utf-8")
            smb_result = "reachable_unblocked"
        except OSError as exc:
            smb_result = f"blocked:{exc}"

    return {"mode": mode, "touched": touched, "pid": os.getpid(), "smb_probe": smb_result}


def main() -> int:
    parser = argparse.ArgumentParser(description="SAQR Isolated Lab Test Generator")
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--mode", choices=["seed", "fast", "shadowless", "inplace", "benign"], default="fast")
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--delay-ms", type=float, default=50.0)
    parser.add_argument("--smb-target", default=None)
    args = parser.parse_args()

    if args.mode == "seed":
        seeded = seed_test_files(Path(args.target_dir), count=args.count)
        print(json.dumps({"seeded": len(seeded), "dir": args.target_dir}))
        return 0

    res = run_test_mode(
        Path(args.target_dir),
        mode=args.mode,
        delay_ms=args.delay_ms,
        smb_target=Path(args.smb_target) if args.smb_target else None,
    )
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
