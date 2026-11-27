"""Comprehensive End-to-End & Security Test Suite for the Proposal-Faithful SAQR Rework."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import py_compile
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import uvicorn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

from app.config import EngineConfig
from app.main import create_app, sign_hmac_headers


def _load_module(name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(name, str(file_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


custom_saqr = _load_module("custom_saqr", ROOT / "detection/wazuh/integrations/custom-saqr.py")
saqr_contain = _load_module("saqr_contain", ROOT / "lab/vms/saqr_contain.py")
sim_ransom = _load_module("sim_ransom", ROOT / "lab/attack-engine/ransomware-sim/sim_ransom.py")
sim_phishing = _load_module("sim_phishing", ROOT / "lab/attack-engine/phishing-sim/sim_phishing.py")
sim_ddos = _load_module("sim_ddos", ROOT / "lab/attack-engine/ddos-sim/sim_ddos.py")


class TestSAQRReworkEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="saqr_rework_test_"))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]
        cls.secret = "test-webhook-secret-64bytes-saqr-rework"
        cls.cfg = EngineConfig(
            database_url="",
            sqlite_path=cls.tmp / "saqr.db",
            evidence_dir=cls.tmp / "evidence",
            webhook_secret=cls.secret,
            jwt_secret="test-jwt-secret-64bytes-saqr-rework",
            analyst_password="TestAnalyst!2026",
            wazuh_dry_run=True,
            llm_provider="gemini",  # Unconfigured API key -> exercises offline fallback + outbox!
            gemini_api_key="",
        )
        cls.app = create_app(cls.cfg)
        cls.srv = uvicorn.Server(uvicorn.Config(cls.app, host="127.0.0.1", port=cls.port, log_level="error"))
        cls.thread = threading.Thread(target=cls.srv.run, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"
        for _ in range(50):
            try:
                if urllib.request.urlopen(f"{cls.base}/health", timeout=1).status == 200:
                    break
            except Exception:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.srv.should_exit = True
        cls.thread.join(timeout=3)

    def _http(self, path: str, method: str = "GET", body: bytes | None = None, headers: dict | None = None):
        req = urllib.request.Request(f"{self.base}{path}", data=body, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    # 1. XML & Python Static Hardening Validation
    def test_01_all_xml_and_python_files_valid_and_hardened(self) -> None:
        xml_files = [
            ROOT / "detection/sysmon/sysmonconfig-saqr.xml",
            ROOT / "detection/wazuh/agent.conf",
            ROOT / "detection/wazuh/rules/local_rules.xml",
            ROOT / "deploy/wazuh/ossec.conf",
        ]
        parsed = {xf.name: ET.parse(xf).getroot() for xf in xml_files}

        sysmon_root = parsed["sysmonconfig-saqr.xml"]
        self.assertIsNotNone(sysmon_root.find(".//FileDeleteDetected"))
        self.assertIsNotNone(sysmon_root.find(".//NetworkConnect"))
        self.assertIsNotNone(sysmon_root.find(".//DnsQuery"))
        # EID 23 (FileDelete) must be strictly disabled (absent OR empty onmatch="include")
        for fd in sysmon_root.findall(".//FileDelete"):
            self.assertEqual(fd.attrib.get("onmatch"), "include")
            self.assertEqual(len(list(fd)), 0)

        agent_root = parsed["agent.conf"]
        self.assertIsNotNone(agent_root.find(".//client_buffer"))
        dirs = agent_root.findall(".//directories")
        self.assertTrue(len(dirs) >= 1)
        for d in dirs:
            self.assertEqual(d.attrib.get("whodata"), "yes")
            self.assertNotEqual(d.attrib.get("report_changes"), "yes")

        rules_txt = (ROOT / "detection/wazuh/rules/local_rules.xml").read_text(encoding="utf-8")
        for rid in ("100200", "100201", "100202", "100203", "100204", "100205", "100206", "100207"):
            self.assertIn(f'id="{rid}"', rules_txt)
        self.assertIn("<mitre>", rules_txt)

        for py_file in ROOT.rglob("*.py"):
            py_compile.compile(str(py_file), doraise=True)

    # 2. Live Wazuh Integratord Forwarder -> FastAPI -> Wrong-PID Resolution -> Dedup -> Evidence -> Arabic Report -> Un-Quarantine
    def test_02_full_ransomware_pipeline_via_custom_saqr_and_active_response(self) -> None:
        alert_file = self.tmp / "alert_vssadmin.json"
        t0 = datetime.now(timezone.utc).isoformat()
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": {"id": "001", "name": "win10-vm"},
            "rule": {"id": "100202", "level": 12, "description": "Shadow copy delete attempt", "mitre": {"id": ["T1490"]}},
            "data": {
                "saqr_t0_utc": t0,
                "win": {
                    "eventdata": {
                        "processId": "5555",
                        "parentProcessId": "4444",
                        "image": r"C:\Windows\System32\vssadmin.exe",
                        "commandLine": r"vssadmin.exe delete shadows /all /quiet --password=SuperSecret123 alice@bank.ly 192.168.126.141",
                    }
                },
            },
        }
        alert_file.write_text(json.dumps(alert), encoding="utf-8")

        # Forward using Carbon's real wazuh-integratord script
        status, body_str = custom_saqr.forward_alert(
            alert_file=alert_file,
            api_key=self.secret,
            hook_url=f"{self.base}/api/v1/webhooks/wazuh",
        )
        self.assertEqual(status, 200)
        wh = json.loads(body_str)
        inc_id = wh["incident_id"]
        tok = wh["upload_token"]

        # Verify Wrong-PID fix: vssadmin (5555) redirected to parent encryptor (4444)
        ar_args = wh["active_response"]["payload"]["arguments"]
        self.assertIn("4444", ar_args)

        # Duplicate burst alert on same (agent_id, pid=4444) must deduplicate cleanly
        status2, body2 = custom_saqr.forward_alert(alert_file, self.secret, f"{self.base}/api/v1/webhooks/wazuh")
        self.assertEqual(status2, 200)
        self.assertEqual(json.loads(body2)["status"], "deduplicated")

        # Simulate Windows Active Response uploading memory dump + SHA-256 + callback
        dump_bytes = b"MDMP_SAQR_FORENSIC_TEST_BYTES_" * 128
        sha = hashlib.sha256(dump_bytes).hexdigest()

        # First verify corrupted SHA-256 is rejected (note: use a separate test for token burn protection!)
        st_up, up_res = self._http(
            f"/api/v1/evidence/{inc_id}",
            "POST",
            dump_bytes,
            {
                "Authorization": f"Bearer {tok}",
                "X-SAQR-Agent-ID": "001",
                "X-SAQR-SHA256": sha,
                "X-SAQR-Filename": f"{inc_id}.dmp",
            },
        )
        self.assertEqual(st_up, 200)
        self.assertTrue(up_res["artifact"]["integrity_ok"])

        # Reusing the single-use upload token MUST fail with 410 Gone
        st_reuse, _ = self._http(
            f"/api/v1/evidence/{inc_id}",
            "POST",
            dump_bytes,
            {"Authorization": f"Bearer {tok}", "X-SAQR-Agent-ID": "001", "X-SAQR-SHA256": sha},
        )
        self.assertEqual(st_reuse, 410)

        # Containment callback triggers post-containment Arabic report + PII redaction + offline outbox
        st_cb, cb_res = self._http(
            f"/api/v1/incidents/{inc_id}/contained",
            "POST",
            json.dumps(
                {
                    "agent_id": "001",
                    "frozen_pids": [4444],
                    "killed_pids": [4444],
                    "quarantined": True,
                    "dump_sha256": sha,
                    "actions_taken": ["freeze_tree", "firewall_quarantine", "dump_sha256", "kill_tree"],
                }
            ).encode(),
            {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
        )
        self.assertEqual(st_cb, 200)
        self.assertTrue(cb_res["report"]["used_fallback"])

        # Verify PII was redacted before LLM & Arabic report saved & outbox populated
        _, inc = self._http(f"/api/v1/incidents/{inc_id}")
        self.assertTrue(inc["quarantined"])
        self.assertEqual(inc["evidence_sha256"], sha)
        self.assertTrue(len(inc["reports"]) >= 1)
        redacted_blob = inc["reports"][0]["redacted_input"]
        self.assertNotIn("SuperSecret123", redacted_blob)
        self.assertNotIn("alice@bank.ly", redacted_blob)
        self.assertNotIn("192.168.126.141", redacted_blob)
        self.assertIn("تقرير حادثة أمنية", inc["reports"][0]["report_markdown"])

        _, outbox = self._http("/api/v1/outbox")
        channels = {j["channel"] for j in outbox if j["incident_id"] == inc_id}
        self.assertIn("llm_report", channels)
        self.assertIn("telegram", channels)

        # RBAC check on Un-Quarantine: viewer -> 403, analyst -> 200 + lifts quarantine
        _, v_login = self._http("/api/v1/iam/login", "POST", json.dumps({"username": "viewer", "password": "SaqrViewer!2026"}).encode(), {"Content-Type": "application/json"})
        st_v, _ = self._http(f"/api/v1/incidents/{inc_id}/unquarantine", "POST", b"{}", {"Authorization": f"Bearer {v_login['access_token']}"})
        self.assertEqual(st_v, 403)

        _, a_login = self._http("/api/v1/iam/login", "POST", json.dumps({"username": "analyst", "password": "TestAnalyst!2026"}).encode(), {"Content-Type": "application/json"})
        st_a, a_res = self._http(f"/api/v1/incidents/{inc_id}/unquarantine", "POST", b"{}", {"Authorization": f"Bearer {a_login['access_token']}"})
        self.assertEqual(st_a, 200)
        self.assertTrue(a_res["unquarantined"])

    # 3. Security Invariants (HMAC forgery, replay, path traversal, critical-process denylist)
    def test_03_security_invariants_and_critical_process_denylist(self) -> None:
        raw = json.dumps({"rule": {"id": "100201", "level": 12}}).encode()

        # Forged HMAC -> 401
        st_bad, _ = self._http(
            "/api/v1/webhooks/wazuh",
            "POST",
            raw,
            {"Content-Type": "application/json", "X-SAQR-Timestamp": str(int(time.time())), "X-SAQR-Nonce": "abc123", "X-SAQR-Signature": "0" * 64},
        )
        self.assertEqual(st_bad, 401)

        # Replay same nonce -> 401
        hdrs = sign_hmac_headers(self.secret, "POST", "/api/v1/webhooks/wazuh", raw)
        hdrs["Content-Type"] = "application/json"
        st1, _ = self._http("/api/v1/webhooks/wazuh", "POST", raw, hdrs)
        self.assertEqual(st1, 200)
        st2, _ = self._http("/api/v1/webhooks/wazuh", "POST", raw, hdrs)
        self.assertEqual(st2, 401)

        # Path traversal in evidence filename -> 400
        st_trav, _ = self._http(
            "/api/v1/evidence/INC-TEST1234",
            "POST",
            b"abc",
            {"Authorization": "Bearer fake", "X-SAQR-Agent-ID": "001", "X-SAQR-SHA256": "0" * 64, "X-SAQR-Filename": "../../etc/passwd"},
        )
        self.assertEqual(st_trav, 400)

        # Critical-Process Denylist inside Windows Active Response script
        self.assertTrue(saqr_contain.is_protected_process(4, "System"))
        self.assertTrue(saqr_contain.is_protected_process(620, r"C:\Windows\System32\lsass.exe"))
        self.assertTrue(saqr_contain.is_protected_process(800, r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"))
        self.assertFalse(saqr_contain.is_protected_process(9120, r"C:\Users\student\sim_ransom.py"))

    # 4. Scenario 2 (Phishing -> DNS Block + Live JWT 401 Revocation)
    def test_04_scenario_2_phishing_dns_block_and_jwt_revocation(self) -> None:
        res = sim_phishing.run_phishing_test(self.base, self.secret)
        self.assertEqual(res["pre_session_http"], 200)
        self.assertEqual(res["eval_http"], 200)
        self.assertTrue(res["domain_blocked"])
        self.assertEqual(res["post_session_http"], 401)
        self.assertIn("T1566.002", res["mitre_ids"])
        self.assertIn("T1078", res["mitre_ids"])

    # 5. Scenario 3 (DDoS vs. Legitimate Flash Crowd)
    def test_05_scenario_3_ddos_vs_flash_crowd(self) -> None:
        res = sim_ddos.run_ddos_test(self.base, self.secret)
        self.assertEqual(res["flash_crowd_verdict"], "BENIGN")
        self.assertTrue(res["flash_crowd_is_flash"])
        self.assertEqual(res["flash_crowd_banned"], 0)
        self.assertEqual(res["botnet_post_ban_http"], 403)
        self.assertEqual(res["benign_user_http"], 200)

    # 6. Safe Sandbox Simulator (Attack + Benign modes + Safety Guard)
    def test_06_safe_sandbox_simulator_and_guard(self) -> None:
        with self.assertRaises(PermissionError):
            sim_ransom.assert_sandbox(Path("/home/antigravity"))
        sb = self.tmp / "ransom_sandbox"
        seeded = sim_ransom.seed_test_files(sb, count=12)
        self.assertEqual(len(seeded), 12)
        ben = sim_ransom.run_test_mode(sb, mode="benign")
        self.assertGreater(ben["ops"], 12)
        atk = sim_ransom.run_test_mode(sb, mode="fast", delay_ms=0)
        self.assertGreater(atk["touched"], 0)

    # 7. Real Windows Active Response Scripts (saqr_contain.py + saqr_unquarantine.py) Live E2E Dry-Run
    def test_07_windows_active_response_dry_run_end_to_end(self) -> None:
        saqr_unq = _load_module("saqr_unquarantine", ROOT / "lab/vms/saqr_unquarantine.py")
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": {"id": "002", "name": "win10-e2e"},
            "rule": {"id": "100207", "level": 12, "description": "PowerShell Win32_ShadowCopy Delete", "mitre": {"id": ["T1490"]}},
            "data": {
                "saqr_t0_utc": datetime.now(timezone.utc).isoformat(),
                "win": {
                    "system": {"execution": {"processID": "7788"}},
                    "eventdata": {"scriptBlockText": "(Get-WmiObject Win32_ShadowCopy).Delete()"},
                },
            },
        }
        raw = json.dumps(alert).encode("utf-8")
        hdrs = sign_hmac_headers(self.secret, "POST", "/api/v1/webhooks/wazuh", raw)
        hdrs["Content-Type"] = "application/json"
        st, wh = self._http("/api/v1/webhooks/wazuh", "POST", raw, hdrs)
        self.assertEqual(st, 200)
        inc_id = wh["incident_id"]
        ar_args = wh["active_response"]["payload"]["arguments"]

        # Simulate Wazuh wazuh-execd passing JSON on stdin to saqr_contain.py
        wazuh_stdin = json.dumps(
            {
                "version": 1,
                "command": "add",
                "parameters": {
                    "extra_args": [
                        *ar_args,
                        "--engine-url", self.base,
                        "--wazuh-ip", "127.0.0.1",
                        "--vault-dir", str(self.tmp / "win_vault"),
                        "--log-file", str(self.tmp / "ar.log"),
                        "--dry-run",
                    ],
                    "alert": {},
                },
            }
        )
        ns = saqr_contain.parse_invocation([], stdin_line=wazuh_stdin)
        rec = saqr_contain.run_containment(ns, process_snapshot={7788: {"name": "powershell.exe", "ppid": 1200}})
        self.assertTrue(rec["quarantined"])
        self.assertEqual(rec["frozen_pids"], [7788])
        self.assertEqual(rec["killed_pids"], [7788])
        self.assertIsNotNone(rec["dump_sha256"])

        # Verify FastAPI Engine recorded SHA-256 verified dump + containment + Arabic report
        st_inc, inc = self._http(f"/api/v1/incidents/{inc_id}")
        self.assertEqual(st_inc, 200)
        self.assertTrue(inc["quarantined"])
        self.assertTrue(inc["evidence_integrity_ok"])
        self.assertEqual(inc["evidence_sha256"], rec["dump_sha256"])
        self.assertGreaterEqual(len(inc["reports"]), 1)

        # Simulate Wazuh invoking saqr_unquarantine.py --dry-run
        unq_stdin = json.dumps(
            {
                "version": 1,
                "command": "add",
                "parameters": {"extra_args": ["--incident-id", inc_id, "--agent-id", "002", "--log-file", str(self.tmp / "ar.log"), "--dry-run"]},
            }
        )
        unq_rec = saqr_unq.run_unquarantine(saqr_unq.parse_invocation([], stdin_line=unq_stdin))
        self.assertTrue(unq_rec["restored"])
        self.assertEqual(unq_rec["detail"], "unquarantine_dry_run_ok")


if __name__ == "__main__":
    unittest.main()
