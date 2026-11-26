"""Pydantic v2 schemas and deterministic bilingual MITRE ATT&CK catalog for SAQR."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


MITRE_MAP: Dict[str, Dict[str, str]] = {
    "T1486": {"id": "T1486", "tactic_ar": "التأثير", "name_ar": "تشفير البيانات بهدف التأثير (الفدية)", "name_en": "Data Encrypted for Impact"},
    "T1490": {"id": "T1490", "tactic_ar": "التأثير", "name_ar": "تعطيل استعادة النظام وحذف نسخ الظل", "name_en": "Inhibit System Recovery"},
    "T1021.002": {"id": "T1021.002", "tactic_ar": "الحركة الجانبية", "name_ar": "الانتشار عبر مشاركات SMB", "name_en": "SMB/Windows Admin Shares"},
    "T1566.002": {"id": "T1566.002", "tactic_ar": "الوصول الأولي", "name_ar": "التصيد الإلكتروني عبر رابط خبيث أو نطاق متشابه", "name_en": "Spearphishing Link"},
    "T1078": {"id": "T1078", "tactic_ar": "الوصول الأولي", "name_ar": "استغلال حسابات أو جلسات صالحة", "name_en": "Valid Accounts"},
    "T1498": {"id": "T1498", "tactic_ar": "التأثير", "name_ar": "حجب الخدمة الشبكي الموزع (DDoS)", "name_en": "Network Denial of Service"},
    "T1499": {"id": "T1499", "tactic_ar": "التأثير", "name_ar": "إغراق طبقة التطبيقات (HTTP Flood)", "name_en": "Endpoint Denial of Service"},
}


def resolve_mitre(ids: List[str]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen = set()
    for raw in ids:
        tid = raw.strip().upper()
        if not tid or tid in seen:
            continue
        seen.add(tid)
        out.append(MITRE_MAP.get(tid, {"id": tid, "tactic_ar": "غير مصنف", "name_ar": tid, "name_en": tid}))
    return out


class ContainmentCallback(BaseModel):
    agent_id: str
    frozen_pids: List[int] = Field(default_factory=list)
    killed_pids: List[int] = Field(default_factory=list)
    quarantined: bool = True
    dump_sha256: Optional[str] = None
    t3_utc: Optional[str] = None
    t4_utc: Optional[str] = None
    actions_taken: List[str] = Field(default_factory=list)


class PhishingAlert(BaseModel):
    agent_id: str = "001"
    hostname: str = "win10-vm"
    username: str
    sender_email: str
    domain: str
    url: str
    subject: str = ""
    spf_pass: bool = True
    dkim_pass: bool = True
    dmarc_pass: bool = True
    credential_submitted: bool = False
    session_jti: Optional[str] = None
    t0_utc: Optional[str] = None


class DDoSRequestItem(BaseModel):
    src_ip: str
    uri: str = "/api/v1/demo/web-target"
    user_agent: str = ""
    status_code: int = 200


class DDoSBatch(BaseModel):
    events: List[DDoSRequestItem]


class LoginRequest(BaseModel):
    username: str
    password: str


class RevokeRequest(BaseModel):
    jti: str
    username: Optional[str] = None
    reason: str = "SOC analyst manual revocation"
