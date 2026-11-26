"""SAQR Layer 5 — Arabic RTL Streamlit SOC Dashboard (Port 8501).

Connects to SAQR FastAPI Engine (:5000) to visualize live incidents, T0..T4 response
timelines, deterministic MITRE ATT&CK tags, SHA-256 forensic integrity, Arabic AI reports,
blocked phishing domains / DDoS IPs, 1-click analyst Un-Quarantine, and 20-trial CSV metrics.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import requests
import streamlit as st

ENGINE_URL = os.getenv("SAQR_ENGINE_URL", "http://127.0.0.1:5000").rstrip("/")
METRICS_CSV = Path(os.getenv("SAQR_METRICS_CSV", "../metrics_output/trials_20.csv"))

st.set_page_config(
    page_title="SAQR OPS — لوحة عمليات الأمن السيبراني",
    page_icon="🦅",
    layout="wide",
)

# RTL Arabic + SAQR Palette (#081528 Navy, #00BCD4 Cyan, #F5A623 Amber)
st.markdown(
    """
    <style>
      html, body, [class*="css"] { direction: rtl; text-align: right; font-family: "IBM Plex Sans Arabic", "Inter", sans-serif; }
      .stApp { background-color: #081528; color: #F1F5F9; }
      .saqr-banner {
        background: linear-gradient(90deg, #0F213D, #122847);
        border: 1px solid #00BCD4;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 16px;
      }
      .saqr-gold {
        background: rgba(245, 166, 35, 0.14);
        border-right: 4px solid #F5A623;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 14px;
      }
      div[data-testid="stMetric"] {
        background: #122847;
        border: 1px solid #1E3A5F;
        border-radius: 10px;
        padding: 12px 14px;
      }
      code { direction: ltr; unicode-bidi: isolate; }
    </style>
    """,
    unsafe_allow_html=True,
)


def api_get(path: str) -> Optional[Any]:
    try:
        r = requests.get(f"{ENGINE_URL}{path}", timeout=4)
        return r.json() if r.ok else None
    except Exception:
        return None


def api_post(path: str, payload: Optional[Dict[str, Any]] = None, token: str = "") -> requests.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.post(f"{ENGINE_URL}{path}", json=payload or {}, headers=headers, timeout=5)


# ---- Sidebar: Analyst RBAC Login & Controls ----
with st.sidebar:
    st.markdown("### 🔐 دخول محلل SOC (RBAC)")
    if "jwt" not in st.session_state:
        st.session_state.jwt = ""
        st.session_state.role = ""

    if not st.session_state.jwt:
        user = st.text_input("اسم المستخدم", value="analyst")
        pwd = st.text_input("كلمة المرور", type="password", value=os.getenv("SAQR_ANALYST_PASSWORD", ""))
        if st.button("تسجيل الدخول", use_container_width=True):
            try:
                resp = api_post("/api/v1/iam/login", {"username": user, "password": pwd})
                if resp.ok:
                    data = resp.json()
                    st.session_state.jwt = data["access_token"]
                    st.session_state.role = data["role"]
                    st.success(f"تم الدخول بصلاحية: {data['role']}")
                    st.rerun()
                else:
                    st.error("بيانات الدخول غير صحيحة")
            except Exception as exc:
                st.error(f"تعذر الاتصال بالمحرك: {exc}")
    else:
        st.success(f"متصل بصلاحية: `{st.session_state.role}`")
        if st.button("تسجيل الخروج", use_container_width=True):
            st.session_state.jwt = ""
            st.session_state.role = ""
            st.rerun()

    st.divider()
    if st.button("🔄 تحديث البيانات الآن", use_container_width=True):
        st.rerun()
    st.caption(f"Engine: `{ENGINE_URL}`")


# ---- Header ----
st.markdown(
    """
    <div class="saqr-banner">
      <h2 style="margin:0; color:#F1F5F9;">🦅 SAQR <span style="color:#00BCD4;">OPS</span> — منصة صَقْر لعمليات الأمن السيبراني والاستجابة الآلية</h2>
      <div style="color:#94A3B8; font-size:0.9rem; margin-top:4px;">
        DETECT • CONTAIN • EXPLAIN &nbsp;|&nbsp; Wazuh v4.14.11 + Sysmon + FastAPI + PostgreSQL 16 + Gemini / Local Ollama
      </div>
    </div>
    <div class="saqr-gold">
      <b>القاعدة الذهبية:</b> الكشف والعزل وحفظ الأدلة الجنائية (SHA-256) تُنفّذ حتمياً بقواعد محددة دون تدخل الذكاء الاصطناعي؛
      يُستخدم النموذج اللغوي بعد اكتمال الاحتواء فقط لصياغة التقرير العربي بعد تنقيح البيانات الحساسة (PII).
    </div>
    """,
    unsafe_allow_html=True,
)

stats = api_get("/api/v1/stats")
if stats is None:
    st.error(f"تعذر الاتصال بمحرك SAQR على `{ENGINE_URL}`. تأكد من تشغيل `docker compose up -d`.")
    st.stop()

# ---- KPI Strip ----
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("إجمالي الحوادث", stats["total_incidents"])
c2.metric("الأجهزة المعزولة", stats["quarantined_hosts"])
c3.metric("متوسط الكشف MTTD", f"{stats['avg_mttd_ms']} ms" if stats["avg_mttd_ms"] is not None else "—")
c4.metric("متوسط الاحتواء MTTC", f"{stats['avg_mttc_ms']} ms" if stats["avg_mttc_ms"] is not None else "—")
c5.metric("الأدلة الجنائية (SHA-256)", stats["forensic_artifacts"])
c6.metric("نطاقات / IPs محظورة", f"{stats['blocked_domains']} / {stats['blocked_ips']}")

tab_inc, tab_ctrl, tab_metrics = st.tabs(["🚨 الحوادث والتقارير العربية", "🛡️ ضوابط الحظر والتدقيق", "📊 نتائج التجارب الـ 20"])

# ---- Tab 1: Incidents & Arabic Reports ----
with tab_inc:
    incidents: List[Dict[str, Any]] = api_get("/api/v1/incidents") or []
    if not incidents:
        st.info("لا توجد حوادث مسجلة بعد. شغّل محاكي الاختبار لتجربة سلسلة الاستجابة الكاملة.")
    else:
        df = pd.DataFrame(
            [
                {
                    "المعرّف": i["incident_id"],
                    "السيناريو": i["scenario"],
                    "الجهاز": i["hostname"],
                    "القاعدة": i["rule_id"],
                    "الخطورة": i["risk_score"],
                    "الحالة": i["status"],
                    "معزول": "نعم ✅" if i["quarantined"] else "لا",
                    "MITRE": ", ".join(i.get("mitre_ids", [])),
                    "MTTC (ms)": i.get("mttc_ms"),
                }
                for i in incidents
            ]
        )
        st.dataframe(df, use_container_width=True, hide_index=True)

        selected_id = st.selectbox("اختر حادثة لعرض التفاصيل والتقرير العربي:", [i["incident_id"] for i in incidents])
        detail = api_get(f"/api/v1/incidents/{selected_id}")
        if detail:
            left, right = st.columns([1, 1.4])
            with left:
                st.subheader("⏱️ الخط الزمني T0–T4 والأدلة الجنائية")
                st.write(
                    {
                        "T0 (بدء الهجوم)": detail.get("t0_attack_utc"),
                        "T1 (رصد Wazuh)": detail.get("t1_detected_utc"),
                        "T2 (قرار FastAPI)": detail.get("t2_decided_utc"),
                        "T3 (تفريغ الذاكرة)": detail.get("t3_dumped_utc"),
                        "T4 (اكتمال الاحتواء)": detail.get("t4_contained_utc"),
                        "MTTD (ms)": detail.get("mttd_ms"),
                        "MTTC (ms)": detail.get("mttc_ms"),
                        "SHA-256": detail.get("evidence_sha256"),
                        "تطابق الهاش": detail.get("evidence_integrity_ok"),
                    }
                )
                if detail.get("quarantined"):
                    if st.session_state.jwt and st.session_state.role in ("analyst", "admin"):
                        if st.button("🔓 إلغاء العزل الشبكي (Un-Quarantine)", type="primary"):
                            r = api_post(f"/api/v1/incidents/{selected_id}/unquarantine", token=st.session_state.jwt)
                            if r.ok:
                                st.success("تم إرسال أمر إلغاء العزل إلى Wazuh Active Response بنجاح.")
                                st.rerun()
                            else:
                                st.error(f"فشل إلغاء العزل: {r.text}")
                    else:
                        st.warning("سجّل الدخول كـ `analyst` من الشريط الجانبي لتفعيل زر إلغاء العزل.")

            with right:
                st.subheader("📄 التقرير الأمني العربي (بعد الاحتواء)")
                reports = detail.get("reports") or []
                if reports:
                    latest = reports[0]
                    st.caption(f"المزوّد: `{latest['provider']}` | النموذج: `{latest['model_name']}` | زمن التوليد: `{latest['latency_ms']} ms`")
                    st.markdown(latest["report_markdown"])
                else:
                    st.info("التقرير قيد التوليد أو بانتظار اكتمال الاحتواء.")

# ---- Tab 2: Controls, Outbox & Audit Log ----
with tab_ctrl:
    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("🌐 نطاقات التصيد المحظورة (DNS Sinkhole)")
        st.dataframe(api_get("/api/v1/controls/blocked-domains") or [], use_container_width=True)
        st.subheader("📨 قائمة إعادة المحاولة (Offline Outbox)")
        st.dataframe(api_get("/api/v1/outbox") or [], use_container_width=True)
    with col_b:
        st.subheader("🚫 عناوين IP المحظورة (DDoS)")
        st.dataframe(api_get("/api/v1/controls/blocked-ips") or [], use_container_width=True)
        st.subheader("🧾 سجل التدقيق (Audit Log)")
        st.dataframe(api_get("/api/v1/audit") or [], use_container_width=True)

# ---- Tab 3: 20-Trial Scientific Evaluation ----
with tab_metrics:
    st.subheader("📊 نتائج بروتوكول التجارب الـ 20 (المتوسط، الوسيط، الانحراف المعياري)")
    if METRICS_CSV.exists():
        mdf = pd.read_csv(METRICS_CSV)
        st.dataframe(mdf, use_container_width=True)
        if "mttc_ms" in mdf.columns:
            st.bar_chart(mdf.set_index("trial")[["mttd_ms", "mttc_ms"]])
    else:
        st.info("لم تُشغّل التجارب الـ 20 بعد. نفّذ `python3 metrics/run_20_trials.py --mode simulate` أو `--mode vmware` لعرض الرسوم والجداول هنا.")
