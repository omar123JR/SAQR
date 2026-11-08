# 🦅 خطة مشروع صَقْر (SAQR) — الخطة الشاملة الكاملة

> **SAQR** = Security Automated Query & Response  
> **الفكرة الجوهرية:** منصة دفاعية ذكية تجمع بين مركز عمليات مصغر (Mini-SOC) والأتمتة والاستجابة (SOAR) بنمط معماري هجين يدعم العمل المحلي الكامل (Air-gapped) والعمل السحابي الاقتصادي (Cloud API)، مع توليد تقارير أمنية احترافية باللغة العربية.

---

## 1. المشكلة التي يحلها المشروع

| المشكلة | الواقع الحالي | ما يقدمه صَقْر |
|:--------|:-------------|:--------------|
| نقص كوادر الـ SOC | محلل واحد يراقب مئات التنبيهات يدوياً | استجابة تلقائية فورية دون انتظار تدخل بشري في الثواني الأولى |
| قيود سرية البيانات | بنوك وجهات سيادية تمنع خروج السجلات للخارج | دعم كامل للتشغيل المحلي (Air-gapped) بنموذج لغة محلي |
| محدودية موارد الأجهزة | الحواسيب المتوسطة لا تتحمل نماذج AI ضخمة | طبقة تجريد هجينة (Ollama محلي + Gemini API اختياري) |
| غياب التقارير بالعربية | كل أدوات الـ SIEM/SOAR تنتج تقارير إنجليزية | توليد تقارير رسمية بالعربية مربوطة بأطر MITRE ATT&CK |
| تكلفة الحلول التجارية | حلول SOAR/SIEM باهظة جداً بمئات آلاف الدولارات | بيئة قائمة 100% على أدوات وتقنيات مفتوحة المصدر |

---

## 2. المعمارية الكاملة — 5 طبقات

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 1: بيئة الضحية (Windows 10 VM — Hyper-V)                    │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────────┐    │
│  │ Sysmon      │  │ Wazuh Agent │  │ Honeypot Folder          │    │
│  │ (المراقب)   │  │ (المُبلِّغ) │  │ C:\test-files\ (300 ملف) │    │
│  └──────┬──────┘  └──────┬──────┘  └──────────────────────────┘    │
└─────────┼────────────────┼───────────────────────────────────────────┘
          │ Events         │ Alerts (Port 1514)
          ▼                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 2: خط الرصد (Docker WSL2 — wazuh-manager container)         │
│                                                                      │
│  Sysmon Events ──► Wazuh Manager ──► قواعد Sigma/Wazuh             │
│                         │                    ↓                      │
│                         │           تنبيه مُصنَّف بمستوى خطورة 1-5  │
│                         ▼                                            │
│              Webhook ──► FastAPI Engine (Port 5000)                 │
└─────────────────────────────────────────────────────────────────────┘
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 3: محرك القرار الحتمي (FastAPI + PostgreSQL)                 │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  الحادثة الجديدة تصل ──► ربط الأحداث المتشابهة (Correlation)│   │
│  │                              ↓                               │    │
│  │  هل الشروط مكتملة؟    IF events.count > 30 AND                │   │
│  │                        elapsed_seconds < 5 AND                │    │
│  │                        vssadmin_event = true                  │    │
│  │                              ↓                               │    │
│  │  تسجيل T0 (بداية الهجوم) ──► T1 (أول تنبيه) ──► T2 (قرار)  │   │
│  │                              ↓                               │    │
│  │              إطلاق أوامر الاستجابة (SOAR Actions)            │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                         ↓                        ↓                  │
│              [PostgreSQL] tables:                                    │
│              alerts | incidents | actions | evidence | timings       │
└─────────────────────────────────────────────────────────────────────┘
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 4: الاستجابة وطبقة الذكاء الهجينة (SOAR + Pluggable LLM)    │
│                                                                      │
│  Action 1: Process Dump                                              │
│    └─► procdump.exe ──► evidence/sha256_timestamp.dmp               │
│                                                                      │
│  Action 2: العزل الشبكي الفوري                                      │
│    └─► Wazuh Active Response ──► PowerShell: Block-NetAdapter       │
│         (يقطع الاتصال لكن يظل Wazuh Agent متصلاً بالسيرفر)         │
│                                                                      │
│  Action 3: تسجيل T3 (لقطة الذاكرة) + T4 (العزل الكامل)            │
│                                                                      │
│  Action 4: طبقة الذكاء الاصطناعي المرنة (LLM Provider Pattern):     │
│    ├── Local Mode: Ollama (Qwen2.5-1.5B / 3B) [للعرض المعزول]      │
│    └── Cloud Mode: Gemini API / OpenAI        [للتطوير والسرعة]     │
│    Input JSON:  {host, ip, technique, evidence_hash, events[]}      │
│    Output:     تقرير أمني عربي منسق مع تقنيات MITRE ATT&CK         │
└─────────────────────────────────────────────────────────────────────┘
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 5: الإبلاغ والتحكم (Streamlit + Telegram)                   │
│                                                                      │
│  Streamlit Dashboard (RTL - عربي):                                  │
│   ├── لوحة الحوادث المباشرة (Live SOC Board)                       │
│   ├── الجهاز المحتجز وحالته                                         │
│   ├── مقاييس الأداء: MTTD / MTTC / False Positives                 │
│   ├── الجدول الزمني للحادثة (Timeline T0→T4)                       │
│   └── تقرير الذكاء الاصطناعي العربي                                │
│                                                                      │
│  Telegram Bot:                                                       │
│   ├── إشعار فوري عند الاحتواء: "🚨 جهاز WIN-01 تم عزله - MTTD: 3s"│
│   ├── أمر /status: الحالة الحالية للأجهزة                          │
│   └── أمر /report [id]: استرجاع تقرير حادثة بعينها                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. هيكل المستودع (Monorepo)

```
saqr/
├── README.md
├── .env.example                    # المفاتيح والمتغيرات والنمط المختار
├── docker-compose.yml              # تشغيل بيئة الخوادم بأمر واحد
├── .wslconfig                      # تقييد ذاكرة WSL2 الصارم بـ 4GB
│
├── docs/
│   ├── architecture.md             # وثيقة المعمارية
│   ├── lab-setup.md                # دليل إعداد المعمل والشبكة
│   ├── safety-rules.md             # القواعد الأمنية للفريق
│   └── decisions/
│       ├── ADR-001-hybrid-llm.md   # قرار طبقة الذكاء الهجينة
│       └── ADR-002-deterministic.md# قرار فصل محرك القرار عن الـ LLM
│
├── lab/
│   ├── network-diagram.png         # مخطط الشبكة الافتراضية
│   ├── vms/
│   │   ├── windows10-setup.ps1     # تثبيت Sysmon + Agent تلقائياً
│   │   └── snapshots.md            # سجل اللقطات النظيفة
│   └── attack-engine/
│       ├── ransomware-sim/
│       │   └── sim_ransom.py       # محاكي الفدية الآمن
│       ├── phishing/               # (السيمستر الثاني)
│       └── ddos-sim/               # (السيمستر الثاني)
│
├── detection/
│   ├── sysmon/
│   │   └── sysmonconfig.xml        # إعدادات SwiftOnSecurity
│   ├── wazuh/
│   │   └── rules/
│   │       └── local_rules.xml     # قواعد الكشف المخصصة للفدية
│   └── sigma/
│       └── ransomware_rules.yml    # قواعد Sigma للمطابقة
│
├── engine/                         # القلب: FastAPI
│   ├── app/
│   │   ├── main.py                 # نقطة الدخول واستقبال الـ Webhook
│   │   ├── config.py               # تحميل إعدادات البيئة
│   │   ├── models.py               # نماذج PostgreSQL (SQLAlchemy)
│   │   ├── schemas.py              # عقود البيانات الموحدة (Pydantic)
│   │   ├── rules.py                # محرك القواعد الحتمي
│   │   ├── correlator.py           # خوارزمية ربط الأحداث
│   │   └── services/
│   │       ├── soar.py             # تنسيق وتنفيذ أوامر الاستجابة
│   │       ├── evidence.py         # تفريغ الذاكرة وتجزئة الأدلة SHA-256
│   │       ├── metrics.py          # قياس MTTD و MTTC بدقة المللي ثانية
│   │       └── llm.py              # طبقة التجريد الذكية (Provider Pattern)
│   ├── tests/
│   └── Dockerfile
│
├── soar/
│   ├── actions/
│   │   ├── snapshot.py             # أخذ لقطة الآلة الافتراضية
│   │   ├── isolate.py              # عزل كرت الشبكة عبر جدار الحماية
│   │   └── evidence.py             # حفظ Process Dump والهاش
│   └── playbooks/
│       ├── ransomware.yaml         # سيناريو الفدية التفصيلي
│       ├── phishing.yaml           # سيناريو التصيد (مستقبلاً)
│       └── ddos.yaml               # سيناريو حجب الخدمة (مستقبلاً)
│
├── ai/
│   ├── providers/
│   │   ├── base.py                 # الصنف الأساسي الموحد (Abstract Base)
│   │   ├── gemini_provider.py      # الاتصال السريع بـ Gemini API
│   │   └── ollama_provider.py      # الاتصال المحلي بـ Ollama
│   ├── prompts/
│   │   ├── incident_analysis.txt   # صياغة التقرير الأمني الاحترافي
│   │   └── mitre_mapping.txt       # ربط السلوك بتقنيات الهجوم
│   └── eval/
│       └── quality_metrics.py      # التقييم العددي لجودة التقرير
│
├── dashboard/                      # لوحة التحكم: Streamlit (RTL عربي)
│   ├── app.py
│   ├── pages/
│   │   ├── 01_live_board.py        # مراقبة الحوادث المباشرة
│   │   ├── 02_incidents.py         # أرشيف وتفاصيل الحوادث
│   │   ├── 03_metrics.py           # لوحة الإحصائيات (MTTD / MTTC)
│   │   └── 04_reports.py           # التقارير العربية الصادرة
│   └── Dockerfile
│
├── bot/
│   └── telegram/
│       ├── bot.py                  # خادم البوت
│       └── handlers/               # أوامر الإدارة والاستعلام
│
└── metrics/
    ├── collector.py                # جمع التوقيتات والأرقام
    ├── run_experiment.py           # سكريبت التجارب الآلية الـ 20
    └── notebooks/
        └── analysis.ipynb          # رسوم وجداول تقرير التخرج
```

---

## 4. عقد البيانات الموحد (JSON Alert Schema)

```json
{
  "id": "uuid-v4",
  "ts": "2026-11-03T10:15:03.120Z",
  "source": "wazuh | suricata | gateway",
  "host": "WIN-VICTIM-01",
  "ip": "10.10.10.21",
  "rule_id": "100201",
  "category": "ransomware | phishing | ddos",
  "severity": 1,
  "evidence": {
    "process": "sim_ransom.exe",
    "pid": 4821,
    "files_renamed": 312,
    "vssadmin_called": true,
    "dump_path": "evidence/WIN-01_20261103_101505.dmp",
    "dump_sha256": "a3f7c2e8b9148..."
  },
  "timings": {
    "T0": "2026-11-03T10:15:00.000Z",
    "T1": "2026-11-03T10:15:03.120Z",
    "T2": "2026-11-03T10:15:03.125Z",
    "T3": "2026-11-03T10:15:04.210Z",
    "T4": "2026-11-03T10:15:04.850Z"
  },
  "raw": {}
}
```

**الأزمنة:**
| الرمز | المعنى | كيف يُحسب |
|:------|:--------|:----------|
| **T0** | بداية الهجوم الفعلي | أول حدث Sysmon يُسجل تغييراً في ملفات الضحية |
| **T1** | أول تنبيه يصل للمنصة | طابع استلام الـ Webhook من Wazuh داخل FastAPI |
| **T2** | صدور قرار الاستجابة | لحظة تطابق شروط القاعدة الحتمية وتفعيل الـ Playbook |
| **T3** | اكتمال تفريغ الذاكرة | بعد انتهاء procdump وحساب SHA-256 للملف |
| **T4** | اكتمال العزل الشبكي | تأكيد إغلاق منافذ الاتصال عبر جدار الحماية |

**المقاييس العلمية المستخلصة:**
- `MTTD` (Mean Time to Detect) = T1 - T0
- `MTTC` (Mean Time to Contain) = T4 - T0
- `Files Encrypted` = عدد الملفات المشفرة قبل إتمام T4

---

## 5. معمارية طبقة الذكاء الاصطناعي الهجينة (Hybrid & Pluggable LLM)

> [!IMPORTANT]
> **واقع الموارد الهندسي:** جهاز العمل يحمل معالج `Intel Core i5-1135G7` وذاكرة `16GB RAM` وبطاقة رسوميات مدمجة `Intel Iris Xe` بدون ذاكرة VRAM منفصلة. تشغيل نموذج 3B أو 7B محلياً على المعالج يستهلك 3-4 جيجابايت من الرام ويستغرق من 40 إلى 90 ثانية لإنتاج التقرير الواحد، مما يعرض النظام لخطر التجمد ونفاد الذاكرة أثناء التجارب المتزامنة.

### 5.1 استراتيجية التصميم (Provider Pattern)
بدلاً من تقييد النظام بخيار واحد، صُممت طبقة الذكاء الاصطناعي بنمط **Provider Abstraction** يفصل منطق التحليل عن مزود الخدمة. يتيح ذلك التبديل التام بين **النمط السحابي (Cloud API)** و**النمط المحلي (Local Ollama)** بتغيير متغير بيئي واحد في ملف `.env` دون تعديل سطر برمجي واحد في المحرك:

```python
# engine/app/services/llm.py
import os
import requests
from abc import ABC, abstractmethod

class BaseLLMProvider(ABC):
    @abstractmethod
    def generate_report(self, incident_data: dict, prompt_template: str) -> str:
        pass

class GeminiAPIProvider(BaseLLMProvider):
    """النمط السحابي: سريع، خفيف، بدون استهلاك لرام المعالج"""
    def __init__(self, api_key: str, model: str = "gemini-1.5-flash"):
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model)

    def generate_report(self, incident_data: dict, prompt_template: str) -> str:
        prompt = prompt_template.format(incident_json=str(incident_data))
        response = self.model.generate_content(prompt)
        return response.text

class OllamaLocalProvider(BaseLLMProvider):
    """النمط المحلي: آمن 100% للشبكات المعزولة (Air-gapped)"""
    def __init__(self, base_url: str = "http://host.docker.internal:11434", model: str = "qwen2.5:1.5b"):
        self.base_url = base_url
        self.model = model

    def generate_report(self, incident_data: dict, prompt_template: str) -> str:
        prompt = prompt_template.format(incident_json=str(incident_data))
        res = requests.post(
            f"{self.base_url}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False},
            timeout=180
        )
        return res.json().get("response", "")

def get_llm_provider() -> BaseLLMProvider:
    """مصنع المزوّد حسب إعدادات البيئة"""
    provider_type = os.getenv("LLM_PROVIDER", "gemini").lower()
    if provider_type == "gemini":
        return GeminiAPIProvider(api_key=os.getenv("GEMINI_API_KEY", ""))
    elif provider_type == "ollama":
        model_name = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
        return OllamaLocalProvider(model=model_name)
    raise ValueError(f"Unknown provider: {provider_type}")
```

### 5.2 الإعداد والتحكم عبر متغيرات البيئة (.env)
```bash
# للتبديل الفوري دون لمس الكود:

# النمط الأول: سحابي فائق السرعة والخفة (موصى به أثناء التطوير والتجارب الـ 20)
LLM_PROVIDER=gemini
GEMINI_API_KEY=AIzaSyD...
GEMINI_MODEL=gemini-1.5-flash

# النمط الثاني: محلي كامل للبيئات المعزولة (يوم العرض أو البيئات الصارمة)
# LLM_PROVIDER=ollama
# OLLAMA_URL=http://host.docker.internal:11434
# OLLAMA_MODEL=qwen2.5:1.5b
```

### 5.3 خطة التنفيذ المرحلية للذكاء الاصطناعي
1. **مرحلة التطوير والاختبارات الـ 20 (الأسابيع 1 إلى 10):**
   * تفعيل `LLM_PROVIDER=gemini` عبر واجهة مجانية.
   * **المكسب:** توفير 3.5GB رام بالكامل لمحرك Wazuh والآلة الافتراضية، وسرعة استجابة فائقة (< 3 ثوانٍ للتقرير)، مع تجنب انهيار النظام أثناء تكرار التجارب.
2. **مرحلة تجهيز العرض والتقييم المحلي (الأسابيع 11 إلى 13):**
   * تثبيت `Ollama` وتجربة نموذج `qwen2.5:1.5b` (حجمه 1 جيجابايت فقط، يحتاج 1.5GB رام فقط على الـ CPU، وزمنه ~20 ثانية).
   * إجراء اختبار مقارنة بين التقرير المحلي والسحابي لتوثيقه في فصل المناقشة.
3. **يوم العرض والمناقشة:**
   * إن كان الجهاز مستقراً والموارد كافية: يُعرض بنمط `ollama` لإبراز ميزة العمل بلا إنترنت.
   * إن ظهر أي بطء أو ضغط غير متوقع: يُحول في ثوانٍ إلى `gemini` بضمان استقرار العرض 100%.

### 5.4 الرواية الهندسية والأكاديمية أمام لجنة التحكيم
عند مناقشة المشروع أمام اللجنة، لا يُقدم الأمر كـ "عجز في الأجهزة"، بل كـ **ميزة تصميم معماري متقدمة (Enterprise Flexibility)**:
> *"حرصنا في صَقْر على اتباع معمارية المؤسسات المرنة (Pluggable Architecture)؛ فالمؤسسات الدفاعية والسيادية التي تطبق عزلاً فيزيائياً صارماً (Air-gapped) تُشغّل صَقْر بالنمط المحلي (Local Mode عبر Ollama و Qwen2.5) لضمان عدم خروج أي بايت خارج الشبكة. بينما الفروع والمؤسسات المتوسطة تستطيع اختيار النمط السحابي (Cloud Mode عبر Gemini API) لتوفير تكلفة العتاد وتسريع استخراج التقارير. النظام يدعم الخيارين بسلاسة عبر سطر تكوين واحد."*

---

## 6. سيناريو الفدية الكامل خطوة بخطوة

### 6.1 قبل تشغيل الهجوم (الحالة النظيفة)
```
[OK] الآلة الافتراضية Windows 10 تعمل ومحفوظ لها Clean Snapshot
[OK] أدوات المراقبة Sysmon و Wazuh Agent تسجل وترسل الأحداث
[OK] حاويات Docker Compose تعمل (wazuh-manager, engine, postgres, dashboard, bot)
[OK] مجلد Honeypot التجريبي C:\test-files\ يحتوي 300 ملف حقيقي
[OK] مزامنة الوقت عبر NTP نشطة بين النظام المضيف والآلة الافتراضية
```

### 6.2 تشغيل الهجوم الآمن
```python
# lab/attack-engine/ransomware-sim/sim_ransom.py
import os, time, glob

HONEYPOT = r"C:\test-files"
START_TIME = time.time()  # تسجيل T0 الدقيق

files = glob.glob(f"{HONEYPOT}\\*")
for f in files:
    # محاكاة سلوك الفدية: قراءة جزئية وتغيير الامتداد بسرعة عالية
    os.rename(f, f + ".saqr_locked")
    time.sleep(0.01)

# محاكاة أمر حذف النسخ الاحتياطية الشهير
os.system("vssadmin delete shadows /all /quiet")

print(f"T0: {START_TIME} | Processed: {len(files)}")
```

### 6.3 التسلسل الزمني للاستجابة التلقائية
```
t=0.000s │ sim_ransom.py يبدأ العمل وتعديل الملفات
         │
t=0.010s │ Sysmon يرصد الأحداث: EventID 11 (File Create/Rename) و EventID 1 (vssadmin)
         │
t=0.100s │ Wazuh Agent يرسل الأحداث فوراً للمدير عبر منفذ 1514
         │
t=0.500s │ Wazuh Manager يطبق القواعد:
         │   Rule 100201: كشف تغيير جماعي (> 30 ملف خلال 5 ثوانٍ)
         │   Rule 100202: كشف محاولة حذف الظل vssadmin
         │
t=0.700s │ Wazuh يرسل Webhook فوري إلى محرك FastAPI (/alerts) ──► تسجيل T1
         │
t=0.705s │ محرك القرار الحتمي (FastAPI Correlator):
         │   مطابقة شروط الفدية المؤكدة ──► تسجيل T2 (قرار الاحتواء)
         │
t=0.710s │ إطلاق أوامر الاستجابة المتزامنة (SOAR Actions):
         │   1. أخذ Process Dump للعملية وحساب SHA-256 ──► تسجيل T3
         │   2. عزل الجهاز شبكياً بقطع حركة المرور عبر Windows Firewall ──► تسجيل T4
         │   3. إرسال إشعار عاجل عبر بوت Telegram للإدارة
         │
t=1.000s │ استدعاء طبقة الذكاء الاصطناعي (LLM Provider):
         │   إرسال بيانات الحادثة المجمعة لإنشاء التقرير العربي
         │   (يستغرق < 3 ثوانٍ في نمط Gemini أو ~20 ثانية في نمط Ollama 1.5B)
         │
t=3.500s │ لوحة Streamlit تتحدث تلقائياً:
         │   الحالة: 🔴 جهاز معزول | MTTD: 0.70s | MTTC: 1.15s | التقرير العربي جاهز
```

---

## 7. بروتوكول التجارب الـ 20 (Evaluation Protocol)

### 7.1 منهجية القياس العلمي
لضمان الدقة الأكاديمية والمصداقية الإحصائية أمام لجان التحكيم، يُنفذ سيناريو الهجوم 20 مرة متتالية ببروتوكول موحد لحساب:
* **متوسط زمن الكشف (Mean MTTD)** والانحراف المعياري.
* **متوسط زمن الاحتواء (Mean MTTC)** والانحراف المعياري.
* **نسبة الإنذارات الكاذبة (False Positive Rate)** عبر تشغيل تطبيقات اعتيادية ضخمة (نسخ احتياطي شرعي، ضغط ملفات).
* **مقارنة Red vs Blue:** توثيق الفرق الصادم بين غياب المنصة (تشفير 100% من الملفات بعد دقائق) ووجود المنصة (توقف الهجوم في أقل من ثانيتين مع حماية > 90% من الملفات).

### 7.2 سكريبت تشغيل التجارب الآلية
```python
# metrics/run_experiment.py
import subprocess, time, csv, requests, statistics
from datetime import datetime

RUNS = 20
RESULTS = []

def run_test(run_id):
    print(f"\n▶ بدء التجربة رقم {run_id}...")
    input("  تأكد من استعادة الـ Snapshot النظيف واضغط Enter...")
    time.sleep(3)
    
    # تشغيل محاكي الفدية على الضحية
    subprocess.Popen([
        "powershell.exe", "-Command",
        "Invoke-Command -VMName 'SAQR-Win10' -ScriptBlock { python C:\\lab\\sim_ransom.py }"
    ])
    
    # انتظار اكتمال الاستجابة
    time.sleep(15)
    
    # جلب التوقيتات المسجلة من المحرك
    data = requests.get("http://localhost:5000/metrics/latest").json()
    RESULTS.append(data)
    print(f"  [OK] تجربة {run_id}: MTTD={data['mttd_ms']}ms, MTTC={data['mttc_ms']}ms")

for i in range(1, RUNS + 1):
    run_test(i)

# حفظ النتائج في ملف CSV للأوراق البحثية
with open("saqr_experiment_results.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=RESULTS[0].keys())
    writer.writeheader()
    writer.writerows(RESULTS)

mttds = [r["mttd_ms"] for r in RESULTS]
mttcs = [r["mttc_ms"] for r in RESULTS]
print("\n" + "="*50)
print(f"متوسط زمن الكشف (MTTD): {statistics.mean(mttds):.1f} ms (انحراف: {statistics.stdev(mttds):.1f})")
print(f"متوسط زمن الاحتواء (MTTC): {statistics.mean(mttcs):.1f} ms (انحراف: {statistics.stdev(mttcs):.1f})")
```

---

## 8. إعداد البيئة خطوة بخطوة (Lab Setup)

### 8.1 ميزانية موارد الجهاز
```
المعالج:  Intel Core i5-1135G7 (4 أنوية / 8 خيوط)
الذاكرة:   16GB RAM:
          ├── 4.0GB مخصصة لـ Docker / WSL2
          ├── 3.5GB مخصصة للآلة الافتراضية Windows 10
          ├── 1.5GB مخصصة لـ Ollama (عند تفعيل النمط المحلي)
          └── 7.0GB لنظام التشغيل والمراقبة
المساحة:  استهلاك إجمالي ~60GB من أصل 90GB متوفرة
```

### 8.2 ملف .wslconfig (إلزامي في دليل المستخدم)
```ini
# C:\Users\<Username>\.wslconfig
[wsl2]
memory=4GB
processors=4
swap=2GB
localhostForwarding=true
networkingMode=mirrored
```

### 8.3 ملف Docker Compose
```yaml
# deploy/docker-compose.yml
version: "3.9"

services:
  wazuh-manager:
    image: wazuh/wazuh-manager:4.7.3
    container_name: saqr-wazuh
    ports:
      - "1514:1514/udp"
      - "1515:1515"
      - "55000:55000"
    volumes:
      - wazuh-data:/var/ossec/data
      - ./detection/wazuh/rules:/var/ossec/etc/rules/local:ro
    environment:
      - WAZUH_MANAGER_IP=0.0.0.0
    networks:
      - saqr-net

  postgres:
    image: postgres:16-alpine
    container_name: saqr-db
    environment:
      POSTGRES_DB: saqr
      POSTGRES_USER: saqr
      POSTGRES_PASSWORD: ${DB_PASSWORD:-saqr123}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - saqr-net

  engine:
    build: ../engine
    container_name: saqr-engine
    ports:
      - "5000:5000"
    environment:
      - DB_URL=postgresql://saqr:saqr123@postgres/saqr
      - WAZUH_URL=http://wazuh-manager:55000
      - LLM_PROVIDER=${LLM_PROVIDER:-gemini}
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - OLLAMA_URL=http://host.docker.internal:11434
      - TELEGRAM_TOKEN=${TELEGRAM_TOKEN}
      - TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}
    depends_on:
      - postgres
      - wazuh-manager
    networks:
      - saqr-net

  dashboard:
    build: ../dashboard
    container_name: saqr-dashboard
    ports:
      - "8501:8501"
    environment:
      - ENGINE_URL=http://engine:5000
    depends_on:
      - engine
    networks:
      - saqr-net

volumes:
  wazuh-data:
  postgres-data:

networks:
  saqr-net:
    internal: false
```

---

## 9. قواعد الكشف الرئيسية (Detection Rules)

```xml
<!-- detection/wazuh/rules/local_rules.xml -->
<group name="saqr,ransomware,">

  <!-- كشف التشفير الجماعي السريع -->
  <rule id="100201" level="14" frequency="30" timeframe="5">
    <if_matched_sid>60106</if_matched_sid>
    <description>SAQR: Rapid Mass File Modifications - Ransomware Indicator</description>
    <group>ransomware_indicator,</group>
  </rule>

  <!-- كشف محاولة حذف النسخ الاحتياطية -->
  <rule id="100202" level="15">
    <if_sid>61613</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)vssadmin.*delete.*shadows</field>
    <description>SAQR: Shadow Copies Deletion Attempt - Critical Impact</description>
    <group>ransomware_indicator,</group>
  </rule>

  <!-- الحادثة المركبة: إصدار أمر الاحتواء الفوري -->
  <rule id="100210" level="15">
    <if_matched_group>ransomware_indicator</if_matched_group>
    <description>SAQR: High-Confidence Ransomware Outbreak - Trigger Automated SOAR</description>
  </rule>

</group>
```

---

## 10. صياغة التقرير الأمني باللغة العربية (LLM Prompting)

```python
# ai/prompts/incident_analysis.txt

PROMPT_TEMPLATE = """أنت كبير محللي الاستجابة للحوادث السيبرانية في مركز عمليات الأمن (SOC).
تلقيت بيانات الحادثة الأمنية المحتواة آلياً التالية بصيغة JSON:

{incident_json}

المطلوب صياغة تقرير رسمي متكامل باللغة العربية وفق الأقسام التالية:

1. **الملخص التنفيذي:**
   شرح موجز وغير تقني موجه لإدارة المؤسسة يلخص ما حدث، وسلامة البيانات، ونجاح العزل التلقائي.

2. **التسلسل الزمني للحادثة (Timeline):**
   جدول زمني يوضح أوقات الهجوم (T0)، الكشف (T1)، اتخاذ القرار (T2)، حفظ الأدلة (T3)، والعزل التام (T4).

3. **مطابقة إطار MITRE ATT&CK:**
   ذكر التقنيات المرصودة (مثل T1486 للتشفير، T1490 لتعطيل استعادة النظام).

4. **الأدلة الجنائية المحفوظة:**
   اسم العملية المشبوهة، معرّفها (PID)، مسار ملف الذاكرة (Process Dump)، والتجزئة المشفرة SHA-256 لضمان حجية الدليل.

5. **الإجراءات التلقائية المتخذة:**
   تفاصيل تفعيل جدار الحماية وعزل الجهاز في زمن قياسي.

6. **التوصيات العلاجية الفورية:**
   خطوات مسح النظام، استعادة الملفات المتضررة، وتأمين بقية الشبكة.
"""
```

---

## 11. مقاييس تقييم جودة التقرير العربي (LLM Evaluation)

```python
# ai/eval/quality_metrics.py

EVALUATION_METRICS = {
    "completeness": {
        "weight": 0.25,
        "criteria": "اشتمال التقرير على الملخص، التايم لاين، والأدلة الجنائية"
    },
    "mitre_fidelity": {
        "weight": 0.25,
        "criteria": "صحة أرقام ومسميات تقنيات MITRE ATT&CK المذكورة"
    },
    "technical_consistency": {
        "weight": 0.30,
        "criteria": "تطابق قيم الهاش والأوقات والأرقام بدقة مع بيانات JSON المدخلة"
    },
    "arabic_clarity": {
        "weight": 0.20,
        "criteria": "سلامة التعبير الأمني العربي وخلوه من الركاكة أو الترجمة الحرفية"
    }
}
# التقييم الإجمالي = مجموع حاصل ضرب الدرجات بالأوزان (الهدف المعتمد > 8.0 / 10)
```

---

## 12. لوحة التحكم التفاعلية (Streamlit RTL)

```python
# dashboard/app.py
import streamlit as st
import requests

st.set_page_config(page_title="صَقْر | منصة الاستجابة الآلية", layout="wide", page_icon="🦅")
st.markdown('<style>body { direction: rtl; text-align: right; }</style>', unsafe_allow_html=True)

st.title("🦅 منصة صَقْر — مركز العمليات المصغر (Mini-SOC)")

col1, col2, col3, col4 = st.columns(4)
col1.metric("حالة المنظومة", "نشطة 🟢")
col2.metric("متوسط زمن الكشف (MTTD)", "0.72 ثانية", delta="-0.15s")
col3.metric("متوسط زمن الاحتواء (MTTC)", "1.18 ثانية", delta="آلي ⚡")
col4.metric("الأجهزة المحتجزة", "1 جهاز معزول 🔒")

st.markdown("---")
st.subheader("🚨 سجل الحوادث المباشر")
# عرض تفاصيل الحادثة الأخيرة والتقرير العربي الناتج
```

---

## 13. نموذج الـ Playbook المؤتمت (Ransomware Scenario)

```yaml
# soar/playbooks/ransomware.yaml
playbook_name: "Ransomware Automated Containment"
version: "2.0"
trigger_rules: [100201, 100202, 100210]

execution_flow:
  - step: 1
    action: "engine.record_timestamp"
    target: "T2"

  - step: 2
    action: "agent.capture_process_dump"
    params:
      tool: "procdump.exe"
      hash_algorithm: "SHA-256"
    record_metric: "T3"
    timeout_sec: 15

  - step: 3
    action: "agent.network_quarantine"
    params:
      method: "windows_firewall_rule"
      whitelist_ip: "wazuh_server_ip"
    record_metric: "T4"
    timeout_sec: 5

  - step: 4
    action: "notifier.telegram_broadcast"
    params:
      priority: "CRITICAL"

  - step: 5
    action: "ai.generate_arabic_report"
    mode: "async"
```

---

## 14. نطاق السيناريوهات للمشروع (سيمستر 1 و 2)

| السيناريو | السيمستر | الهدف العملي | آلية الاستجابة التلقائية |
|:----------|:---------|:-------------|:-------------------------|
| 🔴 **برامج الفدية (Ransomware)** | الأول (الأساسي) | وقف تشفير البيانات في ثوانٍ | Process Dump + عزل جدار الحماية + تقرير عربي |
| 🟡 **التصيد الاحتيالي (Phishing)** | الثاني | منع سرقة الجلسات والنطاقات المزورة | حظر النطاق بالجدار الناري + إلغاء الجلسات النشطة |
| 🟠 **حجب الخدمة الموزع (DDoS)** | الثاني | فرز الهجوم عن ذروة الاستخدام الطبيعية | Rate Limiting ديناميكي + حظر عناوين IP المهاجمة |

---

## 15. توزيع المهام على فريق العمل (5 طلاب)

| الطالب | المسمى والمسؤولية | المهام التنفيذية المحددة | مقياس الإنجاز |
|:-------|:-------------------|:-------------------------|:--------------|
| **الطالب 1** | مهندس المعمل والمحاكاة | تجهيز Win10 VM، وضبط محاكي الفدية، وإدارة Snapshots | ثبات سيناريو الهجوم في 20 تشغيلة متتالية |
| **الطالب 2** | مهندس الرصد واكتشاف التهديدات | ضبط Wazuh Manager و Sysmon وصياغة قواعد Sigma | رصد الهجوم بدقة > 95% وزمن كشف أقل من ثانيتين |
| **الطالب 3** | مهندس محرك القرار وقواعد البيانات | تطوير FastAPI ومحرك القواعد وتخزين جداول التوقيت | زمن معالجة الأحداث والقرار أقل من 50 مللي ثانية |
| **الطالب 4** | مهندس الاستجابة والذكاء الاصطناعي | كتابة سكريبتات العزل، وإدارة طبقة LLM Provider | عزل تام في أقل من 5 ثوانٍ وتقارير عربية متناسقة |
| **الطالب 5** | مسؤول القياسات ولوحة التحكم | بناء لوحة Streamlit، وبوت Telegram، وتنفيذ التجارب | جداول إحصائية ورسوم بيانية دقيقة لكتيب التخرج |

---

## 16. الجدول الزمني التنفيذي (15 أسبوعاً)

| الأسبوع | التركيز الهندسي | المخرجات المستهدفة (Milestones) |
|:--------|:----------------|:---------------------------------|
| **الأسبوع 1** | البنية التحتية والبيئة | ضبط `.wslconfig`، وتشغيل Docker Compose، وتجهيز VM الضحية |
| **الأسبوع 2 - 3** | خط الرصد الأول | تفعيل Sysmon و Wazuh Agent، والتحقق من ظهور الأحداث الحية |
| **الأسبوع 4 - 5** | محاكي الفدية وقواعد الكشف | كتابة `sim_ransom.py` الآمن، واعتماد قواعد Wazuh للكشف السريع |
| **الأسبوع 6 - 7** | محرك القرار والاستجابة | ربط Webhook بـ FastAPI، وتنفيذ سكريبت العزل وحفظ الأدلة الجنائية |
| **الأسبوع 8 - 9** | طبقة الذكاء الاصطناعي الهجينة | تطبيق `LLMProvider` (الربط بـ Gemini API وتجربة Ollama المحلي) |
| **الأسبوع 10 - 11** | لوحة التحكم وبوت Telegram | إتمام لوحة Streamlit العربية، وتفعيل إشعارات التنبيه المباشرة |
| **الأسبوع 12** | فحص التكامل والتنقيح | اختبار الدورة الكاملة من نقرة الهجوم إلى صدور التقرير النهائي |
| **الأسبوع 13** | جلسات القياس الـ 20 | تشغيل بروتوكول القياس وحساب متوسطات MTTD و MTTC ونسب الحماية |
| **الأسبوع 14** | إعداد التقرير والمصنف | توثيق النتائج بالرسوم البيانية، وتسجيل فيديو تجريبي احتياطي (Demo) |
| **الأسبوع 15** | بروفات العرض النهائي | محاكاة المناقشة أمام اللجنة والتأكد من جاهزية نمطي AI |

---

## 17. المخرجات المسلمة للجنة التحكيم

| المخرج | شكل التسليم | معيار التقييم والقبول |
|:-------|:------------|:----------------------|
| **مستودع الكود المنظم** | Git Repository موثق | إمكانية تشغيل المنظومة بسهولة عبر سكريبت موحد |
| **عرض حي متكامل (Live Demo)** | تشغيل فعلي أمام اللجنة | اكتمال حلقة: هجوم ──► كشف ──► عزل ──► تقرير عربي |
| **بيانات التجارب الإحصائية** | جداول CSV ورسوم بيانية | توثيق 20 تشغيلة قياسية بمتوسط MTTD < 2s و MTTC < 5s |
| **كتيب تقرير التخرج** | تقرير أكاديمي رسمي | توثيق المعمارية الهجينة، والمنهجية العلمية، وتحليل النتائج |
| **فيديو العرض الاحتياطي** | فيديو عالي الدقة (10 دقائق) | ضمان تقديم المشروع بسلاسة حتى لو حدث أي طارئ تقني |

---

> [!IMPORTANT]
> **القاعدة الحاكمة للمشروع:** قرارات العزل وحفظ الأدلة تُتخذ فورياً وبشكل **حتمي 100% (Deterministic Engine)** دون انتظار الـ LLM. دور الذكاء الاصطناعي هو التحليل وصياغة التقارير **بعد اكتمال الاحتواء**، مما يضمن أمان وسرعة المنظومة.

> [!CAUTION]
> **قواعد السلامة المعملية:** يُحظر تشغيل محاكي الفدية خارج المجلد المخصص (`C:\test-files\`) داخل الآلة الافتراضية المعزولة شبكياً. يجب التأكد دائماً من وجود لقطة نظيفة (Clean Snapshot) قبل بدء أي تجربة.
