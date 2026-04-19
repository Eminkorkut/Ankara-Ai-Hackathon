from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse

from backend.schemas import (
    AgentLogListResponse,
    AlertListResponse,
    AnalyzeResponse,
    BlockIpRequest,
    BlockIpResponse,
    HealthResponse,
    ReportResponse,
    SandboxEventsResponse,
    ThreatListResponse,
    ThreatRecord,
)
from backend.services.analyzer import LocalThreatModel
from backend.services.reporting import build_report_docx, build_report_payload

MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024
BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="Agentic SOC Hackathon Servisi",
    version="0.1.0",
    description="Yerel dosya tehdit analizi gosterimi için FastAPI backend.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = LocalThreatModel()
threat_store: deque[ThreatRecord] = deque(maxlen=120)
alert_store: deque[str] = deque(maxlen=250)
agent_log_store: deque[str] = deque(maxlen=250)
network_event_store: deque[str] = deque(maxlen=120)
file_event_store: deque[str] = deque(maxlen=120)
blocked_ips: set[str] = set()


def now_label() -> str:
    return datetime.now(UTC).strftime("%H:%M:%S")


def register_alert(message: str) -> None:
    alert_store.appendleft(f"{now_label()} {message}")


def register_log(message: str) -> None:
    agent_log_store.appendleft(f"{now_label()} {message}")


def register_network_event(message: str) -> None:
    network_event_store.appendleft(f"{now_label()} {message}")


def register_file_event(message: str) -> None:
    file_event_store.appendleft(f"{now_label()} {message}")


def seed_demo_data() -> None:
    if threat_store:
        return

    samples = [
        (
            "invoice_update_2026.exe",
            b"MZ powershell invoke-webrequest https://c2-demo.local cmd.exe reg add",
            "185.220.101.77",
        ),
        (
            "gov_docs_patch.scr",
            b"MZ cmd.exe base64 https://sync-agent.local",
            "45.134.26.190",
        ),
        (
            "annual_report_template.docm",
            b"macro data https://legit-looking-site.example",
            "104.244.77.12",
        ),
    ]

    for file_name, payload, ip in samples:
        threat = model.analyze(file_name, payload, ip)
        threat_store.appendleft(threat)

    register_alert("[KRITIK] Zararli yuk endpoint EDR kuyruguna girdi.")
    register_alert("[YUKSEK] Tehdit triyaji için ajan zinciri baslatildi.")
    register_log("LLM ilk tehdit örneklerini analiz ediyor...")
    register_log("Sandbox calistirma izole VM'de basladi...")
    register_network_event("10.30.5.21 -> 185.220.101.77 : 443")
    register_file_event("tmp/dropper.bin oluşturuldu")


seed_demo_data()


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        llm="online",
        agents="running",
        sandbox="active",
        threat_count=len(threat_store),
        blocked_ip_count=len(blocked_ips),
    )


@app.get("/api/threats", response_model=ThreatListResponse)
def list_threats(limit: int = 20) -> ThreatListResponse:
    safe_limit = max(1, min(limit, 100))
    return ThreatListResponse(threats=list(threat_store)[:safe_limit])


@app.get("/api/alerts", response_model=AlertListResponse)
def list_alerts(limit: int = 30) -> AlertListResponse:
    safe_limit = max(1, min(limit, 100))
    return AlertListResponse(alerts=list(alert_store)[:safe_limit])


@app.get("/api/agent-logs", response_model=AgentLogListResponse)
def list_agent_logs(limit: int = 30) -> AgentLogListResponse:
    safe_limit = max(1, min(limit, 100))
    return AgentLogListResponse(logs=list(agent_log_store)[:safe_limit])


@app.get("/api/sandbox-events", response_model=SandboxEventsResponse)
def list_sandbox_events(limit: int = 20) -> SandboxEventsResponse:
    safe_limit = max(1, min(limit, 100))
    return SandboxEventsResponse(
        network_events=list(network_event_store)[:safe_limit],
        file_events=list(file_event_store)[:safe_limit],
    )


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_file(file: UploadFile = File(...), source_ip: str | None = Form(default=None)) -> AnalyzeResponse:
    payload = await file.read()
    filename = file.filename or "yuklenen.bin"

    if not payload:
        raise HTTPException(status_code=400, detail="Yuklenen dosya bos.")

    if len(payload) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Dosya demo yukleme limiti için cok buyuk.")

    threat = model.analyze(filename=filename, payload=payload, source_ip=source_ip)
    threat_store.appendleft(threat)

    severity_tr = {
        "critical": "KRITIK",
        "medium": "ORTA",
        "low": "DUSUK",
    }
    decision_tr = {
        "malicious": "ZARARLI",
        "suspicious": "SUPHELI",
        "under_review": "INCELEMEDE",
        "benign": "TEMIZ",
    }

    alerts = [
        f"[{severity_tr.get(threat.severity, threat.severity.upper())}] Yuklenen dosya analiz edildi: {threat.file_name}",
        f"[{decision_tr.get(threat.decision, threat.decision.upper())}] Skor={threat.risk_score} tehdit_id={threat.id}",
    ]
    agent_logs = [
        "LLM yuklenen dosyayi analiz ediyor...",
        "Sandbox calistirma basladi...",
        f"Davranis profili: {threat.behavior}",
        f"Uretilen karar: {threat.decision}",
    ]
    network_events = [
        f"10.30.5.21 -> {threat.source_ip} : 443",
        f"10.30.5.21 -> {threat.source_ip} : 8080",
    ]
    file_events = [
        f"{threat.file_name} sandbox ortamina yüklendi",
        "runtime/profile_trace.json oluşturuldu",
    ]

    for item in alerts:
        register_alert(item)
    for item in agent_logs:
        register_log(item)
    for item in network_events:
        register_network_event(item)
    for item in file_events:
        register_file_event(item)

    return AnalyzeResponse(
        threat=threat,
        alerts=alerts,
        agent_logs=agent_logs,
        network_events=network_events,
        file_events=file_events,
    )


@app.post("/api/block-ip", response_model=BlockIpResponse)
def block_ip(request: BlockIpRequest) -> BlockIpResponse:
    blocked_ips.add(request.ip)
    reason = f" neden={request.reason}" if request.reason else ""

    register_alert(f"[KRITIK] {request.ip} için otomatik muhafaza calistirildi.")
    register_log(f"Muhafaza ajani onayladi: IP engellendi ({request.ip}).")
    register_network_event(f"firewall engelle kurali -> {request.ip}{reason}")

    return BlockIpResponse(
        blocked=True,
        message=f"{request.ip} muhafaza politikasi ile engellendi.",
        blocked_ips=sorted(blocked_ips),
    )


@app.get("/api/report/{threat_id}", response_model=ReportResponse)
def generate_report(threat_id: str) -> ReportResponse:
    threat = next((item for item in threat_store if item.id == threat_id), None)
    if threat is None:
        raise HTTPException(status_code=404, detail=f"Tehdit bulunamadi: {threat_id}")

    report = build_report_payload(
        threat=threat,
        blocked_ip=threat.source_ip in blocked_ips,
        latest_alerts=list(alert_store)[:6],
        latest_agent_logs=list(agent_log_store)[:6],
    )
    register_log(f"Rapor ajani {threat.id} için olay raporu oluşturdu.")
    return ReportResponse(report=report)


@app.get("/api/report/{threat_id}/docx")
def download_report_docx(threat_id: str) -> StreamingResponse:
    threat = next((item for item in threat_store if item.id == threat_id), None)
    if threat is None:
        raise HTTPException(status_code=404, detail=f"Tehdit bulunamadi: {threat_id}")

    report = build_report_payload(
        threat=threat,
        blocked_ip=threat.source_ip in blocked_ips,
        latest_alerts=list(alert_store)[:6],
        latest_agent_logs=list(agent_log_store)[:6],
    )
    payload = build_report_docx(report)
    register_log(f"Word raporu oluşturuldu ({threat.id}).")

    filename = f"olay_raporu_{threat.id}.docx"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(
        BytesIO(payload),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers=headers,
    )


@app.get("/", include_in_schema=False)
def serve_index() -> FileResponse:
    return FileResponse(BASE_DIR / "index.html")


@app.get("/styles.css", include_in_schema=False)
def serve_styles() -> FileResponse:
    return FileResponse(BASE_DIR / "styles.css", media_type="text/css")


@app.get("/script.js", include_in_schema=False)
def serve_script() -> FileResponse:
    return FileResponse(BASE_DIR / "script.js", media_type="application/javascript")


def serve_gradcam_asset(file_name: str) -> FileResponse:
    return FileResponse(BASE_DIR / file_name, media_type="image/png")


@app.get("/gradcam_example_1.png", include_in_schema=False)
def serve_gradcam_1() -> FileResponse:
    return serve_gradcam_asset("gradcam_example_1.png")


@app.get("/gradcam_example_2.png", include_in_schema=False)
def serve_gradcam_2() -> FileResponse:
    return serve_gradcam_asset("gradcam_example_2.png")


@app.get("/gradcam_example_3.png", include_in_schema=False)
def serve_gradcam_3() -> FileResponse:
    return serve_gradcam_asset("gradcam_example_3.png")
