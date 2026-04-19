const API_BASE = "/api";

let backendAvailable = false;
let currentReport = null;
let currentReportThreatId = null;
const blockedIps = new Set();

let threats = [
  {
    id: "T-2041",
    fileName: "invoice_update_2026.exe",
    riskScore: 96,
    sourceIp: "185.220.101.77",
    behavior: "PowerShell çalıştırma + kimlik bilgisi dökümü denemesi",
    severity: "critical",
    confidence: 0.93,
    reasoning: [
      "Şşüpheli C2 dış bağlantısı tespit edildi",
      "Bilinen malware imzası eşleşti",
      "Sandbox ortamında yetki yükseltme davranışı gözlemlendi",
    ],
    decision: "malicious",
    sha256: "demo",
    fileSizeBytes: 391232,
    createdAt: new Date().toISOString(),
  },
  {
    id: "T-2038",
    fileName: "gov_docs_patch.scr",
    riskScore: 78,
    sourceIp: "45.134.26.190",
    behavior: "Registry kalıcılığı + şüpheli child process",
    severity: "medium",
    confidence: 0.79,
    reasoning: [
      "Başlangıç registry anahtarı değiştirildi",
      "Güvenilmeyen script gizli süreç başlattı",
      "Güvenilmeyen ASN ile bağlantı görüldü",
    ],
    decision: "suspicious",
    sha256: "demo",
    fileSizeBytes: 242872,
    createdAt: new Date().toISOString(),
  },
  {
    id: "T-2035",
    fileName: "annual_report_template.docm",
    riskScore: 52,
    sourceIp: "104.244.77.12",
    behavior: "Makro uzaktan payload çekmeye çalışıyor",
    severity: "low",
    confidence: 0.61,
    reasoning: [
      "Makro çalışması politika dışında",
      "Alışılmadık domaine tek uzak çağrı yapıldı",
      "Sandbox ortamında yanal hareket görülmedi",
    ],
    decision: "under_review",
    sha256: "demo",
    fileSizeBytes: 122512,
    createdAt: new Date().toISOString(),
  },
];

const alertTemplates = [
  { level: "KRİTİK", text: "Dış trafik akışında şüpheli IP tespit edildi." },
  { level: "YÜKSEK", text: "Malware benzeri process ağacı gözlemlendi." },
  { level: "ORTA", text: "Anormal script çalıştırma davranışı algılandı." },
  { level: "BİLGİ", text: "Tehdit istihbaratı akışı güncellendi." },
  { level: "YÜKSEK", text: "Olası kalıcılık mekanizması tespit edildi." },
];

const agentTemplates = [
  "LLM dosya yapısını analiz ediyor...",
  "Sandbox çalıştırma izole VM'de başladı...",
  "Süreç zincirinde davranış anomalisi tespit edildi...",
  "Tehdit triyaj ajanı risk skorunu hesaplıyor...",
  "Muhafaza ajanı engelleme aksiyonunu hazırlıyor...",
  "Hukuk ajanı uyumluluk özetini üretiyor...",
  "Rapor ajanı olay zaman çizelgesini topluyor...",
];

const networkTemplates = [
  "10.30.5.21 -> 185.220.101.77 : 443",
  "10.30.5.21 -> 45.134.26.190 : 8080",
  "10.30.5.21 -> 104.244.77.12 : 53",
  "10.30.5.21 -> 91.218.114.31 : 8443",
  "10.30.5.21 -> 194.26.192.44 : 22",
];

const fileTemplates = [
  "tmp/dropper.bin oluşturuldu",
  "startup.ps1 değiştirildi",
  "credentials.tmp okuma denemesi",
  "registry.dat yazma aksiyonu",
  "task_scheduler.xml enjekte edildi",
  "shadow_copy sorgulandı",
];

const terminalTemplates = [
  "[orkestratör] gelen telemetri paketi kabul edildi",
  "[analiz] embedding + sınıflandırıcı güveni eşiğin üstünde",
  "[sandbox] syscall anomali sayısı arttı",
  "[yanıt] politika motoru otomatik muhafazaya ayarlandı",
  "[denetim] açıklanabilirlik çıktıları analist için hazırlandı",
  "[operasyon] panel son kararla senkronlandı",
];

const flowLabels = [
  "1. Veri Alımı",
  "2. LLM Analizi",
  "3. Araç Seçimi",
  "4. Ajan Çalıştırma",
  "5. Karar",
  "6. Panel Güncelleme",
];

const gradcamProfiles = [
  {
    imagePath: "./gradcam_example_1.png",
    focusSummary: "başlangıç bloklarinda yoğun aktivasyon bölgesini gösteriyor.",
    analysisNote: "başlangıç bölgesindeki executable tetikleyici paternine odaklanıyor.",
  },
  {
    imagePath: "./gradcam_example_2.png",
    focusSummary: "orta katmanda toplanan anomali sinyallerini vurguluyor.",
    analysisNote: "orta bölgede script/registry davranış zincirine odaklanıyor.",
  },
  {
    imagePath: "./gradcam_example_3.png",
    focusSummary: "üst bölgedeki dağınık fakat kalıcı risk sinyalini işaretliyor.",
    analysisNote: "makro ve uzaktan çağrıların birleştiği bölgeye odaklanıyor.",
  },
];

function getThreatGradcamProfile(threat) {
  if (!threat || threats.length === 0) {
    return gradcamProfiles[2];
  }

  const threatIndex = threats.findIndex((item) => item.id === threat.id);
  if (threatIndex < 0) {
    return gradcamProfiles[2];
  }

  return gradcamProfiles[threatIndex % gradcamProfiles.length];
}

let selectedThreat = null;
let flowIndex = 0;
let healthTelemetry = {
  llm: "online",
  agents: "running",
  sandbox: "active",
};
let lastAlertSignature = "";
let lastTerminalSignature = "";

const refs = {
  activeThreatCount: document.getElementById("activeThreatCount"),
  criticalThreatCount: document.getElementById("criticalThreatCount"),
  mediumThreatCount: document.getElementById("mediumThreatCount"),
  lowThreatCount: document.getElementById("lowThreatCount"),
  criticalBar: document.getElementById("criticalBar"),
  mediumBar: document.getElementById("mediumBar"),
  lowBar: document.getElementById("lowBar"),
  threatList: document.getElementById("threatList"),
  threatDetailContent: document.getElementById("threatDetailContent"),
  liveAlertsList: document.getElementById("liveAlertsList"),
  agentLogList: document.getElementById("agentLogList"),
  networkEvents: document.getElementById("networkEvents"),
  fileEvents: document.getElementById("fileEvents"),
  terminalOutput: document.getElementById("terminalOutput"),
  actionFeedback: document.getElementById("actionFeedback"),
  uploadFeedback: document.getElementById("uploadFeedback"),
  uploadSubmitBtn: document.getElementById("uploadSubmitBtn"),
  autoBlockBtn: document.getElementById("autoBlockBtn"),
  generateReportBtn: document.getElementById("generateReportBtn"),
  downloadReportBtn: document.getElementById("downloadReportBtn"),
  reportModal: document.getElementById("reportModal"),
  reportReadable: document.getElementById("reportReadable"),
  closeReportBtn: document.getElementById("closeReportBtn"),
  flowSteps: document.getElementById("flowSteps"),
  lastUpdate: document.getElementById("lastUpdate"),
  llmStatus: document.getElementById("llmStatus"),
  agentStatus: document.getElementById("agentStatus"),
  sandboxStatus: document.getElementById("sandboxStatus"),
  uploadForm: document.getElementById("uploadForm"),
  dragDropZone: document.getElementById("dragDropZone"),
  dragDropText: document.getElementById("dragDropText"),
  threatFileInput: document.getElementById("threatFileInput"),
  sourceIpInput: document.getElementById("sourceIpInput"),
  modelRuntimeLine: document.getElementById("modelRuntimeLine"),
  simProgressBar: document.getElementById("simProgressBar"),
  simProgressPercent: document.getElementById("simProgressPercent"),
  simProgressStage: document.getElementById("simProgressStage"),
  simSteps: document.getElementById("simSteps"),
  xaiBadge: document.getElementById("xaiBadge"),
  xaiDecision: document.getElementById("xaiDecision"),
  xaiDecisionCode: document.getElementById("xaiDecisionCode"),
  xaiConfidenceBar: document.getElementById("xaiConfidenceBar"),
  xaiConfidenceText: document.getElementById("xaiConfidenceText"),
  mcpTerminal: document.getElementById("mcpTerminal"),
  mcpFindings: document.getElementById("mcpFindings"),
  gradcamImage: document.getElementById("gradcamImage"),
  gradcamCaption: document.getElementById("gradcamCaption"),
  llmComment: document.getElementById("llmComment"),
  xaiThoughts: document.getElementById("xaiThoughts"),
  xaiCounters: document.getElementById("xaiCounters"),
  xaiUncertainty: document.getElementById("xaiUncertainty"),
  inferenceSimBox: document.getElementById("inferenceSimBox"),
  analysisModal: document.getElementById("analysisModal"),
  analysisCloseBtn: document.getElementById("analysisCloseBtn"),
  analysisSummary: document.getElementById("analysisSummary"),
  analysisDecision: document.getElementById("analysisDecision"),
  analysisRiskScore: document.getElementById("analysisRiskScore"),
  analysisConfidence: document.getElementById("analysisConfidence"),
  analysisThreatId: document.getElementById("analysisThreatId"),
  analysisSourceIp: document.getElementById("analysisSourceIp"),
  analysisLlmComment: document.getElementById("analysisLlmComment"),
  analysisGradcamImage: document.getElementById("analysisGradcamImage"),
  analysisGradcamCaption: document.getElementById("analysisGradcamCaption"),
  analysisStepSummary: document.getElementById("analysisStepSummary"),
  analysisCreateReportBtn: document.getElementById("analysisCreateReportBtn"),
  analysisBlockIpBtn: document.getElementById("analysisBlockIpBtn"),
};

function nowLabel() {
  return new Date().toLocaleTimeString("tr-TR", { hour12: false });
}

function randomItem(items) {
  return items[Math.floor(Math.random() * items.length)];
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function decisionLabel(value) {
  const map = {
    malicious: "zararlı",
    suspicious: "şüpheli",
    under_review: "incelemede",
    benign: "temiz",
  };
  return map[value] || value;
}

function severityLabel(value) {
  const map = {
    critical: "kritik",
    medium: "orta",
    low: "düşük",
  };
  return map[value] || value;
}

function clampList(listElement, max = 9) {
  while (listElement.children.length > max) {
    listElement.removeChild(listElement.lastChild);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function listHtml(items, ordered = false) {
  const tag = ordered ? "ol" : "ul";
  const rows = items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  return `<${tag} class="report-list">${rows}</${tag}>`;
}

function normalizeApiThreat(apiThreat) {
  return {
    id: apiThreat.id,
    fileName: apiThreat.file_name,
    riskScore: apiThreat.risk_score,
    sourceIp: apiThreat.source_ip,
    behavior: apiThreat.behavior,
    severity: apiThreat.severity,
    confidence: apiThreat.confidence,
    reasoning: apiThreat.reasoning,
    decision: apiThreat.decision,
    sha256: apiThreat.sha256,
    fileSizeBytes: apiThreat.file_size_bytes,
    createdAt: apiThreat.created_at,
  };
}

function splitTimestamp(rawText) {
  const match = rawText.match(/^(\d{2}:\d{2}:\d{2})\s+(.*)$/);
  if (!match) {
    return { time: nowLabel(), message: rawText };
  }
  return { time: match[1], message: match[2] };
}

function alertSeverityClass(level) {
  const normalized = String(level || "").toUpperCase();
  if (normalized.includes("KRIT") || normalized.includes("CRIT") || normalized.startsWith("KR")) {
    return "critical";
  }
  if (
    normalized.includes("YUKSEK") ||
    normalized.includes("HIGH") ||
    normalized.includes("ZARARLI") ||
    normalized.includes("MALICIOUS") ||
    normalized.startsWith("YU") ||
    normalized.startsWith("YÜƒ")
  ) {
    return "high";
  }
  if (
    normalized.includes("ORTA") ||
    normalized.includes("MEDIUM") ||
    normalized.includes("SUPHELI") ||
    normalized.includes("SUSPICIOUS") ||
    normalized.startsWith("OR")
  ) {
    return "medium";
  }
  if (normalized.includes("DUSUK") || normalized.includes("LOW") || normalized.startsWith("DU")) {
    return "low";
  }
  return "info";
}

function appendAlert(level, text, prepend = true, time = nowLabel()) {
  if (!refs.liveAlertsList) {
    return;
  }
  const li = document.createElement("li");
  li.className = `alert-item level-${alertSeverityClass(level)}`;
  li.innerHTML = `<span class="time">${time}</span><strong>[${level}]</strong> ${text}`;
  if (prepend) {
    refs.liveAlertsList.prepend(li);
  } else {
    refs.liveAlertsList.appendChild(li);
  }
  clampList(refs.liveAlertsList, 12);
}

function normalizeAlertLevel(level) {
  const map = {
    CRITICAL: "KRITIK",
    HIGH: "YUKSEK",
    MEDIUM: "ORTA",
    LOW: "DUSUK",
    INFO: "BILGI",
    MALICIOUS: "ZARARLI",
    SUSPICIOUS: "SUPHELI",
    UNDER_REVIEW: "INCELEME",
    BENIGN: "TEMIZ",
  };
  return map[level] || level;
}

function appendAlertEntry(rawEntry, prepend = false) {
  const parsed = splitTimestamp(rawEntry);
  const levelMatch = parsed.message.match(/^\[([A-Z_]+)\]\s*(.*)$/);
  if (levelMatch) {
    appendAlert(normalizeAlertLevel(levelMatch[1]), levelMatch[2], prepend, parsed.time);
    return;
  }
  appendAlert("BILGI", parsed.message, prepend, parsed.time);
}

function appendAgentLog(text, prepend = true, time = nowLabel()) {
  if (!refs.agentLogList) {
    return;
  }
  const li = document.createElement("li");
  li.className = "terminal-item";
  li.innerHTML = `<span class="time">${time}</span>${text}`;
  if (prepend) {
    refs.agentLogList.prepend(li);
  } else {
    refs.agentLogList.appendChild(li);
  }
  clampList(refs.agentLogList, 11);
}

function appendAgentLogEntry(rawEntry, prepend = false) {
  const parsed = splitTimestamp(rawEntry);
  appendAgentLog(parsed.message, prepend, parsed.time);
}

function appendEvent(list, text, prepend = true, time = nowLabel()) {
  if (!list) {
    return;
  }
  const li = document.createElement("li");
  li.className = "event-item";
  li.innerHTML = `<span class="time">${time}</span>${text}`;
  if (prepend) {
    list.prepend(li);
  } else {
    list.appendChild(li);
  }
  clampList(list, 8);
}

function appendEventEntry(list, rawEntry, prepend = false) {
  const parsed = splitTimestamp(rawEntry);
  appendEvent(list, parsed.message, prepend, parsed.time);
}

function appendTerminal(text) {
  const line = `${nowLabel()} ${text}`;
  refs.terminalOutput.textContent = `${line}\n${refs.terminalOutput.textContent}`.slice(0, 2800);
}

function getRiskStory(threat) {
  if (threat.riskScore >= 90) {
    return "Risk seviyesi çok yüksek. Hemen muhafaza ve erişim kesme aksiyonu gerekir.";
  }
  if (threat.riskScore >= 75) {
    return "Risk seviyesi yüksek. Yayılım riski nedeniyle hızlı izolasyon önerilir.";
  }
  if (threat.riskScore >= 55) {
    return "Risk seviyesi orta. Kontrollü engelleme ile manuel teyit birlikte ilerlemeli.";
  }
  return "Risk seviyesi düşük. İzleme ve ek telemetri toplama yaklaşımı daha uygun.";
}

function getXaiInsights(threat) {
  const confidencePercent = Math.round(threat.confidence * 100);
  const extension = threat.fileName.includes(".") ? threat.fileName.split(".").pop().toLowerCase() : "bilinmiyor";
  const thoughts = [
    "Dosya uzantısı ve davranış sinyali aynı yöne bakıyor, skor yükseltiliyor.",
    "Davranış zincirinde niyet değişimi olduğu için otomatik muhafaza önerildi.",
    "Yanlış pozitif ihtimalini azaltmak için karşı görüşler de rapora eklendi.",
  ];

  if (threat.decision === "benign") {
    thoughts.splice(
      0,
      thoughts.length,
      "Güçlü zararlılık sinyali yok, fakat izleme kaldırılmadı.",
      "Sistem bu dosyayı temiz kabul etti ama takip kaydı açık kaldı.",
      "Karar güven seviyesi ortalama olduğu için manuel gözden geçirme önerildi.",
    );
  } else if (threat.decision === "malicious") {
    thoughts.push("Birden fazla bağımsız sinyal aynı sonuça ulaştığı için karar sertleştirildi.");
  }

  const counters = [
    "Tek bir imza eşleşmesi yanlış pozitif olabilir; davranış bağlamı izlenmeli.",
    "IP adresi paylaşımlı altyapı olabilir; threat-intel teyidi gerekli.",
    "Sandbox ortamı ile üretim ortamı farklı davranış üretebilir.",
  ];

  const uncertainty =
    confidencePercent >= 90
      ? "Belirsizlik düşük: model güveni yüksek."
      : confidencePercent >= 75
        ? "Belirsizlik orta: model güveni kabul edilebilir."
        : "Belirsizlik yüksek: ek analist doğrulaması gerekli.";

  const signals = [
    `Dosya uzantısı sinyali: .${extension}`,
    `Davranış etiketi: ${threat.behavior}`,
    `SHA256 izi: ${threat.sha256.slice(0, 18)}...`,
    `Dosya boyutu: ${threat.fileSizeBytes} bayt`,
  ];

  return {
    confidencePercent,
    story: getRiskStory(threat),
    signals,
    thoughts,
    counters,
    uncertainty,
  };
}

function renderThreatOverview() {
  const total = Math.max(threats.length, 1);
  const critical = threats.filter((item) => item.severity === "critical").length;
  const medium = threats.filter((item) => item.severity === "medium").length;
  const low = threats.filter((item) => item.severity === "low").length;

  refs.activeThreatCount.textContent = String(threats.length);
  refs.criticalThreatCount.textContent = String(critical);
  refs.mediumThreatCount.textContent = String(medium);
  refs.lowThreatCount.textContent = String(low);

  refs.criticalBar.style.width = `${(critical / total) * 100}%`;
  refs.mediumBar.style.width = `${(medium / total) * 100}%`;
  refs.lowBar.style.width = `${(low / total) * 100}%`;

  refs.threatList.innerHTML = "";
  threats.forEach((threat) => {
    const item = document.createElement("article");
    const isActive = selectedThreat && threat.id === selectedThreat.id ? "active" : "";
    item.className = `threat-item ${isActive}`;
    item.innerHTML = `
      <div class="top">
        <strong>${escapeHtml(threat.fileName)}</strong>
        <span class="${threat.severity}">${threat.riskScore}</span>
      </div>
      <p class="meta">${escapeHtml(threat.id)} â€” ${escapeHtml(threat.sourceIp)}</p>
    `;
    item.addEventListener("click", () => {
      selectedThreat = threat;
      renderThreatOverview();
      renderThreatDetail();
      renderXai();
      appendAlert("YÜKSEK", `${threat.id} tehdit kartı açıldı.`);
      appendTerminal(`[ui] analist ${threat.fileName} dosyasını açtı`);
    });
    refs.threatList.appendChild(item);
  });
}

function renderThreatDetail() {
  if (!selectedThreat) {
    refs.threatDetailContent.innerHTML = `<p class="xai-muted" style="text-align: center; padding: 20px;">Analiz detaylarını görmek için sol taraftan bir tehdit seçin veya yeni dosya yükleyin.</p>`;
    return;
  }
  
  refs.threatDetailContent.innerHTML = `
    <article class="detail-item">
      <p>Tehdit ID</p>
      <strong>${escapeHtml(selectedThreat.id)}</strong>
    </article>
    <article class="detail-item">
      <p>Dosya Adı</p>
      <strong>${escapeHtml(selectedThreat.fileName)}</strong>
    </article>
    <article class="detail-item">
      <p>Risk Skoru</p>
      <strong class="${selectedThreat.severity}">${selectedThreat.riskScore} / 100</strong>
    </article>
    <article class="detail-item">
      <p>Kaynak IP</p>
      <strong>${escapeHtml(selectedThreat.sourceIp)}</strong>
    </article>
    <article class="detail-item">
      <p>Davranış Analizi</p>
      <strong>${escapeHtml(selectedThreat.behavior)}</strong>
    </article>
    <article class="detail-item">
      <p>Karar</p>
      <strong>${escapeHtml(decisionLabel(selectedThreat.decision))}</strong>
    </article>
  `;
}

function fillList(listEl, items) {
  listEl.innerHTML = "";
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    listEl.appendChild(li);
  });
}

function addSimStep(text) {
  const li = document.createElement("li");
  li.textContent = text;
  refs.simSteps.prepend(li);
  while (refs.simSteps.children.length > 7) {
    refs.simSteps.removeChild(refs.simSteps.lastChild);
  }
}

function setSimProgress(progress, line) {
  refs.simProgressBar.style.width = `${progress}%`;
  refs.modelRuntimeLine.textContent = line;
  refs.simProgressPercent.textContent = `${Math.round(progress)}%`;
  refs.simProgressStage.textContent = line;
}

function collectSimStepSummary() {
  const items = [];
  refs.simSteps.querySelectorAll("li").forEach((item) => {
    items.push(item.textContent || "");
  });
  return items.reverse();
}

function openAnalysisModal(threat, fileName) {
  const gradcamProfile = getThreatGradcamProfile(threat);
  refs.analysisSummary.textContent =
    `${fileName} için demo inference tamamlandı. Karar ${decisionLabel(threat.decision)} olarak oluştu.`;
  refs.analysisDecision.textContent = `${decisionLabel(threat.decision)} (${severityLabel(threat.severity)})`;
  refs.analysisRiskScore.textContent = `${threat.riskScore} / 100`;
  refs.analysisConfidence.textContent = `%${Math.round(threat.confidence * 100)}`;
  refs.analysisThreatId.textContent = threat.id;
  refs.analysisSourceIp.textContent = threat.sourceIp;
  refs.analysisLlmComment.textContent = llmNarrative(threat, fileName, threat.sourceIp);
  refs.analysisGradcamImage.src = `${gradcamProfile.imagePath}?t=${Date.now()}`;
  refs.analysisGradcamCaption.textContent = `Grad-CAM odağı ${threat.id} için ${gradcamProfile.analysisNote}`;

  const steps = collectSimStepSummary();
  refs.analysisStepSummary.innerHTML = "";
  steps.forEach((step) => {
    const li = document.createElement("li");
    li.textContent = step;
    refs.analysisStepSummary.appendChild(li);
  });

  refs.analysisModal.classList.add("open");
  refs.analysisModal.setAttribute("aria-hidden", "false");
}

function closeAnalysisModal() {
  refs.analysisModal.classList.remove("open");
  refs.analysisModal.setAttribute("aria-hidden", "true");
}

function chooseBehaviorFromName(fileName, riskScore) {
  const lower = fileName.toLowerCase();
  if (lower.endsWith(".exe") || lower.endsWith(".dll") || lower.endsWith(".scr")) {
    return "Executable davranışı + process ağacı sapması";
  }
  if (lower.endsWith(".docm") || lower.endsWith(".xlsm")) {
    return "Makro çağrısı + uzaktan bağlantı denemesi";
  }
  if (riskScore > 75) {
    return "Şşüpheli script çalıştırma + ağ çağrısı";
  }
  return "Anomali sinyali düşük, manuel doğrulama gerekli";
}

function fakeReasoning(fileName, riskScore) {
  const extension = fileName.includes(".") ? fileName.split(".").pop().toLowerCase() : "bin";
  const reasons = [
    `ResNet18 özellik haritaları .${extension} uzantısında şüpheli örüntü verdi.`,
    "Grad-CAM odağı dosya içerisindeki yüksek riskli bölgede yoğunlaştı.",
    "Sinyal dağılımı normal dosya profiline göre sapma gösterdi.",
  ];

  if (riskScore >= 85) {
    reasons.push("Karar marjini yüksek olduğu için model zararlı sınıfına yakınlaştı.");
  } else if (riskScore >= 65) {
    reasons.push("Karar sınırı aşıldı ancak yanlış pozitif riski için inceleme notu tutuldu.");
  } else {
    reasons.push("Model düşük risk sınıfı verdi, doğrulama için gözlemde kalmalı.");
  }
  return reasons;
}

function llmNarrative(threat, fileName, sourceIp) {
  const decision = decisionLabel(threat.decision);
  const confidencePercent = Math.round(threat.confidence * 100);
  const gradcamProfile = getThreatGradcamProfile(threat);

  return `LLM Güvenlik Analizi: Sisteme yüklenen '${fileName}' dosyası (kaynak IP: ${sourceIp}), yapısal anomalilerin tespiti için önce bayt duzeyinde "Binary-to-Image" teknigiyle iki boyutlu bir görsele çevrilmiştir. Uretilen dosya imaji, ResNet18 derin öğrenme mimarisinden gecirilmis ve %${confidencePercent} güven skoruyla "${decision.toUpperCase()}" olarak sınıflandırılmıştır. Secilen Grad-CAM görseli bu olayda ${gradcamProfile.analysisNote} Davranış paterni "${threat.behavior.toLowerCase()}" ile uyuştuğundan, bu dosya SOC kuyrugunda öncelikli takibe alınmalıdır.`;
}

function buildSimulatedThreat(file, sourceIp) {
  const lower = file.name.toLowerCase();
  let baseScore = 56;

  if (lower.endsWith(".exe") || lower.endsWith(".dll") || lower.endsWith(".scr")) {
    baseScore = 92;
  } else if (lower.endsWith(".docm") || lower.endsWith(".xlsm") || lower.endsWith(".ps1")) {
    baseScore = 78;
  } else if (lower.endsWith(".zip") || lower.endsWith(".js") || lower.endsWith(".bat")) {
    baseScore = 68;
  }

  const noise = Math.floor(Math.random() * 7) - 3;
  const riskScore = Math.max(35, Math.min(99, baseScore + noise));

  let decision = "under_review";
  let severity = "low";
  if (riskScore >= 85) {
    decision = "malicious";
    severity = "critical";
  } else if (riskScore >= 65) {
    decision = "suspicious";
    severity = "medium";
  }

  return {
    id: `SIM-${Date.now().toString().slice(-6)}`,
    fileName: file.name,
    riskScore,
    sourceIp: sourceIp || randomItem(networkTemplates).split("->")[1].split(":")[0].trim(),
    behavior: chooseBehaviorFromName(file.name, riskScore),
    severity,
    confidence: Math.min(0.99, Number((0.52 + (riskScore / 210)).toFixed(2))),
    reasoning: fakeReasoning(file.name, riskScore),
    decision,
    sha256: `sim-${Math.random().toString(16).slice(2, 18)}`,
    fileSizeBytes: file.size,
    createdAt: new Date().toISOString(),
  };
}

let mcpRenderVersion = 0;
let mcpThinkingInterval = null;

function randomBetween(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function createMcpLineRow(lineData, index) {
  const typeLabelMap = {
    thought: "THINK",
    prompt: "PLAN",
    "tool-call": "MCP CALL",
    "tool-result": "MCP OK",
    action: "COMMIT",
    alert: "ALERT",
  };

  const row = document.createElement("article");
  row.className = `mcp-line ${lineData.type}`;

  const head = document.createElement("div");
  head.className = "mcp-line-head";

  const seq = document.createElement("span");
  seq.className = "mcp-line-seq";
  seq.textContent = `#${String(index).padStart(2, "0")}`;

  const role = document.createElement("span");
  role.className = "mcp-line-role";
  role.textContent = lineData.role;

  const phase = document.createElement("span");
  phase.className = "mcp-line-phase";
  phase.textContent = lineData.phase;

  const kind = document.createElement("span");
  kind.className = "mcp-line-kind";
  kind.textContent = typeLabelMap[lineData.type] || lineData.type.toUpperCase();

  head.appendChild(seq);
  head.appendChild(role);
  head.appendChild(phase);
  head.appendChild(kind);

  if (lineData.tool) {
    const tool = document.createElement("span");
    tool.className = "mcp-line-tool";
    tool.textContent = lineData.tool;
    head.appendChild(tool);
  }

  const message = document.createElement("p");
  message.className = "mcp-line-message";

  row.appendChild(head);
  row.appendChild(message);

  return { row, message };
}

async function typeMcpLine(messageElement, text, renderToken) {
  const cursor = document.createElement("span");
  cursor.className = "mcp-cursor";
  cursor.textContent = "|";
  messageElement.textContent = "";
  messageElement.appendChild(cursor);

  let index = 0;
  while (index < text.length) {
    if (renderToken !== mcpRenderVersion) {
      return false;
    }
    index += randomBetween(1, 3);
    messageElement.textContent = text.slice(0, index);
    messageElement.appendChild(cursor);
    await sleep(randomBetween(11, 26));
  }

  cursor.remove();
  return true;
}

function buildMcpLiveBatch(threat, info) {
  const watchThoughts = [
    "Telemetri akışından gelen sinyaller bağlam penceresine sessizce yazılıyor.",
    "IOC korelasyonu yeniden kontrol ediliyor, acele karar verilmiyor.",
    "Ajan önce hipotezleri eleyip sonra araç çağrısına geçiyor.",
    "Risk marjini stabil mi diye ikinci bir dusunce turu çalışıyor.",
  ];
  const watchAlerts = [
    "ALERT[YUKSEK] dis trafik anomali eşiği kısa süreliğine aşıldı.",
    "ALERT[ORTA] sandbox içinde supheli process zinciri görüldü.",
    "ALERT[KRITIK] politika motoru muhafaza moduna geçiş öneri verdi.",
    "ALERT[ORTA] benzer IOC için geriye dönük tarama tetiklendi.",
  ];

  if (!threat || !info) {
    const lines = [{
      type: "thought",
      role: "watcher-agent",
      phase: "devriye",
      text: randomItem(watchThoughts),
    }];

    if (Math.random() < 0.5) {
      lines.push({
        type: "prompt",
        role: "planner-agent",
        phase: "mikro_plan",
        text: "Yeni turda önce telemetri sessizce toplanacak, sonra karar marjini tekrar olculecek.",
      });
    }

    if (Math.random() < 0.35) {
      lines.push(
        {
          type: "tool-call",
          role: "mcp-router",
          phase: "telemetri_toplama",
          tool: "pull_runtime_signals",
          text: 'mcp.request tools/call {"name":"pull_runtime_signals","arguments":{"window":"realtime","limit":64}}',
        },
        {
          type: "tool-result",
          role: "watcher-agent",
          phase: "sinyal_sentezi",
          tool: "pull_runtime_signals",
          text: `mcp.response {"status":"ok","signal_count":${randomBetween(12, 41)},"drift":"stable"}`,
        },
      );
    }

    if (Math.random() < 0.33) {
      lines.push({
        type: "alert",
        role: "sentinel-agent",
        phase: "uyarı",
        text: randomItem(watchAlerts),
      });
    }

    return lines;
  }

  const fileExtension = threat.fileName.includes(".")
    ? threat.fileName.split(".").pop().toLowerCase()
    : "bin";
  const lines = [{
    type: "thought",
    role: "planner-agent",
    phase: "dusunce_turu",
    text: `Hedef '${threat.fileName}' yeniden degerlendiriliyor. Sistem önce dusunup sonra araç seciyor.`,
  }];

  const mode = Math.random();
  if (mode < 0.4) {
    lines.push(
      {
        type: "tool-call",
        role: "mcp-router",
        phase: "tool_çağrısi",
        tool: "get_file_metadata",
        text: `mcp.request tools/call {"name":"get_file_metadata","arguments":{"threat_id":"${threat.id}","ext":"${fileExtension}"}}`,
      },
      {
        type: "tool-result",
        role: "metadata-agent",
        phase: "tool_cevabi",
        tool: "get_file_metadata",
        text: `mcp.response {"size_bytes":${threat.fileSizeBytes},"sha256":"${threat.sha256.slice(0, 18)}...","ext":"${fileExtension}"}`,
      },
    );
  } else if (mode < 0.75) {
    lines.push(
      {
        type: "tool-call",
        role: "vision-agent",
        phase: "model_çağrısi",
        tool: "run_resnet18_inference",
        text: 'mcp.request tools/call {"name":"run_resnet18_inference","arguments":{"artifact":"binary_image","gradcam":true}}',
      },
      {
        type: "tool-result",
        role: "vision-agent",
        phase: "model_cevabi",
        tool: "run_resnet18_inference",
        text: `mcp.response {"confidence":${info.confidencePercent},"class":"${threat.decision}","risk_score":${threat.riskScore}}`,
      },
    );
  } else {
    lines.push({
      type: "prompt",
      role: "judge-agent",
      phase: "risk_sentezi",
      text: info.thoughts[0] || "Karar siniri yeniden hesaplandi, acele aksiyon alinmiyor.",
    });
  }

  if (Math.random() < 0.28 || threat.riskScore >= 88) {
    lines.push({
      type: "alert",
      role: "sentinel-agent",
      phase: "uyarı",
      text: threat.riskScore >= 85
        ? `ALERT[KRITIK] ${threat.id} risk skoru ${threat.riskScore}/100 seviyesinde, otomatik muhafaza hazir.`
        : `ALERT[ORTA] ${threat.id} için davranış sapmasi tekrar görüldü, izleme sikligi artirildi.`,
    });
  }

  if (Math.random() < 0.45) {
    lines.push({
      type: "action",
      role: "orchestrator",
      phase: "devamli_izleme",
      text: `Karar izi korunuyor: '${threat.decision}'. Sistem yeni veri gelmeden bekleyip dusunmeye devam ediyor.`,
    });
  }

  return lines;
}

function renderXai() {
  mcpRenderVersion += 1;
  const renderToken = mcpRenderVersion;
  if (mcpThinkingInterval) {
    clearInterval(mcpThinkingInterval);
    mcpThinkingInterval = null;
  }

  const activeThreat = selectedThreat;
  const info = activeThreat ? getXaiInsights(activeThreat) : null;

  refs.mcpTerminal.classList.add("active-session");
  refs.mcpTerminal.innerHTML = "";
  refs.xaiBadge.textContent = "LLM dusunuyor...";

  if (activeThreat && info) {
    const gradcamProfile = getThreatGradcamProfile(activeThreat);
    refs.mcpFindings.style.display = "flex";
    refs.mcpFindings.classList.add("fade-in-up");
    refs.xaiDecision.textContent = `${decisionLabel(activeThreat.decision)} (${severityLabel(activeThreat.severity)})`;
    refs.xaiDecisionCode.textContent = `karar_kodu: ${activeThreat.decision}`;
    refs.xaiConfidenceBar.style.width = `${info.confidencePercent}%`;
    refs.xaiConfidenceText.textContent = `Model güveni: %${info.confidencePercent} | Risk skoru: ${activeThreat.riskScore}/100`;
    if (refs.gradcamImage) {
      refs.gradcamImage.src = `${gradcamProfile.imagePath}?t=${Date.now()}`;
    }
    refs.gradcamCaption.textContent = `Grad-CAM odağı ${activeThreat.id} için ${gradcamProfile.focusSummary}`;
    refs.llmComment.textContent = llmNarrative(activeThreat, activeThreat.fileName, activeThreat.sourceIp);
  } else {
    refs.mcpFindings.style.display = "none";
    refs.xaiDecision.textContent = "Canlı Devriye Modu";
    refs.xaiDecisionCode.textContent = "karar_kodu: realtime_watch";
    refs.xaiConfidenceBar.style.width = "38%";
    refs.xaiConfidenceText.textContent = "Model güveni: dinamik | Risk skoru: canlı izleme";
    if (refs.gradcamImage) {
      refs.gradcamImage.src = `./gradcam_example_3.png?t=${Date.now()}`;
    }
    refs.gradcamCaption.textContent = "Canlı devriye acik. Tehdit secildiginde hedefe ozel açıklama gosterilir.";
    refs.llmComment.textContent = "MCP araç katmani arka planda surekli telemetri topluyor ve risk siniflarini tekrar degerlendiriyor.";
  }

  const sessionCode = activeThreat
    ? `${activeThreat.id}-${Date.now().toString().slice(-4)}`
    : `WATCH-${Date.now().toString().slice(-4)}`;
  const confidenceLabel = info ? `%${info.confidencePercent}` : "telemetri";

  const hud = document.createElement("section");
  hud.className = "mcp-hud";
  hud.innerHTML = `
    <div class="mcp-hud-head">
      <span class="mcp-led"></span>
      <strong>mcp_session:${sessionCode}</strong>
      <span class="mcp-hud-meta">qwen3.5-122b-local | mcp-router:v1 | think-first</span>
    </div>
    <div class="mcp-hud-grid">
      <div class="mcp-hud-cell">
        <p>Aktif Ajan</p>
        <strong class="mcp-hud-agent">${activeThreat ? "planner-agent" : "watcher-agent"}</strong>
      </div>
      <div class="mcp-hud-cell">
        <p>Asama</p>
        <strong class="mcp-hud-phase">${activeThreat ? "hedef_izleme" : "devriye"}</strong>
      </div>
      <div class="mcp-hud-cell">
        <p>Son Tool</p>
        <strong class="mcp-hud-tool">-</strong>
      </div>
      <div class="mcp-hud-cell">
        <p>Model Güveni</p>
        <strong class="mcp-hud-confidence">${confidenceLabel}</strong>
      </div>
    </div>
  `;

  const hudAgent = hud.querySelector(".mcp-hud-agent");
  const hudPhase = hud.querySelector(".mcp-hud-phase");
  const hudTool = hud.querySelector(".mcp-hud-tool");

  const streamWrap = document.createElement("div");
  streamWrap.className = "mcp-stream";

  const thinking = document.createElement("div");
  thinking.className = "mcp-thinking";
  thinking.innerHTML = `<span class="mcp-thinking-dot"></span><span class="mcp-thinking-text">Ajan bağlami okuyup dusunuyor...</span>`;
  const thinkingText = thinking.querySelector(".mcp-thinking-text");

  refs.mcpTerminal.appendChild(hud);
  refs.mcpTerminal.appendChild(streamWrap);
  refs.mcpTerminal.appendChild(thinking);

  const thinkingPhrases = activeThreat
    ? [
        "Hedef dosya için ilk dusunce turu tamamlanmak uzere...",
        "Model, karsi gorusleri de tartarak karar marjini olcuyor...",
        "Ajan acele etmeden araç secimini tekrar kontrol ediyor...",
        "Nihai yargi önce ic muhakeme, sonra tool yaniti ile netlesiyor...",
      ]
    : [
        "Canlı devriye telemetrisi sessizce bağlama yazılıyor...",
        "Ajan birkac saniye dusunup sonra sonraki araça geçiyor...",
        "IOC korelasyonu arka planda adim adim güncelleniyor...",
        "Politika motoru yeni uyarı esiklerini sakin sekilde kontrol ediyor...",
      ];

  let thinkingIndex = 0;
  mcpThinkingInterval = setInterval(() => {
    if (renderToken !== mcpRenderVersion) {
      return;
    }
    thinkingIndex = (thinkingIndex + 1) % thinkingPhrases.length;
    thinkingText.textContent = thinkingPhrases[thinkingIndex];
  }, 2200);

  let sequence = 0;

  async function runStream() {
    while (renderToken === mcpRenderVersion) {
      const batchLines = buildMcpLiveBatch(activeThreat, info);
      for (let index = 0; index < batchLines.length; index += 1) {
        if (renderToken !== mcpRenderVersion) {
          return;
        }

        const lineData = batchLines[index];
        sequence += 1;
        hudAgent.textContent = lineData.role;
        hudPhase.textContent = lineData.phase;
        if (lineData.tool) {
          hudTool.textContent = lineData.tool;
        }

        if (lineData.type === "tool-call") {
          refs.xaiBadge.textContent = `MCP araçi çalışıyor: ${lineData.tool}`;
        } else if (lineData.type === "tool-result") {
          refs.xaiBadge.textContent = `Tool yaniti geldi: ${lineData.tool}`;
        } else if (lineData.type === "alert") {
          refs.xaiBadge.textContent = "Canlı ALERT algilandi";
        } else if (lineData.type === "prompt") {
          refs.xaiBadge.textContent = "LLM dusunuyor ve plani revize ediyor...";
        } else {
          refs.xaiBadge.textContent = activeThreat
            ? `LLM dusunuyor | ${activeThreat.id}`
            : "LLM dusunuyor...";
        }

        const lineRow = createMcpLineRow(lineData, sequence);
        streamWrap.appendChild(lineRow.row);
        while (streamWrap.children.length > 22) {
          streamWrap.removeChild(streamWrap.firstChild);
        }
        refs.mcpTerminal.scrollTop = refs.mcpTerminal.scrollHeight;

        const typed = await typeMcpLine(lineRow.message, lineData.text, renderToken);
        if (!typed || renderToken !== mcpRenderVersion) {
          return;
        }

        let delay = randomBetween(1400, 2300);
        if (lineData.type === "thought" || lineData.type === "prompt") {
          delay = randomBetween(1900, 3600);
        } else if (lineData.type === "tool-call") {
          delay = randomBetween(2200, 3800);
        } else if (lineData.type === "tool-result") {
          delay = randomBetween(1200, 2400);
        } else if (lineData.type === "alert") {
          delay = randomBetween(1100, 1900);
        } else if (lineData.type === "action") {
          delay = randomBetween(1400, 2500);
        }

        await sleep(delay);
      }

      refs.xaiBadge.textContent = activeThreat
        ? `LLM dusunuyor | ${activeThreat.id}`
        : "LLM dusunuyor...";
      await sleep(randomBetween(2400, 4800));
    }
  }

  void runStream();
}
function renderFlow() {
  refs.flowSteps.innerHTML = "";
  flowLabels.forEach((label, idx) => {
    const row = document.createElement("div");
    row.className = `step ${idx === flowIndex ? "active" : ""}`;
    row.textContent = label;
    refs.flowSteps.appendChild(row);
  });
}

function tickFlow() {
  flowIndex = (flowIndex + 1) % flowLabels.length;
  renderFlow();
}

function getPriorityThreat() {
  if (selectedThreat) {
    return selectedThreat;
  }
  if (!threats || threats.length === 0) {
    return null;
  }
  return threats.reduce((best, candidate) => {
    if (!best || candidate.riskScore > best.riskScore) {
      return candidate;
    }
    return best;
  }, null);
}

function buildNaturalAlert() {
  const threat = getPriorityThreat();
  if (!threat) {
    const neutral = [
      { level: "BILGI", text: "Telemetri normal seyirde, anomali esikleri izleniyor." },
      { level: "BILGI", text: "Otomatik triyaj kuyru gu sessiz devriye modunda." },
      { level: "ORTA", text: "Duzensiz paket yoğunlugu görüldü, yeniden ölçüm baslatildi." },
    ];
    return randomItem(neutral);
  }

  const risk = threat.riskScore;
  const roll = Math.random();
  let level = "BILGI";
  if (risk >= 90) {
    level = roll < 0.58 ? "KRITIK" : "YUKSEK";
  } else if (risk >= 75) {
    level = roll < 0.55 ? "YUKSEK" : "ORTA";
  } else if (risk >= 55) {
    level = roll < 0.62 ? "ORTA" : "BILGI";
  } else {
    level = roll < 0.72 ? "BILGI" : "DUSUK";
  }

  const alerts = [
    `${threat.id} için davranış profili yeniden tetiklendi (kaynak: ${threat.sourceIp}).`,
    `${threat.fileName} dosyası için risk marjini tekrar olculdu.`,
    `Ajan triyaj kuyru gu ${threat.id} olayini ikinci dogrulamaya aldi.`,
    `MCP korelasyon katmani ${threat.id} için IOC benzerligi buldu.`,
    `Karar motoru ${threat.id} için aksiyon seviyesini yeniden degerlendiriyor.`,
  ];

  if (blockedIps.has(threat.sourceIp) && Math.random() < 0.45) {
    return {
      level: "BILGI",
      text: `${threat.sourceIp} adresi muhafaza listesinde, izleme pasif dogrulama moduna alindi.`,
    };
  }
  return { level, text: randomItem(alerts) };
}

function tickAgent() {
  if (!refs.agentLogList) {
    return;
  }
  appendAgentLog(randomItem(agentTemplates));
}

function tickSandbox() {
  if (!refs.networkEvents || !refs.fileEvents) {
    return;
  }
  appendEvent(refs.networkEvents, randomItem(networkTemplates));
  appendEvent(refs.fileEvents, randomItem(fileTemplates));
}

function buildNaturalTerminalLine() {
  const threat = getPriorityThreat();
  if (!threat) {
    const generic = [
      "[boot] telemetry watcher idle warm mode",
      "[ops] dashboard sync completed without drift",
      "[llm] context window refreshed from passive feeds",
      "[policy] no hard action required in this cycle",
    ];
    return randomItem(generic);
  }

  const confidence = Math.round((threat.confidence || 0.5) * 100);
  const lines = [
    `[ingest] ${threat.id} telemetry window accepted (${randomBetween(18, 64)} events)`,
    `[llm] reasoning pass completed for ${threat.fileName} | conf=${confidence}%`,
    `[mcp] tool route selected: ${randomItem(["get_file_metadata", "query_sandbox_db", "run_resnet18_inference"])}`,
    `[policy] posture=${threat.riskScore >= 85 ? "strict" : "balanced"} for source ${threat.sourceIp}`,
    `[ops] panel delta sync ${randomBetween(24, 140)}ms | threat=${threat.id}`,
  ];
  return randomItem(lines);
}

function applyStatusState(element, stateClass, label) {
  if (!element) {
    return;
  }
  element.classList.remove("online", "busy", "degraded");
  element.classList.add(stateClass);
  element.textContent = label;
}

function updateSystemStatus() {
  const threat = getPriorityThreat();
  const risk = threat ? threat.riskScore : 48;

  if (!backendAvailable) {
    applyStatusState(refs.llmStatus, "degraded", "Yedek mod");
    applyStatusState(refs.agentStatus, "degraded", "Gecikmeli");
    applyStatusState(refs.sandboxStatus, "degraded", "Yerel");
    return;
  }

  const llmLatency = randomBetween(24, 92) + (risk >= 85 ? randomBetween(8, 26) : 0);
  const agentQueue = randomBetween(1, 5) + (risk >= 80 ? 1 : 0);
  const sandboxLoad = randomBetween(34, 84) + (risk >= 85 ? randomBetween(6, 14) : 0);

  let llmState = llmLatency > 90 ? "busy" : "online";
  let agentState = agentQueue > 5 ? "busy" : "online";
  let sandboxState = sandboxLoad > 88 ? "busy" : "online";

  if (String(healthTelemetry.llm || "").toLowerCase() !== "online") {
    llmState = "degraded";
  }
  if (String(healthTelemetry.agents || "").toLowerCase() !== "running") {
    agentState = "degraded";
  }
  if (String(healthTelemetry.sandbox || "").toLowerCase() !== "active") {
    sandboxState = "degraded";
  }

  if (Math.random() < 0.05) {
    const target = randomItem(["llm", "agent", "sandbox"]);
    if (target === "llm") llmState = "degraded";
    if (target === "agent") agentState = "degraded";
    if (target === "sandbox") sandboxState = "degraded";
  }

  applyStatusState(
    refs.llmStatus,
    llmState,
    llmState === "online" ? `Cevrimici | ${llmLatency}ms` : llmState === "busy" ? `Yogun | ${llmLatency}ms` : "Gecikmeli",
  );
  applyStatusState(
    refs.agentStatus,
    agentState,
    agentState === "online" ? "Calisiyor" : agentState === "busy" ? `Yogun | q=${agentQueue}` : "Gecikmeli",
  );
  applyStatusState(
    refs.sandboxStatus,
    sandboxState,
    sandboxState === "online" ? `Aktif | ${sandboxLoad}%` : sandboxState === "busy" ? `Yuksek | ${sandboxLoad}%` : "Kontrollu",
  );
}

function tickAlerts() {
  if (Math.random() < 0.18) {
    return;
  }
  let item = buildNaturalAlert();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (!item) {
      break;
    }
    const signature = `${item.level}|${item.text}`;
    if (signature !== lastAlertSignature) {
      break;
    }
    item = buildNaturalAlert();
  }
  if (!item) {
    return;
  }
  lastAlertSignature = `${item.level}|${item.text}`;
  appendAlert(item.level, item.text);
}

function tickTerminal() {
  if (Math.random() < 0.16) {
    return;
  }
  let line = buildNaturalTerminalLine();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (line !== lastTerminalSignature) {
      break;
    }
    line = buildNaturalTerminalLine();
  }
  lastTerminalSignature = line;
  appendTerminal(line);
}

function scheduleNaturalTick(fn, minDelay, maxDelay) {
  const loop = () => {
    fn();
    setTimeout(loop, randomBetween(minDelay, maxDelay));
  };
  setTimeout(loop, randomBetween(minDelay, maxDelay));
}

function updateSyncClock() {
  refs.lastUpdate.textContent = `Son senkron: ${nowLabel()}`;
}

function buildLocalReport() {
  const xai = getXaiInsights(selectedThreat);
  return {
    olay_id: `INC-${Date.now().toString().slice(-6)}`,
    başlık: "Agentic SOC Olay Raporu",
    olüsturulma_zamani: new Date().toISOString(),
    yonetici_özeti: `${selectedThreat.fileName} dosyası ${decisionLabel(selectedThreat.decision)} olarak sınıflandı.`,
    tehdit_profili: {
      tehdit_id: selectedThreat.id,
      dosya_adi: selectedThreat.fileName,
      kaynak_ip: selectedThreat.sourceIp,
      risk_skoru: selectedThreat.riskScore,
      seviye: severityLabel(selectedThreat.severity),
      karar: decisionLabel(selectedThreat.decision),
      karar_kodu: selectedThreat.decision,
      güven: selectedThreat.confidence,
      sha256: selectedThreat.sha256,
      dosya_boyutu_bayt: selectedThreat.fileSizeBytes,
      ip_engelli_mi: blockedIps.has(selectedThreat.sourceIp),
    },
    xai_özeti: {
      ana_gerekceler: selectedThreat.reasoning,
      model_sinyalleri: xai.signals,
      karsi_gorusler: xai.counters,
      belirsizlik_notu: xai.uncertainty,
      risk_hikayesi: xai.story,
    },
    ai_dusunce_notlari: xai.thoughts,
    önerilen_aksiyonlar: [
      "Kaynak IP'yi geçici olarak karantinaya al.",
      "Aynı hash'e sahip dosyalar için ortam taraması başlat.",
      "Benzer IOC'ler için son 24 saatlik logları geriye dönük tara.",
      "Gerekiyorsa olay kaydını hukuk ve uyumluluk birimine ilet.",
    ],
    operasyon_zaman_cizelgesi: [
      "Telemetri alındı",
      "LLM sınıflandırması tamamlandı",
      "Sandbox davranışı analiz edildi",
      "Ajanik karar üretildi",
      "SOC paneli güncellendi",
    ],
    canlı_alarm_özeti: [
      "Yerel mod: canlı alarm verisi backend bağlantısı olmadan sınırlı gösterilir.",
      `${selectedThreat.id} için risk odaklı alarm kaydı oluşturuldu.`,
    ],
    ajan_gunluk_özeti: [
      "Yerel mod: ajan günlükleri demo verisi ile oluşturuldu.",
      "Rapor ajanı olay bağlamını derleyip yönetici özetini hazırladı.",
    ],
    uyumluluk_notu: "Veri işleme akışında dış ortama ham dosya aktarımı yapılmadı.",
    is_etkisi: "Olay kritik kaynaklara yayılmadan kontrol altına alınabilir.",
    kapanis: "Bu rapor demo amaçlıdır; AI düşünce notları simülasyon içerir.",
  };
}

function renderReadableReport(report) {
  const profile = report.tehdit_profili || {};
  const xai = report.xai_özeti || {};

  refs.reportReadable.innerHTML = `
    <section class="report-section">
      <h3>Yönetici Özeti</h3>
      <p>${escapeHtml(report.yonetici_özeti || "Özet bilgisi yok.")}</p>
    </section>
    <section class="report-section">
      <h3>Tehdit Profili</h3>
      <div class="report-kv">
        <div><p>Tehdit ID</p><strong>${escapeHtml(profile.tehdit_id || "-")}</strong></div>
        <div><p>Dosya Adı</p><strong>${escapeHtml(profile.dosya_adi || "-")}</strong></div>
        <div><p>Kaynak IP</p><strong>${escapeHtml(profile.kaynak_ip || "-")}</strong></div>
        <div><p>Risk Skoru</p><strong>${escapeHtml(profile.risk_skoru || "-")}</strong></div>
        <div><p>Seviye</p><strong>${escapeHtml(profile.seviye || "-")}</strong></div>
        <div><p>Karar</p><strong>${escapeHtml(profile.karar || "-")}</strong></div>
      </div>
    </section>
    <section class="report-section">
      <h3>Açıklanabilir YZ Özet</h3>
      <p>${escapeHtml(xai.risk_hikayesi || "")}</p>
      <p class="xai-muted">${escapeHtml(xai.belirsizlik_notu || "")}</p>
      ${listHtml(xai.ana_gerekceler || [])}
    </section>
    <section class="report-section">
      <h3>AI Düşünce Notları (Simülasyon)</h3>
      ${listHtml(report.ai_dusunce_notlari || [], true)}
    </section>
    <section class="report-section">
      <h3>Önerilen Aksiyonlar</h3>
      ${listHtml(report.önerilen_aksiyonlar || [])}
    </section>
    <section class="report-section">
      <h3>Zaman Çizelgesi</h3>
      ${listHtml(report.operasyon_zaman_cizelgesi || [])}
    </section>
    <section class="report-section">
      <h3>Canlı Alarm Özeti</h3>
      ${listHtml(report.canlı_alarm_özeti || [])}
    </section>
    <section class="report-section">
      <h3>Ajan Günlük Özeti</h3>
      ${listHtml(report.ajan_gunluk_özeti || [])}
    </section>
    <section class="report-section">
      <h3>Uyumluluk ve İş Etkisi</h3>
      <p>${escapeHtml(report.uyumluluk_notu || "")}</p>
      <p>${escapeHtml(report.is_etkisi || "")}</p>
      <p>${escapeHtml(report.kapanis || "")}</p>
    </section>
  `;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : null;

  if (!response.ok) {
    const message = body && body.detail ? body.detail : `HTTP ${response.status}`;
    throw new Error(message);
  }

  return body;
}

async function refreshHealth() {
  try {
    const health = await requestJson(`${API_BASE}/health`);
    backendAvailable = true;
    healthTelemetry = {
      llm: health.llm || "online",
      agents: health.agents || "running",
      sandbox: health.sandbox || "active",
    };
  } catch (_error) {
    backendAvailable = false;
    healthTelemetry = {
      llm: "degraded",
      agents: "degraded",
      sandbox: "degraded",
    };
  }
}

async function loadThreatsFromApi() {
  const payload = await requestJson(`${API_BASE}/threats?limit=25`);
  const apiThreats = Array.isArray(payload.threats) ? payload.threats.map(normalizeApiThreat) : [];
  if (apiThreats.length === 0) {
    return;
  }
  threats = apiThreats;
  selectedThreat = threats[0];
  renderThreatOverview();
  renderThreatDetail();
  renderXai();
}

async function loadActivityFromApi() {
  const alertsPayload = await requestJson(`${API_BASE}/alerts?limit=12`);
  if (refs.liveAlertsList) {
    refs.liveAlertsList.innerHTML = "";
    (alertsPayload.alerts || []).forEach((entry) => appendAlertEntry(entry, false));
  }

  if (refs.agentLogList) {
    const logsPayload = await requestJson(`${API_BASE}/agent-logs?limit=11`);
    refs.agentLogList.innerHTML = "";
    (logsPayload.logs || []).forEach((entry) => appendAgentLogEntry(entry, false));
  }

  if (refs.networkEvents || refs.fileEvents) {
    const sandboxPayload = await requestJson(`${API_BASE}/sandbox-events?limit=8`);
    if (refs.networkEvents) {
      refs.networkEvents.innerHTML = "";
      (sandboxPayload.network_events || []).forEach((entry) => appendEventEntry(refs.networkEvents, entry, false));
    }
    if (refs.fileEvents) {
      refs.fileEvents.innerHTML = "";
      (sandboxPayload.file_events || []).forEach((entry) => appendEventEntry(refs.fileEvents, entry, false));
    }
  }
}

function isLikelyIpv4(value) {
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  return ipv4Regex.test(value);
}

async function handleUploadSubmit(event) {
  event.preventDefault();
  const file = refs.threatFileInput.files && refs.threatFileInput.files[0];
  const sourceIp = refs.sourceIpInput.value.trim();

  if (!file) {
    refs.uploadFeedback.textContent = "Lütfen önce bir dosya seçin.";
    return;
  }
  if (sourceIp && !isLikelyIpv4(sourceIp)) {
    refs.uploadFeedback.textContent = "Kaynak IP formatı geçersiz. 185.220.101.77 gibi IPv4 girin.";
    return;
  }

  refs.uploadSubmitBtn.disabled = true;
  refs.uploadFeedback.textContent = "Demo inference başladı: ResNet18 pipeline çalışıyor...";
  refs.simSteps.innerHTML = "";
  refs.inferenceSimBox.classList.add("scanning");
  
  setSimProgress(0, "Hazırlanıyor...");
  addSimStep("Girdi dosyası kuyruğa alındı.");
  appendAgentLog("Demo inference talebi alındı.");
  appendTerminal(`[upload] ${file.name} için simülasyon başlatıldı`);

  const stages = [
    { progress: 12, line: "weights yükleniyor...", text: "best_model_state_dict.pth diskten okunuyor..." },
    { progress: 27, line: "mimari init...", text: "ResNet18 mimarisi initialize edildi." },
    { progress: 44, line: "ön-işleme...", text: "Dosya 224x224 tensor formata normalize edildi." },
    { progress: 62, line: "feature extraction...", text: "Convolution katmanlarında aktivasyonlar hesaplandı." },
    { progress: 77, line: "inference...", text: "Class logits ve confidence değerleri oluşturuldu." },
    { progress: 91, line: "grad-cam...", text: "Grad-CAM ısı haritası çıkarıldı." },
    { progress: 100, line: "llm yorum...", text: "LLM karar yorumu oluşturuldu." },
  ];

  for (const stage of stages) {
    setSimProgress(stage.progress, stage.line);
    addSimStep(stage.text);
    appendTerminal(`[sim] ${stage.text}`);
    await sleep(450 + Math.floor(Math.random() * 280));
  }

  const simulatedThreat = buildSimulatedThreat(file, sourceIp);
  threats = [simulatedThreat, ...threats.filter((item) => item.id !== simulatedThreat.id)].slice(0, 25);
  selectedThreat = simulatedThreat;

  renderThreatOverview();
  renderThreatDetail();
  renderXai();

  refs.uploadFeedback.textContent =
    `${file.name} için demo inference tamamlandı. Karar: ${decisionLabel(simulatedThreat.decision)} (${simulatedThreat.riskScore}/100)`;
  setSimProgress(100, "tamamlandı");
  refs.inferenceSimBox.classList.remove("scanning");
  
  refs.sourceIpInput.value = "";
  refs.threatFileInput.value = "";
  refs.dragDropText.innerHTML = "Şşüpheli dosyayı buraya sürükleyin veya <strong>tıklayarak seçin</strong>";
  refs.uploadSubmitBtn.disabled = false;

  appendAlert("YÜKSEK", `ResNet18 simülasyon tamamlandı (${simulatedThreat.id}).`);
  appendAgentLog("LLM yorum ajanı karar metnini dashboard'a yazdı.");
  appendEvent(refs.networkEvents, `10.30.5.21 -> ${simulatedThreat.sourceIp} : 443`, true);
  const linkedGradcam = getThreatGradcamProfile(simulatedThreat);
  appendEvent(
    refs.fileEvents,
    `${file.name} için ${linkedGradcam.imagePath.replace("./", "")} iliskilendirildi`,
    true,
  );
  appendTerminal(`[sim] analiz bitti: ${simulatedThreat.id}`);
  openAnalysisModal(simulatedThreat, file.name);
}

async function fetchReportData(threatId) {
  if (!backendAvailable || threatId.startsWith("SIM-")) {
    return buildLocalReport();
  }
  try {
    const payload = await requestJson(`${API_BASE}/report/${encodeURIComponent(threatId)}`);
    return payload.report;
  } catch (_error) {
    return buildLocalReport();
  }
}

async function downloadDocxReport(threatId) {
  const response = await fetch(`${API_BASE}/report/${encodeURIComponent(threatId)}/docx`);
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      if (body.detail) {
        message = body.detail;
      }
    } catch (_error) {
      message = `HTTP ${response.status}`;
    }
    throw new Error(message);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `olay_raporu_${threatId}.docx`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function openReportModal(report, threatId) {
  currentReport = report;
  currentReportThreatId = threatId;
  renderReadableReport(report);
  refs.reportModal.classList.add("open");
  refs.reportModal.setAttribute("aria-hidden", "false");
  if (threatId.startsWith("SIM-")) {
    refs.downloadReportBtn.disabled = true;
    refs.downloadReportBtn.title = "Demo simülasyon kaydı için Word indirme kapalı.";
  } else {
    refs.downloadReportBtn.disabled = false;
    refs.downloadReportBtn.title = "";
  }
}

function closeReportModal() {
  refs.reportModal.classList.remove("open");
  refs.reportModal.setAttribute("aria-hidden", "true");
}

async function handleAutoBlockIp() {
  try {
    if (backendAvailable && !selectedThreat.id.startsWith("SIM-")) {
      const payload = await requestJson(`${API_BASE}/block-ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: selectedThreat.sourceIp, reason: selectedThreat.id }),
      });
      blockedIps.add(selectedThreat.sourceIp);
      refs.actionFeedback.textContent = payload.message;
      appendAlert("KRİTİK", `${selectedThreat.sourceIp} için otomatik muhafaza çalıştırıldı.`);
      appendAgentLog("Muhafaza ajanı onayladı: IP engellendi.");
      appendTerminal(`[yanıt] firewall kuralı gönderildi: ${selectedThreat.sourceIp}`);
      await loadActivityFromApi();
      await refreshHealth();
      return;
    }
  } catch (error) {
    appendTerminal(`[api] ip-engelle başarısız: ${error.message}`);
  }

  blockedIps.add(selectedThreat.sourceIp);
  refs.actionFeedback.textContent = `${selectedThreat.sourceIp} yerel yedek politika ile engellendi.`;
  appendAlert("KRİTİK", `${selectedThreat.sourceIp} için otomatik muhafaza çalıştırıldı.`);
  appendAgentLog("Muhafaza ajanı onayladı: IP engellendi.");
  appendTerminal(`[yanıt] yedek firewall kuralı gönderildi: ${selectedThreat.sourceIp}`);
}

async function handleGenerateReport() {
  try {
    const report = await fetchReportData(selectedThreat.id);
    openReportModal(report, selectedThreat.id);
    refs.actionFeedback.textContent = "Olay raporu okunabilir formatta oluşturuldu.";
    appendAgentLog("Rapor ajanı detaylı olay raporunu oluşturdu.");
    appendTerminal(`[denetim] detaylı rapor hazırlandı: ${selectedThreat.id}`);
  } catch (error) {
    refs.actionFeedback.textContent = `Rapor oluşturma başarısız: ${error.message}`;
    appendTerminal(`[api] rapor oluşturma başarısız: ${error.message}`);
  }
}

function bindActions() {
  refs.uploadForm.addEventListener("submit", (event) => {
    void handleUploadSubmit(event);
  });
  
  // Drag and Drop Logic
  ["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
    refs.dragDropZone.addEventListener(eventName, preventDefaults, false);
  });

  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  ["dragenter", "dragover"].forEach(eventName => {
    refs.dragDropZone.addEventListener(eventName, () => {
      refs.dragDropZone.classList.add('dragover');
    }, false);
  });

  ["dragleave", "drop"].forEach(eventName => {
    refs.dragDropZone.addEventListener(eventName, () => {
      refs.dragDropZone.classList.remove('dragover');
    }, false);
  });

  refs.dragDropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    
    if (files && files.length > 0) {
      refs.threatFileInput.files = files;
      refs.dragDropText.innerHTML = `Seçilen Dosya: <strong>${files[0].name}</strong>`;
    }
  }, false);

  refs.threatFileInput.addEventListener('change', (e) => {
    if (refs.threatFileInput.files.length > 0) {
      refs.dragDropText.innerHTML = `Seçilen Dosya: <strong>${refs.threatFileInput.files[0].name}</strong>`;
    }
  });

  refs.autoBlockBtn.addEventListener("click", () => {
    void handleAutoBlockIp();
  });

  refs.generateReportBtn.addEventListener("click", () => {
    void handleGenerateReport();
  });

  refs.downloadReportBtn.addEventListener("click", async () => {
    if (!currentReportThreatId) {
      refs.actionFeedback.textContent = "Önce bir rapor oluşturmanız gerekiyor.";
      return;
    }
    if (!backendAvailable) {
      refs.actionFeedback.textContent = "Word indirme için backend bağlantısı gerekiyor.";
      return;
    }

    refs.actionFeedback.textContent = "Word raporu indiriliyor...";
    try {
      await downloadDocxReport(currentReportThreatId);
      refs.actionFeedback.textContent = "Word raporu indirildi.";
      appendTerminal(`[api] word raporu indirildi: ${currentReportThreatId}`);
    } catch (error) {
      refs.actionFeedback.textContent = `Word indirme başarısız: ${error.message}`;
      appendTerminal(`[api] word raporu indirilemedi: ${error.message}`);
    }
  });

  refs.closeReportBtn.addEventListener("click", closeReportModal);

  refs.reportModal.addEventListener("click", (event) => {
    if (event.target === refs.reportModal) {
      closeReportModal();
    }
  });

  refs.analysisCloseBtn.addEventListener("click", closeAnalysisModal);

  refs.analysisModal.addEventListener("click", (event) => {
    if (event.target === refs.analysisModal) {
      closeAnalysisModal();
    }
  });

  refs.analysisCreateReportBtn.addEventListener("click", () => {
    closeAnalysisModal();
    void handleGenerateReport();
  });

  refs.analysisBlockIpBtn.addEventListener("click", () => {
    closeAnalysisModal();
    void handleAutoBlockIp();
  });
}

async function bootstrap() {
  renderThreatOverview();
  renderThreatDetail();
  renderXai();
  renderFlow();
  bindActions();

  appendAlert("YUKSEK", "Tehdit triyaj kuyrugu aktif edildi.");
  appendAlert("BILGI", "Canlı izleme katmani ilk senkronu tamamladi.");
  appendTerminal("[boot] yerel SOC çalışma ortami baslatildi");
  appendTerminal("[boot] ajan orkestratoru hazir");
  updateSyncClock();
  updateSystemStatus();

  try {
    await Promise.all([loadThreatsFromApi(), loadActivityFromApi(), refreshHealth()]);
    refs.uploadFeedback.textContent = "Backend baglandi. Dosya yukleme analizi hazir.";
    appendTerminal("[api] FastAPI backend baglandi");
  } catch (error) {
    refs.uploadFeedback.textContent = "Backend erisilemez. Panel yerel demo modunda çalışıyor.";
    appendTerminal(`[api] backend erisilemez: ${error.message}`);
  }

  updateSystemStatus();
  scheduleNaturalTick(tickAlerts, 3200, 7600);
  setInterval(tickFlow, 1700);
  scheduleNaturalTick(tickTerminal, 2400, 6200);
  scheduleNaturalTick(updateSystemStatus, 2200, 5000);
  setInterval(updateSyncClock, 1000);
  setInterval(() => {
    void refreshHealth();
  }, 5000);
}

void bootstrap();



