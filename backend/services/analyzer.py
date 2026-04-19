from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import math
import random
from typing import Final

from backend.schemas import ThreatRecord

SUSPICIOUS_EXTENSIONS: Final[dict[str, tuple[int, str]]] = {
    ".exe": (26, "Calistirilabilir yuk uzantisi"),
    ".dll": (22, "Dinamik kutuphane uzantisi"),
    ".scr": (24, "Ekran koruyucu ikili dosya uzantisi"),
    ".bat": (18, "Batch script uzantisi"),
    ".cmd": (18, "Komut satiri script uzantisi"),
    ".ps1": (22, "PowerShell script uzantisi"),
    ".js": (16, "JavaScript script uzantisi"),
    ".vbs": (16, "VBScript uzantisi"),
    ".docm": (14, "Makro destekli Office dokumani"),
    ".xlsm": (14, "Makro destekli hesap tablosu"),
}

BYTE_SIGNATURES: Final[list[tuple[bytes, int, str, str]]] = [
    (b"powershell", 22, "PowerShell cagirimi kaliplari bulundu", "PowerShell calistirma"),
    (b"invoke-webrequest", 14, "Uzak indirme davranışi tespit edildi", "Yuk indirme davranışi"),
    (b"cmd.exe", 16, "Komut kabugu calistirma gostergesi bulundu", "Komut kabugu calistirma"),
    (b"base64", 10, "Kodlanmis yuk isareti bulundu", "Obfuske edilmis yuk"),
    (b"http://", 8, "Güvensiz dis URL referansi bulundu", "Supheli dis trafik"),
    (b"https://", 6, "Dis URL referansi bulundu", "Harici geri çağrım denemesi"),
    (b"reg add", 14, "Registry kalıcılik komutu tespit edildi", "Registry kalıcıligi"),
    (b"mimikatz", 28, "Kimlik bilgisi hirsizligi araçi anahtar kelimesi bulundu", "Kimlik bilgisi dokumu"),
]

DEFAULT_SOURCE_IP_POOL: Final[list[str]] = [
    "185.220.101.77",
    "45.134.26.190",
    "104.244.77.12",
    "91.218.114.31",
    "194.26.192.44",
]


class LocalThreatModel:
    """Hackathon demosu için sezgisel tehdit modeli."""

    def analyze(self, filename: str, payload: bytes, source_ip: str | None = None) -> ThreatRecord:
        normalized_name = filename or "yuklenen.bin"
        payload_lower = payload.lower()
        extension = self._file_extension(normalized_name)
        score = 8
        reasoning: list[str] = []
        behavior_tags: list[str] = []

        extension_match = SUSPICIOUS_EXTENSIONS.get(extension)
        if extension_match:
            extension_weight, extension_reason = extension_match
            score += extension_weight
            reasoning.append(extension_reason)

        entropy = self._calculate_entropy(payload)
        if entropy >= 7.2:
            score += 18
            reasoning.append("Yuksek binary entropi obfuske/paketli yapiyi isaret ediyor")
            behavior_tags.append("Paketlenmis binary profili")
        elif entropy >= 6.8:
            score += 9
            reasoning.append("Orta seviyede yuksek entropi gozlemlendi")

        if payload.startswith(b"MZ"):
            score += 18
            reasoning.append("PE basligi (MZ) tespit edildi")
            behavior_tags.append("Windows calistirilabilir davranışi")

        for signature, weight, reason, behavior in BYTE_SIGNATURES:
            if signature in payload_lower:
                score += weight
                reasoning.append(reason)
                behavior_tags.append(behavior)

        score += self._size_factor(len(payload))

        risk_score = max(0, min(score, 100))
        confidence = min(0.99, round(0.5 + (risk_score / 210), 2))

        if risk_score >= 85:
            decision = "malicious"
            severity = "critical"
        elif risk_score >= 65:
            decision = "suspicious"
            severity = "medium"
        elif risk_score >= 40:
            decision = "under_review"
            severity = "low"
        else:
            decision = "benign"
            severity = "low"

        if not reasoning:
            reasoning = [
                "Guclu malware sinyali tespit edilmedi",
                "Davranis analist dogrulamasi gerektiriyor",
                "Dosya trend analizi için izleme listesinde tutuldu",
            ]
        else:
            reasoning = reasoning[:4]

        behavior = " + ".join(dict.fromkeys(behavior_tags)) if behavior_tags else "Guclu anomali gozlenmedi"

        return ThreatRecord(
            id=self._build_threat_id(),
            file_name=normalized_name,
            risk_score=risk_score,
            source_ip=source_ip or random.choice(DEFAULT_SOURCE_IP_POOL),
            behavior=behavior,
            severity=severity,
            confidence=confidence,
            reasoning=reasoning,
            decision=decision,
            sha256=hashlib.sha256(payload).hexdigest(),
            file_size_bytes=len(payload),
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _file_extension(filename: str) -> str:
        if "." not in filename:
            return ""
        return f".{filename.rsplit('.', maxsplit=1)[-1].lower()}"

    @staticmethod
    def _size_factor(size_bytes: int) -> int:
        if size_bytes > 7_000_000:
            return 10
        if size_bytes > 1_000_000:
            return 6
        if size_bytes > 150_000:
            return 3
        return 0

    @staticmethod
    def _build_threat_id() -> str:
        stamp = datetime.now(UTC).strftime("%H%M%S")
        suffix = random.randint(100, 999)
        return f"T-{stamp}-{suffix}"

    @staticmethod
    def _calculate_entropy(content: bytes) -> float:
        if not content:
            return 0.0

        counts = [0] * 256
        for value in content:
            counts[value] += 1

        entropy = 0.0
        content_len = len(content)
        for count in counts:
            if count == 0:
                continue
            probability = count / content_len
            entropy -= probability * math.log2(probability)
        return entropy
