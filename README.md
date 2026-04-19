# Agentic SOC Hackathon Demo

FastAPI tabanli backend ve tek sayfa frontend ile hazirlanmis bir Agentic SOC (Security Operations Center) demosu.

Uygulama; yuklenen dosya uzerinde sezgisel tehdit analizi yapar, olaylari panelde gosterir ve JSON + DOCX formatinda rapor uretebilir.

## Ozellikler

- Dosya yukleme ve tehdit skorlama (`/api/analyze`)
- Canli alarm, ajan gunlugu ve sandbox olay akisi
- IOC/muhafaza adimi olarak IP engelleme (`/api/block-ip`)
- Olay raporu olusturma (`/api/report/{threat_id}`)
- Word formatinda rapor indirme (`/api/report/{threat_id}/docx`)
- FastAPI uzerinden statik frontend servis etme

## Teknoloji Yigini

- Python 3.10+
- FastAPI
- Uvicorn
- Pydantic
- python-docx
- HTML + CSS + JavaScript

## Proje Yapisi

```text
.
|-- backend/
|   |-- main.py
|   |-- schemas.py
|   `-- services/
|       |-- analyzer.py
|       `-- reporting.py
|-- index.html
|-- styles.css
|-- script.js
`-- requirements.txt
```

## Kurulum

1. Ortami hazirlayin:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
2. Bagimliliklari yukleyin:
   ```bash
   pip install -r requirements.txt
   ```
3. Uygulamayi baslatin:
   ```bash
   uvicorn backend.main:app --reload
   ```
4. Tarayicidan acin:
   - Uygulama: `http://127.0.0.1:8000`
   - Swagger UI: `http://127.0.0.1:8000/docs`

## API Ozeti

| Method | Endpoint | Aciklama |
|---|---|---|
| GET | `/api/health` | Servis saglik durumu |
| GET | `/api/threats` | Tehdit listesi |
| GET | `/api/alerts` | Alarm listesi |
| GET | `/api/agent-logs` | Ajan gunlugu |
| GET | `/api/sandbox-events` | Sandbox ag/dosya olaylari |
| POST | `/api/analyze` | Dosya analizi (multipart: `file`, opsiyonel `source_ip`) |
| POST | `/api/block-ip` | IP engelleme istegi |
| GET | `/api/report/{threat_id}` | Olay raporu (JSON) |
| GET | `/api/report/{threat_id}/docx` | Olay raporu (DOCX) |

## Ornek Kullanim

Dosya analizi:

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze" ^
  -F "file=@sample.exe" ^
  -F "source_ip=203.0.113.10"
```

IP engelleme:

```bash
curl -X POST "http://127.0.0.1:8000/api/block-ip" ^
  -H "Content-Type: application/json" ^
  -d "{\"ip\":\"203.0.113.10\",\"reason\":\"SOC containment\"}"
```

## Notlar

- Analiz modeli demo amacli sezgisel bir yaklasim kullanir; uretim ortami icin yeterli degildir.
- Uygulama verileri bellekte tutulur, yeniden baslatma sonrasi sifirlanir.
- Yukleme limiti varsayilan olarak 10 MB'dir.
