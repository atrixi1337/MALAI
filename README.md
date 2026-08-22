# 🔬 MALAI — Malware Analysis AI Agent

AI-powered malware analysis and forensic reporting tool. Upload any suspicious file and get comprehensive static analysis with AI-generated threat assessments powered by [OrcaRouter](https://orcarouter.ai).

![MALAI](https://img.shields.io/badge/AI-Malware%20Analysis-blue) ![Python](https://img.shields.io/badge/Python-3.11+-yellow) ![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green)

## ✨ Features

- **🔬 Static Analysis** — PE header parsing, entropy analysis, file type detection, anomaly detection
- **🔐 Hash Computation** — MD5, SHA-1, SHA-256, SHA-512, ssdeep (fuzzy hashing)
- **📝 String Extraction** — Suspicious API calls, URLs, IPs, registry keys, PowerShell commands
- **🏷️ YARA Scanning** — Match against malware signature rules (10+ built-in rules)
- **🎯 IOC Extraction** — Automatically extract IPs, domains, hashes, URLs, crypto wallets, etc.
- **🧠 AI IOC Adjudication** — OrcaRouter LLM labels each extracted IOC as TRUE_SUSPICIOUS / BENIGN / UNVERIFIED, grounded in VirusTotal data, to cut false positives
- **🌐 VirusTotal Enrichment** — File reputation by hash (upload-if-absent), plus domain/IP/URL lookups, surfaced with detections, tags, and relations
- **🤖 AI Analysis** — LLM-powered threat classification via OrcaRouter (supports GPT, Claude, Gemini, Qwen, and more)
- **📊 Risk Scoring** — Composite 0–100 risk score with Critical/High/Medium/Low/Info levels
- **🌐 Web UI** — Modern drag-and-drop interface for easy file analysis

---

## 🚀 Quick Start

### Prerequisites

- **Docker & Docker Compose** (recommended), or **Python 3.11+**
- An [OrcaRouter](https://orcarouter.ai) API key (`sk-orca-...`)

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/atrixi1337/MALAI.git
cd MALAI
```

Create your `.env` file:

```bash
cp .env.example .env
```

Edit `.env` and add your OrcaRouter API key:

```env
ORCAROUTER_API_KEY=sk-orca-your-key-here
ORCAROUTER_BASE_URL=https://api.orcarouter.ai/v1
ORCAROUTER_MODEL=qwen/qwen3.8-27b-free
```

Build and run:

```bash
docker compose up --build
```

Open **http://localhost:8000** in your browser.

### Option 2: Local Setup (without Docker)

```bash
# Clone and enter the project
git clone https://github.com/atrixi1337/MALAI.git
cd MALAI

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate   # Linux / macOS
# venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your OrcaRouter API key

# Run the app
python app.py
```

Open **http://localhost:8000**.

---

## ⚙️ Configuration

All configuration is done via environment variables (set in `.env` or `docker-compose.yml`):

| Variable | Default | Description |
|---|---|---|
| `ORCAROUTER_API_KEY` | — | Your OrcaRouter API key (required) |
| `ORCAROUTER_BASE_URL` | `https://api.orcarouter.ai/v1` | OrcaRouter API endpoint |
| `ORCAROUTER_MODEL` | `qwen/qwen3.8-27b-free` | LLM model to use (see [supported models](https://docs.orcarouter.ai)) |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key (optional; enables enrichment) |
| `VIRUSTOTAL_UPLOAD_IF_ABSENT` | `true` | Upload the sample to VT when no report exists for its hash |
| `MAX_FILE_SIZE_MB` | `50` | Maximum upload file size in MB |
| `YARA_RULES_DIR` | `./rules` | Directory containing YARA rule files |

### Available Models

OrcaRouter supports models from multiple providers. Set `ORCAROUTER_MODEL` to any of:

| Model | Provider |
|---|---|
| `qwen/qwen3.8-27b-free` | Qwen (free tier) |
| `openai/gpt-4o-mini` | OpenAI |
| `anthropic/claude-sonnet-4.6` | Anthropic |
| `google/gemini-2.5-pro` | Google |
| `deepseek/deepseek-chat` | DeepSeek |

Full list at [docs.orcarouter.ai](https://docs.orcarouter.ai).

---

## 📡 API

### Analyze a file

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@suspicious.exe"
```

### Generate full forensic report

```bash
curl -X POST http://localhost:8000/api/report \
  -F "file=@suspicious.exe"
```

### Health check

```bash
curl http://localhost:8000/api/health
```

---

## 🏗️ Architecture

```
MALAI/
├── app.py                  # FastAPI web server & API endpoints
├── config.py               # Configuration management
├── agents/
│   ├── analyzer.py         # Main analysis orchestrator
│   └── ai_engine.py        # OrcaRouter LLM integration
├── analyzers/
│   ├── static_analyzer.py  # PE analysis, entropy, file type
│   ├── string_analyzer.py  # String extraction & categorization
│   ├── hash_analyzer.py    # Multi-hash computation
│   ├── yara_analyzer.py    # YARA rule matching
│   └── ioc_extractor.py    # IOC extraction
├── rules/
│   └── malware_indicators.yar  # Default YARA rules
├── static/
│   └── index.html          # Web UI
├── .env.example            # Environment template
├── Dockerfile
└── docker-compose.yml
```

---

## 🛡️ Built-in YARA Rules

| Rule | Description | Severity |
|------|-------------|----------|
| Suspicious PowerShell | Encoded commands, bypass, hidden | High |
| Registry Autorun | Persistence via Run keys | High |
| Suspicious API Calls | Process injection patterns | High |
| Potential Ransomware | Encryption + ransom indicators | Critical |
| Network Activity | C2 communication patterns | Medium |
| Anti-Analysis | Debug/VM detection, evasion | Medium |
| Coin Miner | Mining pool references | Medium |
| Script Obfuscation | eval(), base64, obfuscation | High |
| Data Exfiltration | Data theft indicators | High |
| Known Malware | Mirai, Emotet, Cobalt Strike | Critical |

---

## ⚠️ Disclaimer

MALAI is for **research and educational purposes only**. Always analyze malware in isolated/sandboxed environments. Never run suspicious files on production systems. The authors are not responsible for any misuse.

## 📄 License

MIT
