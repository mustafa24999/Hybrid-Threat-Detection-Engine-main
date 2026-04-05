# Zenith Hybrid Threat Detection Engine
**Enterprise-Grade Static Analysis & Intelligence Correlation**

## 1. Overview
The Zenith Hybrid Threat Detection Engine is a multi-component cybersecurity tool designed to analyze URLs and files for malicious intent. It combines "Zenith-Tier" local static analysis (heuristics, magic bytes, entropy, domain patterns) with external threat intelligence (VirusTotal) to provide a comprehensive, low-latency risk assessment.

### Zenith-Tier Improvements
- **SOC-Ready Logging**: JSON-structured logs streamed to `stdout` for SIEM (ELK/Splunk) ingestion.
- **Deep Static Inspection**: Static analysis for OLE Macros, PDF JavaScript objects, PE integrity (Signature/Packers), and Binary Null-Byte detection.
- **Hardened API**: Mandatory `X-Zenith-Auth` header verification for all client requests.
- **Performance Architecture**: SQLite WAL-mode concurrency and 4KB-chunked header caching for rapid analysis.

## 1.1. Installation
```bash
git clone https://github.com/AbasSec/Hybrid-Threat-Detection-Engine
cd Hybrid-Threat-Detection-Engine
```

## 2. Architecture Diagram
```text
[ Browser Guard ] <--- (Context Menu / Navigation Hook)
        |
        | (JSON/HTTP + X-Zenith-Auth)
        v
[ Zenith Backend ] <---- [ SQLite WAL Database ]
        |       |
        |       +---- [ Local Analyzers (Deep Static Inspection) ]
        |
        +---- [ Threat Intel: VirusTotal API ] (Optional)
        ^
        | (Multipart/JSON)
        |
[ Desktop Analyst ] <--- (Local File System / History Review)
```

# 2. Setup & Configuration
The easiest way to configure the Zenith Engine is using our interactive setup script. This will create your environment file and prompt you for your API keys.

```bash
python3 setup.py
```

## 3. Deployment (Production / Docker)
Once configured, you can launch the backend using Docker for isolation and scale.

```bash
# 1. Install Docker (Kali/Debian)
sudo apt update && sudo apt install -y docker.io docker-compose && sudo systemctl start docker

# 2. Launch Engine
sudo docker-compose up --build -d
```

### 3.1 24/7 Background Service (Linux Systemd)
To keep the Zenith Engine running 24/7 in the background without Docker:

```bash
# 1. Copy the service file to systemd
sudo cp zenith-backend.service /etc/systemd/system/

# 2. Reload and enable the service
sudo systemctl daemon-reload
sudo systemctl enable zenith-backend
sudo systemctl start zenith-backend

# 3. Verify status
sudo systemctl status zenith-backend
```
The system persists scan history in the `./data` volume and logs JSON metadata to the container output.

## 4. Client Setup & Quick Start
For beginners and non-terminal experts, we provide an interactive setup script that handles dependency installation and configuration automatically.

### 4.1 Quick Start (Recommended)
Before running the setup, ensure you have the necessary build tools (required for some Python dependencies on Linux):

```bash
# Install build tools and UI library (Debian/Ubuntu/Kali)
sudo apt update && sudo apt install -y build-essential python3-venv python3-tk

# 1. Run the interactive setup
python3 setup.py
```

# 2. Start the Engine and Dashboard
# On Windows:
.\start_zenith.bat

# On Linux/Mac:
./start_zenith.sh
```

### 4.2 Manual Desktop Analyst Setup
If you prefer manual configuration:
1. **Create Virtual Environment**: `python3 -m venv venv && source venv/bin/activate`
2. **Install Dependencies**: `pip install -r backend/requirements.txt -r desktop-app/requirements.txt`
3. **Configure API Key**: Copy `backend/.env.example` to `backend/.env` and add your `VT_API_KEY`.
4. **Run Application**: `python3 desktop-app/app.py`

### 4.3 Dashboard Configuration
The **Desktop Analyst** now includes a built-in **Settings** menu (⚙) that allows you to update your VirusTotal API key and backend configuration directly from the UI without touching the terminal or `.env` files.

### 4.3 Browser Guard (Extension) Setup
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `browser-extension/` folder.
4. **Interception Feature**: When you click any link, a "Zenith Shield" modal will appear asking if you want to **Scan Link** or **Navigate Direct**.
5. **Troubleshooting (If popup doesn't show)**: 
   * **Reload Pages**: The extension only works on tabs that are refreshed *after* the extension is installed.
   * **Re-install**: If updates aren't appearing, **Remove** the extension from `chrome://extensions/` and click **Load unpacked** again.
   * **Icons**: Ensure the `browser-extension/icons/icon.svg` file exists (automatically created by `setup.py`).

## 5. Security & Configuration
The Zenith Engine requires a mandatory API Key for all transactions.
- **Backend**: Set `BACKEND_API_KEY` in `backend/.env`.
- **Clients**: Set the matching key in `desktop-app/app.py` (`ZENITH_AUTH_KEY`) and `browser-extension/background.js` (`ZENITH_AUTH_KEY`).

To disable external intelligence lookups, set `THREAT_PROVIDER=null` in the `.env` file.

## 6. Scoring Logic
| Vector | Check | Weight |
|--------|-------|--------|
| **URL** | Insecure Protocol (HTTP) | +0.15 |
| **URL** | IP-Based Host (Obfuscation) | +0.40 |
| **URL** | DGA Detection (High Entropy > 3.8) | +0.25 |
| **URL** | Phishing Keywords (login, verify, etc.) | Up to +0.40 |
| **File** | High-Risk Extension (.exe, .ps1, etc.) | +0.35 |
| **File** | Magic Byte / Extension Mismatch | +0.45 |
| **File** | Deep PE Check (Packers/Malformed Header) | Up to +0.50 |
| **File** | Embedded Macros (VBA/JS) | +0.50 |
| **Global**| VirusTotal Detection Rate > 10% | +0.50 |

**Risk Thresholds:**
- **Safe**: < 0.30
- **Suspicious**: 0.30 - 0.65
- **Malicious**: > 0.65

## 7. Development & Testing
Zenith includes a deep heuristic verification suite.
```bash
# Generate test samples
python3 tests/generate_samples.py

# Run verification suite
python3 tests/test_zenith_engine.py
```

## 8. API Reference
- `POST /scan/url`: Scans a URL for static threats.
- `POST /scan/file`: Upload and analyze a file (Multi-part).
- `GET /history`: Retrieve recent scan records (Supports `limit` param).
- `GET /health`: Engine status and active provider verification.

## 9. Future Roadmap
- **ML Integration**: Random Forest classifier for polymorphic threat detection.
- **YARA Support**: Integration of custom SOC YARA rules for file scanning.
- **Sandboxing**: Automated dynamic execution analysis in isolated containers.

---
*Zenith Hybrid Threat Detector - Protected by Senior Security Engineering Standards.*
