# ZENITH HYBRID THREAT DETECTION ENGINE: THE ULTIMATE MASTER GUIDE
**Zenith-Tier Security Operations & Implementation Manual**

---

## 1. PREFACE: THE ARCHITECTURE OF TRUST
In the modern cybersecurity landscape, the "Detection Gap"—the time between a threat's release and its signature's creation—is the primary vulnerability of enterprise networks. The Zenith Hybrid Threat Detection Engine was engineered specifically to close this gap. By focusing on the structural and behavioral markers of malicious code rather than specific signatures, Zenith identifies the *intent* of a file or URL.

This guide serves as the definitive reference for deploying, managing, and maximizing the efficacy of the Zenith ecosystem. It covers the three-pillar architecture: the **FastAPI Core**, the **Browser Guard**, and the **Analyst Workstation**.

---

## 2. PART I: SYSTEM REQUIREMENTS & PREREQUISITES
Before deploying the Zenith Engine, verify that your environment meets the following specifications to ensure "Zenith-Tier" performance.

### 2.1 Hardware Specifications
- **Small Office/Home Office (SOHO)**: 2 CPU Cores, 2GB RAM, 10GB SSD.
- **Enterprise SOC Deployment**: 4 CPU Cores, 8GB RAM, 50GB SSD (for history retention).
- **Network**: Port 8000 (TCP) must be open for internal traffic between clients and the backend.

### 2.2 Software Dependencies
- **Backend**: Python 3.9+ or Docker Engine 20.10+.
- **Desktop Analyst**: Python 3.9+ with `tkinter` and `requests`.
- **Browser Guard**: Google Chrome, Microsoft Edge, or any Chromium-based browser supporting Manifest V3.

---

## 3. PART II: THE INSTALLATION JOURNEY

### 3.1 Method A: The Containerized Deployment (Recommended)
Containerization is the gold standard for Zenith deployment. It isolates the engine from the host OS, preventing any potential cross-contamination during file analysis.

1.  **Prepare the Environment**: Ensure `docker` and `docker-compose` are installed.
2.  **Configuration**: Copy `backend/.env.example` to `backend/.env`.
3.  **Launch**:
    ```bash
    docker-compose up --build -d
    ```
4.  **Verification**: Access `http://127.0.0.1:8000/health`. A JSON response confirming "ok" status indicates a successful launch.

### 3.2 Method B: Bare-Metal Installation
For specialized environments where Docker is restricted:
1.  **Clone & Navigate**:
    ```bash
    git clone https://github.com/AbasSec/Hybrid-Threat-Detection-Engine.git
    cd Hybrid-Threat-Detection-Engine
    ```
2.  **Environment Setup**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r backend/requirements.txt
    ```
3.  **Manual Start**:
    ```bash
    python3 backend/main.py
    ```

---

## 4. PART III: BROWSER GUARD SETUP (FOR EVERY ENDPOINT)
The Browser Guard is the "Shield at the Edge." It must be deployed to every workstation in the organization.

### 4.1 Loading the Extension
1.  Open Chrome and go to `chrome://extensions/`.
2.  Enable **Developer Mode**.
3.  Select **Load Unpacked** and point to the `browser-extension/` folder.

### 4.2 Hardening the Connection
1.  Open `browser-extension/background.js`.
2.  Change `BACKEND_URL` to point to your server's internal IP (e.g., `http://10.0.0.50:8000`).
3.  Set `ZENITH_AUTH_KEY` to match your backend `.env` file. This prevents unauthorized users from querying your internal engine.

---

## 5. PART IV: DEEP FEATURE EXPLORATION

### 5.1 The "Pause-and-Scan" Interception Logic
This is the Zenith Engine's most unique capability. 
- **The Problem**: Users often click phishing links impulsively.
- **The Zenith Solution**: By right-clicking a link and selecting **🛡 Scan this link for threats**, the extension "hooks" the navigation. It creates a temporary session state that prevents the browser from loading the URL until the scan is complete.
- **User Agency**: Once the results are displayed, the user is given a choice: "Proceed anyway" or "Cancel." This friction is intentional; it forces a "Security First" mindset.

### 5.2 Heuristic Ability: Domain Generation Algorithms (DGA)
Botnets often generate thousands of random domain names to communicate with their Command & Control (C2) servers.
- **How Zenith Detects It**: The engine calculates the **Shannon Entropy** of the domain. 
- **The Science**: English-language domains have a predictable frequency of characters. Randomly generated strings (e.g., `q1w2e3r4t5y6.xyz`) have a much higher entropy.
- **Analyst Note**: Any domain with an entropy score above **3.8** should be treated as a high-risk indicator of a compromised machine on the network.

### 5.3 Heuristic Ability: Portable Executable (PE) Integrity
When a file is uploaded to the Zenith Desktop Analyst, the engine performs a deep-dive into the binary structure.
- **MZ Header Verification**: Every Windows executable starts with `MZ`.
- **PE Signature Mapping**: Zenith follows the pointer at offset `0x3C` to find the `PE\0\0` signature.
- **Packer Detection**: The engine scans for section names like `UPX0`, `.aspack`, or `PELOCK`. Since legitimate software rarely uses these packers, their presence is a 95% confidence indicator of malware.

### 5.4 Heuristic Ability: Document & Script Payloads
The "Zenith-Tier" engine includes specialized parsers for the most common enterprise attack vectors.
- **OLE/VBA Macros**: Scans Excel and Word documents for the `VBA_Project` stream.
- **PDF JavaScript**: Detects `/JS` and `/JavaScript` objects.
- **Script Patterns**: Identifies "Bypass" execution policies in PowerShell and `WScript.Shell` instantiation in VBScripts.

---

## 6. PART V: THE ANALYST WORKFLOW (SOC OPERATIONS)
In a professional SOC environment, Zenith is used as a "Triage Tool."

### 6.1 Step-by-Step Triage
1.  **Observation**: An alert is triggered in the SIEM showing a high-entropy URL scan.
2.  **Investigation**: The analyst opens the **Zenith Desktop Analyst**.
3.  **Comparison**: The analyst reviews the "Scan History" pane to see if other users have scanned similar URLs.
4.  **Deep Dive**: The analyst retrieves the suspicious file from the user's quarantine and uploads it to Zenith for structural analysis.
5.  **Conclusion**: Based on the combined score (Local Heuristics + VirusTotal Intelligence), the analyst either clears the alert or initiates an Incident Response (IR) ticket.

---

## 7. PART VI: SIEM & LOG INTEGRATION
Zenith was built to be observed. Every scan produces a structured JSON log entry.

### 7.1 Integrating with ELK (Elasticsearch, Logstash, Kibana)
To ingest Zenith logs:
1.  Configure Filebeat to monitor the Docker container's stdout.
2.  Map the `analysis.score` field to a numeric type in Elasticsearch.
3.  Create a Kibana dashboard showing:
    - **Threat Volume**: A line graph of "Malicious" vs "Safe" scans.
    - **Top Targets**: A pie chart of the most frequently scanned suspicious domains.
    - **Client Heatmap**: Identification of internal IPs with the most high-risk scans (indicator of targeted phishing).

---

## 8. PART VII: TROUBLESHOOTING & MAINTENANCE

### 8.1 The "Engine Error" Status
If the extension or desktop app shows a red status dot:
1.  Check the API Key. A mismatch between the client and backend will result in a `403 Forbidden` error, which Zenith interprets as an offline engine for security reasons.
2.  Check the WAL file. If the system was shut down improperly, the `scan_history.db-wal` file might be locked. Deleting the `-wal` and `-shm` files (while the engine is stopped) usually resolves the issue.

### 8.2 Database Pruning
Zenith automatically limits history to 500 records by default. If you need to increase this for compliance:
1.  Open `backend/config.py`.
2.  Modify `MAX_HISTORY_RECORDS`.
3.  Restart the backend.

---

## 9. PART VIII: THE ROAD TO ZERO-DAY PROTECTION
Zenith's true power lies in its weights. By adjusting the `SCORE_MALICIOUS_THRESHOLD` in the `.env` file, an organization can tune the engine's sensitivity.
- **High-Security Mode**: Set threshold to `0.50`. This will result in more false positives but will catch subtle threats.
- **Balanced Mode (Default)**: Set to `0.65`. Ideal for most corporate environments.

---

## 10. CONCLUSION: CONSTANT VIGILANCE
The Zenith Hybrid Threat Detection Engine is a living system. As new malware techniques emerge (like Typosquatting on new TLDs like `.zip` or `.mov`), Zenith can be updated by simply adding a new heuristic check to the `url_analyzer.py` or `file_analyzer.py` modules.

By following this guide, your organization has deployed a world-class, static-analysis-first defense layer. We recommend monthly review of the Zenith scan history to identify trends in the threats targeting your users.

**Stay Secure. Stay Zenith.**

---
*Manual End*
