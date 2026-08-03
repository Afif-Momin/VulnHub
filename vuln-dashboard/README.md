# Centralized Vulnerability Assessment Dashboard (VulnHub Auditor)

A centralized, unified vulnerability scanner orchestration and reporting platform designed for assessing network targets, such as **VulnHub** virtual machines, as well as local or remote development environments. It integrates **Nmap**, **OWASP ZAP**, and **OpenVAS**, normalizes their raw scanner outputs into a unified Pydantic data model, persists them in an SQLite database, and displays interactive metrics, severity breakdowns, remediation instructions, and exportable reports.

---

## What is VulnHub and How Does This Dashboard Help?

**[VulnHub](https://www.vulnhub.com/)** is a well-known platform that hosts pre-configured virtual machines (VMs) containing deliberate security vulnerabilities, design exploits, and configuration weaknesses. These VMs serve as legal, local environments for cybersecurity professionals and students to practice penetration testing, security auditing, and vulnerability assessment.

### Role of the Vulnerability Assessment Dashboard:
When auditing a VulnHub VM, researchers usually run several independent scanning tools which output separate, non-standardized reports (Nmap XMLs, ZAP JSONs, OpenVAS logs).
This dashboard acts as a **centralized vulnerability manager**:
1. **Target Identification:** Run Nmap to discover open ports, protocols, and active services on the target VulnHub VM's local IP address.
2. **Web Vulnerability Scanning:** Target HTTP/HTTPS endpoints on the VM with OWASP ZAP's spider and active scanning rules.
3. **Infrastructure Vulnerability Assessment:** Run deep network checks on the VM services using OpenVAS.
4. **Data Normalization:** Ingest all distinct scanner results, automatically normalize them to a single schema, apply custom severity overrides, and enrich them with structured remediation steps.
5. **Unified Reporting:** View full dashboards of the VulnHub VM's threat profile, inspect evidence side-by-side with remediation steps, and download technical or executive PDF reports.

---

## Architecture Overview

```
vuln-dashboard/
├── backend/
│   ├── main.py                # FastAPI server & route orchestration
│   ├── scanners/
│   │   ├── nmap_scanner.py    # Subprocess execution & XML parser
│   │   ├── zap_scanner.py     # HTTP Agent for OWASP ZAP API
│   │   └── openvas_scanner.py # python-gvm GMP connector & XML parser
│   ├── models/
│   │   └── finding.py         # Unified Finding schema (Pydantic)
│   ├── storage/
│   │   └── db.py              # SQLite storage engine (standard library)
│   ├── reports/
│   │   └── report_builder.py  # ReportLab PDF & JSON exporter
│   └── remediation/
│       ├── guidance.py        # Severity overrides & enrichment logic
│       └── rules.json         # Severity mapping database definitions
├── frontend/
│   └── dashboard.py           # Streamlit application UI
├── tests/
│   ├── fixtures/              # Sample XML & JSON scanner outputs
│   ├── test_scanners.py       # Scanner unit tests
│   └── test_integration.py    # End-to-end pipeline integration test
└── requirements.txt           # Python application dependencies
```

---

## Setup and Installation

### 1. Setup Python Virtual Environment
Install Python 3.11 or higher on your host system. Navigate into the `vuln-dashboard` folder inside your repository root, then initialize the environment:

#### On Windows (PowerShell):
```powershell
cd vuln-dashboard
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

#### On Linux Ubuntu:
```bash
cd vuln-dashboard
sudo apt update
sudo apt install -y python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Ingress / Scanning Tools Configuration

### Setup on Linux Ubuntu

#### Nmap
```bash
sudo apt install -y nmap
```

#### OWASP ZAP
1. Download the Linux package from the [OWASP ZAP Download Page](https://www.zaproxy.org/download/).
2. Run ZAP in headless/daemon mode:
```bash
./zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.key=your_secret_api_key
```

#### OpenVAS / Greenbone
1. Install Greenbone Vulnerability Manager:
```bash
sudo apt install -y gvmd openvas-scanner
```
2. The dashboard automatically discovers the socket at `/run/gvmd/gvmd.sock`.

---

### Setup on Windows

#### Nmap
1. Download and run the official Windows executable installer from [nmap.org](https://nmap.org/download.html).
2. Ensure the Nmap installation directory (e.g. `C:\Program Files (x86)\Nmap`) is added to your environment variable `PATH`.

#### OWASP ZAP
1. Download and run the Windows MSI installer from the [OWASP ZAP Download Page](https://www.zaproxy.org/download/).
2. Start ZAP daemon mode via Command Prompt or PowerShell:
```cmd
zap.bat -daemon -host 127.0.0.1 -port 8080 -config api.key=your_secret_api_key
```

#### OpenVAS Platform Workaround on Windows
OpenVAS/GVM cannot run natively on Windows. To test OpenVAS targeting from a Windows host:
1. Run GVM inside a Linux VM (VirtualBox/VMware), WSL2 (Ubuntu), or a Docker container.
2. In the Streamlit **Scan Console**, choose **OpenVAS Network Scan** and uncheck *Connect via Unix Socket*.
3. Provide the remote TLS credentials (GVM Host IP, GMP Port 9390, Username, and Password).

---

## How to Test and Run the Dashboard

To verify and test that the backend, database storage, and front-end dashboard are operating correctly, follow these guides.

### Step 1: Run the Automated Test Suite (Offline Verification)
Both Windows and Linux can execute the automated test suite. Make sure you are in the `vuln-dashboard` directory and your virtual environment is active.

#### On Windows (PowerShell):
```powershell
cd "C:\AFIF\CyberSec Projects\VulnHub\vuln-dashboard"
$env:PYTHONPATH="."
python -m pytest tests/
```

#### On Linux Ubuntu:
```bash
cd vuln-dashboard
export PYTHONPATH="."
python3 -m pytest tests/
```

Expected output:
```text
tests/test_integration.py .
tests/test_scanners.py .....
============================== 6 passed in 0.31s ==============================
```

---

### Step 2: Running the Live Application

#### 1. Start the FastAPI Backend
Open a terminal, navigate into the project directory, activate the environment, and run:

- **On Windows (PowerShell):**
  ```powershell
  cd "C:\AFIF\CyberSec Projects\VulnHub\vuln-dashboard"
  .\venv\Scripts\Activate.ps1
  python -m uvicorn backend.main:app --reload --port 8000
  ```
- **On Linux Ubuntu:**
  ```bash
  cd vuln-dashboard
  source venv/bin/activate
  python3 -m uvicorn backend.main:app --reload --port 8000
  ```

*Access the interactive API docs at http://127.0.0.1:8000/docs.*

#### 2. Start the Streamlit Frontend Dashboard
Open a **second terminal session**, navigate into the project directory, activate the environment, and run:

- **On Windows (PowerShell):**
  ```powershell
  cd "C:\AFIF\CyberSec Projects\VulnHub\vuln-dashboard"
  .\venv\Scripts\Activate.ps1
  python -m streamlit run frontend/dashboard.py
  ```
- **On Linux Ubuntu:**
  ```bash
  cd vuln-dashboard
  source venv/bin/activate
  python3 -m streamlit run frontend/dashboard.py
  ```

The dashboard interface will automatically launch in your default web browser at http://localhost:8501.

---

### Step 3: Performing a Verification Walkthrough (How to Test)

1. **Verify Scanner Connection status:**
   Check the sidebar diagnostics panel. The "Backend API Server" should show green `Connected to Backend`, and Nmap status will indicate whether the scanner was discovered in the host path.
2. **Ingest Mock Reports (Offline Ingest verification):**
   - Click the **Ingest Center** tab on the Streamlit page.
   - Select **Nmap XML (-oX file)** and upload `tests/fixtures/nmap_sample.xml`. Click **Import Scan Record**.
   - Select **OWASP ZAP JSON Alerts** and upload `tests/fixtures/zap_sample.json`. Click **Import Scan Record**.
   - Select **OpenVAS GVM XML Results** and upload `tests/fixtures/openvas_sample.xml`. Click **Import Scan Record**.
   - Head back to the **Analytics Dashboard** tab. You should see interactive graph figures and metrics (1 Critical, 2 High, 1 Medium, 3 Info) loaded in the SQLite database.
3. **Audit Findings & Guidance:**
   - Scroll down to the **Findings Inspector Table** to filter and sort target details.
   - Use the **Finding Inspector Detail Panel** dropdown to inspect specific findings (e.g. SQL Injection). Verify that the Remediation Guidance section shows database parameterized instructions and raw XML/JSON evidence blocks.
4. **Test Report Exports:**
   - In the sidebar, click **Download Technical PDF** or **Download Executive PDF**.
   - Open the generated PDF file to verify proper ReportLab styling and counts rendering.
5. **Run a Live Scan against a local authorized host:**
   - Click the **Scan Console** tab.
   - Input your target IP (e.g. `127.0.0.1`).
   - Acknowledge the target scanning authorization checkbox.
   - Click **Trigger Nmap Scan** to execute a real-time subprocess port probe. Once complete, findings will refresh on the analytics page.

---

## Known Limitations
1. **Nmap Scan Privileges:** Certain fast SYN scans (`-sS`) require Administrator/root privileges. To ensure smooth local running without administrative prompt alerts, the dashboard defaults to standard TCP Connect scans (`-sT`).
2. **ZAP Scan Duration:** Spider and active scans on large websites can run for several minutes. Ensure your target URL has a small tree for quick portfolio demonstrations.
3. **OpenVAS Windows support:** Requires a remote endpoint; local Unix socket mapping is bypassed on Windows.
