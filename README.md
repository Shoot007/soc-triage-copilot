# 🛡️ SOC Triage Copilot

An automated SOC Level 1 alert triage pipeline using Wazuh, Threat Intelligence APIs, and LLMs.

## 🚀 Features
- **Wazuh Integration:** Pulls latest alerts directly from the Wazuh API.
- **Threat Intelligence Enrichment:** Automatically extracts source IPs and queries VirusTotal and AbuseIPDB for reputation scores.
- **AI Triage:** Uses OpenAI to analyze the alert and threat intel, providing a verdict (True Positive/False Positive), confidence score, MITRE ATT&CK mapping, and recommended action.
- **Human-in-the-Loop:** AI only generates the report; it does not auto-block IPs.

## 🛠️ Tech Stack
- **SIEM:** Wazuh
- **Language:** Python 3
- **APIs:** Wazuh API, VirusTotal API, AbuseIPDB API, OpenAI API

## ⚙️ Setup Instructions
1. Clone the repository.
2. Create a virtual environment: `python3 -m venv venv`
3. Activate it: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Create a `.env` file in the root directory and add your API keys.
6. Run the script: `python3 main.py`
