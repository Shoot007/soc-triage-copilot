import os
import json
import requests
import urllib3
from openai import OpenAI
from dotenv import load_dotenv

# Disable warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

def get_wazuh_token():
    print("[*] Authenticating with Wazuh API...")
    auth_url = f"{os.getenv('WAZUH_URL')}/security/user/authenticate"
    auth_resp = requests.post(auth_url, auth=(os.getenv('WAZUH_USER'), os.getenv('WAZUH_PASS')), verify=False)
    if auth_resp.status_code == 200:
        return auth_resp.json().get("data", {}).get("token")
    else:
        print("[!] Wazuh Authentication Failed!")
        return None

def fetch_latest_alert(token):
    print("[*] Fetching latest alerts from Wazuh...")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Fetching from alerts endpoint
    alerts_url = f"{os.getenv('WAZUH_URL')}/alerts?limit=1&sort=-timestamp"
    alerts_resp = requests.get(alerts_url, headers=headers, verify=False)
    
    if alerts_resp.status_code == 200:
        alerts_data = alerts_resp.json()
        items = alerts_data.get("data", {}).get("affected_items", [])
        if items:
            return items[0]
            
    # Fallback to fetch from archives (if no alerts are generated yet)
    print("[!] No alerts found. Trying to fetch raw events from Archives...")
    archives_url = f"{os.getenv('WAZUH_URL')}/archives?limit=1&sort=-timestamp"
    archives_resp = requests.get(archives_url, headers=headers, verify=False)
    
    if archives_resp.status_code == 200:
        archives_data = archives_resp.json()
        items = archives_data.get("data", {}).get("affected_items", [])
        if items:
            return items[0]
            
    return None

def main():
    token = get_wazuh_token()
    if not token:
        return

    alert = fetch_latest_alert(token)
    if not alert:
        print("[!] No security alerts or archives found in Wazuh. Please generate a test alert.")
        return

    alert_desc = alert.get('rule', {}).get('description', 'Unknown Alert')
    print(f"[+] Alert Found: {alert_desc}")

    # Extracting IP
    alert_data = alert.get("data", {})
    src_ip = alert_data.get("srcip") or alert_data.get("src_ip") or alert_data.get("dstip") or "8.8.8.8"
    print(f"[+] Source IP: {src_ip}")

    # Threat Intel APIs
    print("[*] Checking VirusTotal and AbuseIPDB...")
    vt_headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
    vt_resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{src_ip}", headers=vt_headers)
    vt_data = vt_resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    abuse_headers = {"Key": os.getenv("ABUSEIPDB_API_KEY"), "Accept": "application/json"}
    abuse_resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=abuse_headers, params={"ipAddress": src_ip})
    abuse_score = abuse_resp.json().get("data", {}).get("abuseConfidenceScore", 0)

    print(f"[+] VirusTotal Stats: {vt_data}")
    print(f"[+] AbuseIPDB Score: {abuse_score}")

    # AI Triage
    print("[*] Sending data to AI for Triage (AICredits)...")
    client = OpenAI(
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url="https://aicredits.in/v1"
    )

    prompt = f"""
    You are a SOC Level 1 Analyst. Below is a Wazuh Alert and its Source IP Threat Intel data.
    Strictly use the provided facts. Do not assume anything on your own.

    Alert Details:
    {json.dumps(alert, indent=2)}

    Threat Intel:
    - VirusTotal Stats: {vt_data}
    - AbuseIPDB Confidence Score (0-100): {abuse_score} (High score means malicious)

    Task: Triage the alert and output strictly in valid JSON format (no markdown, no extra text).
    JSON Schema:
    {{
      "verdict": "True Positive" | "False Positive" | "Benign True Positive" | "Insufficient Evidence",
      "confidence": 0.0 to 1.0,
      "mitre_id": "TXXXX",
      "mitre_name": "Name of technique",
      "reasoning": "Short 2-3 lines explaining why",
      "recommended_action": "What L1 should do"
    }}
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You are a helpful SOC assistant that only outputs JSON."}, {"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        triage_result = response.choices[0].message.content

        print("\n" + "="*40)
        print("       AI TRIAGE REPORT")
        print("="*40)
        parsed_res = json.loads(triage_result)
        print(json.dumps(parsed_res, indent=2))
        
        os.makedirs("reports", exist_ok=True)
        with open(f"reports/alert_{alert.get('id', 'unknown')}.json", "w") as f:
            f.write(triage_result)
        print(f"\n[+] Report successfully saved in reports/ folder.")

    except Exception as e:
        print(f"\n[!] AI API Error: {e}")

if __name__ == "__main__":
    main()
