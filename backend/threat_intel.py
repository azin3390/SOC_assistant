import requests
import os
from dotenv import load_dotenv

load_dotenv('/Users/aziniftikhar/soc_assistant/.env')
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return {"error": f"API error {r.status_code}"}
    data = r.json()['data']['attributes']
    stats = data.get('last_analysis_stats', {})
    return {
        "type": "ip",
        "value": ip,
        "malicious": stats.get('malicious', 0),
        "suspicious": stats.get('suspicious', 0),
        "harmless": stats.get('harmless', 0),
        "country": data.get('country', 'Unknown'),
        "reputation": data.get('reputation', 0),
        "verdict": "Malicious" if stats.get('malicious', 0) > 0 else "Suspicious" if stats.get('suspicious', 0) > 0 else "Clean"
    }

def check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return {"error": f"API error {r.status_code}"}
    data = r.json()['data']['attributes']
    stats = data.get('last_analysis_stats', {})
    return {
        "type": "domain",
        "value": domain,
        "malicious": stats.get('malicious', 0),
        "suspicious": stats.get('suspicious', 0),
        "harmless": stats.get('harmless', 0),
        "reputation": data.get('reputation', 0),
        "verdict": "Malicious" if stats.get('malicious', 0) > 0 else "Suspicious" if stats.get('suspicious', 0) > 0 else "Clean"
    }

def check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return {"error": f"API error {r.status_code}"}
    data = r.json()['data']['attributes']
    stats = data.get('last_analysis_stats', {})
    return {
        "type": "hash",
        "value": file_hash,
        "malicious": stats.get('malicious', 0),
        "suspicious": stats.get('suspicious', 0),
        "harmless": stats.get('harmless', 0),
        "name": data.get('meaningful_name', 'Unknown'),
        "verdict": "Malicious" if stats.get('malicious', 0) > 0 else "Suspicious" if stats.get('suspicious', 0) > 0 else "Clean"
    }

def analyze(value):
    value = value.strip()
    # Detect what type of indicator it is
    import re
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
        return check_ip(value)
    elif re.match(r'^[a-fA-F0-9]{32,64}$', value):
        return check_hash(value)
    else:
        return check_domain(value)

# Test it
if __name__ == '__main__':
    print("Testing VirusTotal API...")
    result = analyze("8.8.8.8")
    print(result)
