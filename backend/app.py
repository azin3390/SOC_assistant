from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from threat_intel import analyze
from rag_engine import RAGEngine
from log_analyzer import analyze_logs
from report_generator import generate_report
from timeline import generate_timeline_html
from url_scanner import scan_url as ml_scan_url
from crime_scene import analyze_crime_scene
import os, re, random
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
CORS(app)

print("Starting Sentinel SOC...")
rag = RAGEngine()
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rag.load_knowledge_base(os.path.join(BASE_DIR, 'data', 'threat_knowledge.txt'))
print("Sentinel SOC ready!")

chat_history = []
conversation_memory = {}

def detect_indicators(text):
    indicators = []
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
    for ip in ips: indicators.append(('ip', ip))
    hashes = re.findall(r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b', text)
    for h in hashes: indicators.append(('hash', h))
    common = ['google.com','microsoft.com','apple.com','github.com']
    domains = re.findall(r'\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b', text)
    for d in domains:
        if d not in common and len(d) > 5: indicators.append(('domain', d))
    return indicators[:3]

def generate_soc_response(query, rag_context, threat_results):
    response = {"analysis":"","threat_intel":threat_results,"recommendations":[],"severity":"Low","rag_context":rag_context}
    if threat_results:
        malicious_count = sum(t.get('malicious',0) for t in threat_results if 'malicious' in t)
        if malicious_count > 5: response["severity"] = "Critical"
        elif malicious_count > 0: response["severity"] = "High"
        elif any(t.get('suspicious',0) > 0 for t in threat_results): response["severity"] = "Medium"
    recs = {
        "Critical": ["🚨 IMMEDIATE: Isolate affected systems","🚨 Block malicious IPs at firewall","🚨 Escalate to senior SOC analyst","📋 Preserve logs for forensics","🔄 Begin incident response"],
        "High":     ["⚠️ Block suspicious IPs at firewall","🔍 Investigate affected systems","📋 Review logs for lateral movement","🔄 Monitor for more activity"],
        "Medium":   ["👀 Monitor indicators closely","📋 Add to watchlist","🔍 Investigate source"],
        "Low":      ["✅ No immediate action required","📋 Log for future reference","👀 Continue standard monitoring"]
    }
    response["recommendations"] = recs.get(response["severity"], recs["Low"])
    return response

@app.route('/')
def home():
    return send_from_directory(os.path.join(BASE_DIR, 'frontend'), 'index.html')

@app.route('/dashboard')
def dashboard():
    return send_from_directory(os.path.join(BASE_DIR, 'frontend'), 'index.html')

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({"error": "Send JSON with a message field"}), 400
    query = data['message'].strip()
    session_id = data.get('session_id', 'default')

    # Maintain simple conversation memory per session
    if session_id not in conversation_memory:
        conversation_memory[session_id] = []
    conversation_memory[session_id].append({"role": "user", "text": query})
    conversation_memory[session_id] = conversation_memory[session_id][-10:]  # keep last 10 turns

    rag_context = rag.answer(query)
    indicators = detect_indicators(query)
    threat_results = []
    for itype, ivalue in indicators:
        result = analyze(ivalue)
        if 'error' not in result: threat_results.append(result)

    response = generate_soc_response(query, rag_context, threat_results)
    conversation_memory[session_id].append({"role": "assistant", "text": rag_context[:200]})

    chat_history.append({"query":query,"severity":response["severity"]})
    print(f"[CHAT] {query[:50]} | Severity: {response['severity']}")
    return jsonify(response)

@app.route('/analyze', methods=['POST'])
def analyze_indicator():
    data = request.get_json()
    if not data or 'indicator' not in data:
        return jsonify({"error": "Send JSON with indicator field"}), 400
    return jsonify(analyze(data['indicator']))

@app.route('/analyze-logs', methods=['POST'])
def analyze_logs_route():
    data = request.get_json()
    if not data or 'logs' not in data:
        return jsonify({"error": "Send JSON with logs field"}), 400
    result = analyze_logs(data['logs'])
    timeline = generate_timeline_html(data['logs'])
    result['timeline_html'] = timeline['html']
    result['timeline_stats'] = timeline['stats']
    return jsonify(result)

@app.route('/scan-url', methods=['POST'])
def scan_url_route():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Send JSON with url field"}), 400
    url = data['url'].strip()
    ml_result = ml_scan_url(url)
    try:
        domain = url.replace('http://','').replace('https://','').split('/')[0]
        vt_result = analyze(domain)
    except:
        vt_result = {"error": "Could not extract domain"}
    rag_context = rag.answer(f"analyze this {ml_result['verdict']} URL: {url}")
    return jsonify({
        "url": url, "verdict": ml_result["verdict"],
        "risk_score": ml_result["risk_score"], "reasons": ml_result["reasons"],
        "ml_analysis": ml_result["ml_analysis"],
        "threat_intel": vt_result if 'error' not in vt_result else None,
        "rag_context": rag_context
    })

@app.route('/crime-scene', methods=['POST'])
def crime_scene_route():
    data = request.get_json()
    if not data or 'incident' not in data:
        return jsonify({"error": "Send JSON with incident field"}), 400
    result = analyze_crime_scene(data['incident'])
    return jsonify(result)

@app.route('/generate-report', methods=['POST'])
def generate_report_route():
    data = request.get_json()
    if not data: return jsonify({"error": "No data"}), 400
    output_path = '/tmp/threat_report.pdf'
    generate_report(data, output_path)
    return send_file(output_path, as_attachment=True, download_name='threat_report.pdf')

@app.route('/overview-stats', methods=['GET'])
def overview_stats():
    now = datetime.now()
    return jsonify({
        "total_alerts":     {"value": 2842, "change": 12.4,  "trend": "up"},
        "critical_alerts":  {"value": 120,  "change": 8.7,   "trend": "up"},
        "incidents":        {"value": 23,   "change": -4.3,  "trend": "down"},
        "assets_monitored": {"value": 1897, "change": 6.2,   "trend": "up"},
        "users_monitored":  {"value": 532,  "change": 3.1,   "trend": "up"},
        "last_updated":     now.strftime("%H:%M:%S")
    })

@app.route('/recent-alerts', methods=['GET'])
def recent_alerts():
    alerts = [
        {"id":"ALT-001","title":"Malware detected on workstation","source":"workstation-23","ip":"192.168.1.45","severity":"Critical","time":"10:24 AM","type":"malware"},
        {"id":"ALT-002","title":"Brute force attack detected","source":"SSH","ip":"203.0.113.25","severity":"High","time":"10:21 AM","type":"brute_force"},
        {"id":"ALT-003","title":"Suspicious login attempt","source":"user: admin","ip":"172.16.5.10","severity":"Medium","time":"10:18 AM","type":"auth"},
        {"id":"ALT-004","title":"Unusual outbound connection","source":"host-17","ip":"198.51.100.8","severity":"High","time":"10:15 AM","type":"c2"},
        {"id":"ALT-005","title":"New device added to network","source":"Laptop-19","ip":"192.168.1.88","severity":"Low","time":"10:12 AM","type":"asset"},
        {"id":"ALT-006","title":"SQL injection attempt blocked","source":"web-server-01","ip":"45.33.32.156","severity":"Critical","time":"10:08 AM","type":"sqli"},
        {"id":"ALT-007","title":"Privilege escalation attempt","source":"WORKSTATION-042","ip":"192.168.1.102","severity":"High","time":"10:05 AM","type":"priv_esc"},
    ]
    return jsonify({"alerts": alerts})

@app.route('/recent-incidents', methods=['GET'])
def recent_incidents():
    incidents = [
        {"id":"INC-2026-0521","title":"Ransomware detection on host","severity":"Critical","status":"In Progress","created":"Jun 21, 10:23 AM","assigned":"Alice Chen"},
        {"id":"INC-2026-0520","title":"Data exfiltration attempt","severity":"High","status":"Investigating","created":"Jun 20, 09:15 PM","assigned":"Bob Smith"},
        {"id":"INC-2026-0519","title":"Phishing campaign detected","severity":"Medium","status":"Resolved","created":"Jun 19, 04:42 PM","assigned":"Carol Wu"},
        {"id":"INC-2026-0518","title":"Privilege escalation attempt","severity":"High","status":"Resolved","created":"Jun 18, 11:08 AM","assigned":"David Lee"},
    ]
    return jsonify({"incidents": incidents})

@app.route('/attack-types', methods=['GET'])
def attack_types():
    return jsonify({"attack_types": [
        {"name":"Malware","count":812,"color":"#FF6B6B","pct":31},
        {"name":"Phishing","count":601,"color":"#FF9F43","pct":23},
        {"name":"Brute Force","count":423,"color":"#FFE66D","pct":16},
        {"name":"Exploitation","count":320,"color":"#4ECDC4","pct":12},
        {"name":"DDoS","count":210,"color":"#A29BFE","pct":8},
    ]})

@app.route('/active-threats', methods=['GET'])
def active_threats():
    return jsonify({"threats": [
        {"name":"Qakbot Malware","severity":"Critical","count":23,"delta":"+3"},
        {"name":"C2 Communication","severity":"Critical","count":17,"delta":"+1"},
        {"name":"Lateral Movement","severity":"High","count":12,"delta":"-2"},
        {"name":"Data Exfiltration","severity":"Medium","count":8,"delta":"0"},
        {"name":"Credential Access","severity":"Medium","count":6,"delta":"+1"},
    ]})

@app.route('/alerts-chart', methods=['GET'])
def alerts_chart():
    now = datetime.now()
    hours = []
    for i in range(24):
        t = now - timedelta(hours=23-i)
        base = 80 + (i*15) if i > 12 else 120-(i*8)
        noise = random.randint(-20,40)
        hours.append({"time":t.strftime("%H:00"),"count":max(10,base+noise)})
    return jsonify({"data": hours})

@app.route('/system-health', methods=['GET'])
def system_health():
    return jsonify({"systems": [
        {"name":"SIEM","status":"Operational","uptime":"99.9%"},
        {"name":"EDR","status":"Operational","uptime":"99.8%"},
        {"name":"Firewall","status":"Operational","uptime":"100%"},
        {"name":"Threat Intel","status":"Operational","uptime":"99.7%"},
        {"name":"SOAR","status":"Degraded","uptime":"94.2%"},
        {"name":"Vulnerability","status":"Operational","uptime":"99.5%"},
    ]})

@app.route('/severity-dist', methods=['GET'])
def severity_dist():
    return jsonify({"data": [
        {"label":"Critical","count":120,"pct":4.2,"color":"#FF6B6B"},
        {"label":"High","count":482,"pct":17.0,"color":"#FF9F43"},
        {"label":"Medium","count":1286,"pct":45.3,"color":"#FFE66D"},
        {"label":"Low","count":954,"pct":33.5,"color":"#4ECDC4"},
    ],"total":2842})

@app.route('/history', methods=['GET'])
def history():
    return jsonify({"history": chat_history[-20:]})

@app.route('/galaxy')
def galaxy():
    return send_from_directory(os.path.join(BASE_DIR, 'frontend'), 'galaxy.html')

@app.route('/health')
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002))
    print(f"\nSentinel SOC on http://localhost:{port}")
    app.run(debug=False, host='0.0.0.0', port=port)
