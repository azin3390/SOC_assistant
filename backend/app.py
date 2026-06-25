from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from threat_intel import analyze
from rag_engine import RAGEngine
from log_analyzer import analyze_logs
from report_generator import generate_report
from timeline import generate_timeline_html
import os, re
from dotenv import load_dotenv

load_dotenv('/Users/aziniftikhar/soc_assistant/.env')
app = Flask(__name__)
CORS(app)

print("Starting SOC Assistant...")
rag = RAGEngine()
rag.load_knowledge_base('/Users/aziniftikhar/soc_assistant/data/threat_knowledge.txt')
print("SOC Assistant ready!")

chat_history = []

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
    if response["severity"] == "Critical":
        response["recommendations"] = ["🚨 IMMEDIATE: Isolate affected systems","🚨 Block malicious IPs at firewall","🚨 Escalate to senior SOC analyst","📋 Preserve logs for forensics","🔄 Begin incident response"]
    elif response["severity"] == "High":
        response["recommendations"] = ["⚠️ Block suspicious IPs at firewall","🔍 Investigate affected systems","📋 Review logs for lateral movement","🔄 Monitor for more activity"]
    elif response["severity"] == "Medium":
        response["recommendations"] = ["👀 Monitor indicators closely","📋 Add to watchlist","🔍 Investigate source"]
    else:
        response["recommendations"] = ["✅ No immediate action required","📋 Log for future reference","👀 Continue standard monitoring"]
    return response

@app.route('/')
def home():
    return jsonify({"status": "SOC Assistant running"})

@app.route('/dashboard')
def dashboard():
    return send_from_directory('/Users/aziniftikhar/soc_assistant/frontend','index.html')

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({"error": "Send JSON with a message field"}), 400
    query = data['message'].strip()
    rag_context = rag.answer(query)
    indicators = detect_indicators(query)
    threat_results = []
    for itype, ivalue in indicators:
        result = analyze(ivalue)
        if 'error' not in result: threat_results.append(result)
    response = generate_soc_response(query, rag_context, threat_results)
    chat_history.append({"query":query,"severity":response["severity"]})
    print(f"[SOC] {query[:50]} | Severity: {response['severity']}")
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

@app.route('/generate-report', methods=['POST'])
def generate_report_route():
    data = request.get_json()
    if not data: return jsonify({"error": "No data"}), 400
    output_path = '/Users/aziniftikhar/soc_assistant/threat_report.pdf'
    generate_report(data, output_path)
    return send_file(output_path, as_attachment=True, download_name='threat_report.pdf')

@app.route('/history', methods=['GET'])
def history():
    return jsonify({"history": chat_history[-20:]})

if __name__ == '__main__':
    print("\nSOC Assistant API on http://localhost:5002")
    app.run(debug=True, port=5002)
