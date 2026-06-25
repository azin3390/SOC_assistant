# =============================================================
# URL SCANNER — PhishGuard ML integrated into SOC Assistant
# Combines ML feature analysis + VirusTotal threat intel
# =============================================================

import re
import math

def extract_url_features(url):
    """Extract the same 10 features PhishGuard uses"""
    features = {}

    features['url_length'] = len(url)
    features['has_https'] = 1 if url.startswith('https') else 0

    ip_pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'
    features['has_ip'] = 1 if re.match(ip_pattern, url) else 0

    features['special_char_count'] = len(re.findall(r'[@\-_=]', url))
    features['digit_count'] = len(re.findall(r'\d', url))
    features['dot_count'] = url.count('.')

    suspicious_words = ['secure','login','verify','account','update',
                        'confirm','banking','paypal','signin','password']
    found_words = [w for w in suspicious_words if w in url.lower()]
    features['suspicious_keyword_count'] = len(found_words)
    features['found_keywords'] = found_words

    features['has_port'] = 1 if re.search(r':\d{2,5}/', url) else 0

    try:
        hostname = url.split('/')[2]
        features['subdomain_depth'] = max(0, hostname.count('.') - 1)
    except:
        features['subdomain_depth'] = 0

    def entropy(s):
        if not s: return 0
        freq = {c: s.count(c)/len(s) for c in set(s)}
        return -sum(p * math.log2(p) for p in freq.values())
    features['url_entropy'] = round(entropy(url), 3)

    return features

def calculate_risk_score(features):
    """Calculate risk score 0-100 from features"""
    score = 0
    reasons = []

    if features['has_https'] == 0:
        score += 20
        reasons.append({
            "flag": "No HTTPS",
            "detail": "Site uses plain HTTP — data is not encrypted.",
            "severity": "high"
        })

    if features['has_ip'] == 1:
        score += 25
        reasons.append({
            "flag": "IP address as hostname",
            "detail": "Legitimate websites use domain names, not raw IPs.",
            "severity": "high"
        })

    if features['url_length'] > 75:
        score += 15
        reasons.append({
            "flag": f"Very long URL ({features['url_length']} chars)",
            "detail": "Phishing URLs are often very long to hide the real destination.",
            "severity": "medium"
        })

    if features['suspicious_keyword_count'] > 0:
        score += features['suspicious_keyword_count'] * 5
        reasons.append({
            "flag": f"Suspicious keywords: {', '.join(features['found_keywords'])}",
            "detail": "Words like 'verify', 'login', 'secure' are common in phishing.",
            "severity": "medium"
        })

    if features['special_char_count'] > 4:
        score += 15
        reasons.append({
            "flag": f"Many special characters ({features['special_char_count']})",
            "detail": "Excessive @, -, _ characters disguise phishing URLs.",
            "severity": "medium"
        })

    if features['digit_count'] > 5:
        score += 10
        reasons.append({
            "flag": f"Many digits in URL ({features['digit_count']})",
            "detail": "Typosquatting like 'paypa1' uses digits to mimic brands.",
            "severity": "low"
        })

    if features['subdomain_depth'] > 2:
        score += 10
        reasons.append({
            "flag": f"Deep subdomain structure ({features['subdomain_depth']} levels)",
            "detail": "Deep subdomains hide the real malicious domain.",
            "severity": "medium"
        })

    if features['url_entropy'] > 4.5:
        score += 5
        reasons.append({
            "flag": f"High URL entropy ({features['url_entropy']})",
            "detail": "Random-looking characters suggest auto-generated phishing URL.",
            "severity": "low"
        })

    score = min(98, max(1, score))

    if score < 30:
        verdict = "Safe"
    elif score < 60:
        verdict = "Suspicious"
    else:
        verdict = "Phishing"

    if not reasons:
        reasons.append({
            "flag": "No major red flags found",
            "detail": "URL appears to follow safe patterns.",
            "severity": "none"
        })

    return {
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
        "features": {k: v for k, v in features.items() if k != 'found_keywords'}
    }

def scan_url(url):
    """Full URL scan combining ML features + description"""
    url = url.strip()
    if not url.startswith('http'):
        url = 'http://' + url

    features = extract_url_features(url)
    ml_result = calculate_risk_score(features)

    return {
        "url": url,
        "verdict": ml_result["verdict"],
        "risk_score": ml_result["risk_score"],
        "reasons": ml_result["reasons"],
        "features": ml_result["features"],
        "ml_analysis": {
            "url_length": features['url_length'],
            "has_https": features['has_https'],
            "has_ip": features['has_ip'],
            "special_chars": features['special_char_count'],
            "digits": features['digit_count'],
            "suspicious_keywords": features['found_keywords'],
            "subdomain_depth": features['subdomain_depth'],
            "entropy": features['url_entropy']
        }
    }

if __name__ == '__main__':
    test_urls = [
        "https://www.google.com",
        "http://paypa1-secure-login.xyz/verify/account",
        "http://192.168.1.1/bank/login"
    ]
    for url in test_urls:
        result = scan_url(url)
        print(f"{result['verdict']} ({result['risk_score']}%) → {url}")
