# app.py — Flask Backend for Phishing Detection
# Loads models once at startup, exposes /predict endpoint

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd
import time
import os
import re

from features.url_features import extract_url_features
from explain.text_explain import get_top_phishing_words
from explain.url_reasons import get_url_reasons

app = Flask(__name__)
CORS(app)

# ── Load Models Once at Startup ───────────────────
print("Loading models...")
BASE_DIR   = os.path.dirname(__file__)
tfidf      = joblib.load(os.path.join(BASE_DIR, 'models/tfidf.pkl'))
text_model = joblib.load(os.path.join(BASE_DIR, 'models/text_model.pkl'))
url_model  = joblib.load(os.path.join(BASE_DIR, 'models/url_model.pkl'))
print("✅ All models loaded!")

# ── In-memory cache ───────────────────────────────
cache = {}

# ── Trusted Domains & Keywords ────────────────────
TRUSTED_DOMAINS = [
    'google.com', 'gmail.com', 'microsoft.com', 'apple.com',
    'github.com', 'linkedin.com', 'twitter.com', 'facebook.com',
    'youtube.com', 'wikipedia.org', 'amazon.com', 'outlook.com',
    'instagram.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    'citibank.com', 'paypal.com', 'dropbox.com', 'slack.com',
    'zoom.us', 'notion.so', 'spotify.com', 'netflix.com'
]

SUSPICIOUS_KEYWORDS = [
    'verify', 'login', 'secure', 'account', 'update',
    'confirm', 'password', 'signin', 'banking', 'suspend'
]

def is_trusted(url):
    url_lower = url.lower()

    # Check explicit whitelist first
    for domain in TRUSTED_DOMAINS:
        if domain in url_lower:
            return True

    try:
        hostname = re.sub(r'https?://', '', url_lower).split('/')[0]
        parts = hostname.split('.')
        actual_tld = parts[-1]

        # Rule 1 — actual TLD must be .gov or .edu
        # harvard.edu ✅  harvard-edu-login.com ❌
        if actual_tld in ['gov', 'edu']:
            return True

        # Rule 2 — https + short hostname + no suspicious keywords + few subdomains
        has_suspicious = any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)
        is_short       = len(hostname) < 30
        is_https       = url_lower.startswith('https')
        few_subdomains = len(parts) <= 3

        if is_https and is_short and not has_suspicious and few_subdomains:
            return True

    except:
        pass

    return False

# ── Helper: Risk Level ────────────────────────────
def get_risk_level(score):
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"

# ── /predict Endpoint ─────────────────────────────
@app.route('/predict', methods=['POST'])
def predict():
    start_time = time.time()
    data = request.get_json()

    # Extract inputs
    subject     = data.get('subject', '')
    sender      = data.get('from', '')
    body        = data.get('body', '')
    urls        = data.get('urls', [])
    fingerprint = data.get('fingerprint', '')

    # Check cache
    if fingerprint and fingerprint in cache:
        cached = cache[fingerprint]
        cached['cached'] = True
        return jsonify(cached)

    # Build full text
    full_text = f"{subject} {sender} {body}".strip().lower()

    # ── Text Model Inference ──────────────────────
    tfidf_vec = tfidf.transform([full_text])
    p_text    = float(text_model.predict_proba(tfidf_vec)[0][1])

    # ── URL Model Inference ───────────────────────
    p_url_max   = 0.0
    top_url     = None
    url_reasons = []

    for url in urls[:10]:
        if is_trusted(url):
            continue
        features   = extract_url_features(url)
        feat_df    = pd.DataFrame([features])
        p_url      = float(url_model.predict_proba(feat_df)[0][1])
        if p_url > p_url_max:
            p_url_max   = p_url
            url_reasons = get_url_reasons(url, features)
            top_url     = {'url': url[:100], 'score': round(p_url * 100)}

    # ── Fusion ────────────────────────────────────
    risk = 0.6 * p_text + 0.4 * p_url_max
    risk_score = round(risk * 100)

    # ── Explainability ────────────────────────────
    top_words    = get_top_phishing_words(full_text, tfidf, text_model, top_n=3)
    text_reasons = [f"Suspicious word detected: '{w}'" for w in top_words] if p_text > 0.5 else []

    all_reasons = text_reasons + url_reasons
    if not all_reasons:
        all_reasons = ["No strong phishing indicators detected"]

    # ── Build Response ────────────────────────────
    latency_ms = round((time.time() - start_time) * 1000, 2)

    response = {
        'risk_score':   risk_score,
        'risk_level':   get_risk_level(risk_score),
        'text_prob':    round(p_text * 100, 2),
        'url_max_prob': round(p_url_max * 100, 2),
        'top_reasons':  all_reasons[:5],
        'top_url':      top_url,
        'latency_ms':   latency_ms,
        'cached':       False
    }

    # Cache result
    if fingerprint:
        cache[fingerprint] = response

    return jsonify(response)

# ── Health Check ──────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'models_loaded': True})

if __name__ == '__main__':
    app.run(debug=True, port=5000)