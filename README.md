# 🛡️ PhishGuard — Real-Time Phishing Detection Browser Extension

> A Chrome extension that automatically scans Gmail emails using Hybrid Lightweight Machine Learning to detect phishing attacks in real-time, with explainable risk scores and reasons.

---

## 📌 Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [The Problem We Are Solving](#2-the-problem-we-are-solving)
3. [How The System Works](#3-how-the-system-works)
4. [System Architecture](#4-system-architecture)
5. [Complete File Structure](#5-complete-file-structure)
6. [Datasets Used](#6-datasets-used)
7. [Machine Learning Models](#7-machine-learning-models)
8. [Flask Backend Explained](#8-flask-backend-explained)
9. [Chrome Extension Explained](#9-chrome-extension-explained)
10. [Performance Results](#10-performance-results)
11. [Privacy & Security Design](#11-privacy--security-design)
12. [How To Run The Project](#12-how-to-run-the-project)
13. [Design Decisions (Q&A)](#13-design-decisions-qa)
14. [Limitations & Future Work](#14-limitations--future-work)
15. [Summary](#15-summary)

---

## 1. What Is This Project?

PhishGuard is a Chrome browser extension that automatically scans Gmail emails in real-time to detect phishing attacks. When you open an email, it:

- Analyzes the **email text** using a TF-IDF + Logistic Regression model
- Analyzes every **URL** in the email using a Random Forest model
- Combines both scores into a **risk score from 0 to 100**
- Shows a **colored badge** with 3–5 clear reasons why the email might be dangerous
- Does all of this in about **118ms** on a typical email (p95: 187ms), well under the 250ms target

Think of it as a smart security guard sitting inside your Gmail inbox, silently reading every email and warning you before you click on anything dangerous.

---

## 2. The Problem We Are Solving

Phishing emails are one of the most common cyberattacks in the world. Attackers send fake emails pretending to be from banks, PayPal, Google, or universities to trick users into giving away passwords or clicking malicious links.

Traditional spam filters catch obvious spam but miss sophisticated phishing emails that look legitimate. Our system adds an extra intelligent layer of protection directly inside Gmail — using machine learning that was trained on over **80,000 real phishing and legitimate emails**.

---

## 3. How The System Works

The system has three main parts working together:

### Part 1 — Chrome Extension (What the user sees)
- Lives inside your Chrome browser
- Watches Gmail for when you open an email
- Extracts the subject, sender, body text, and all links
- Sends this data to our local backend server
- Displays a colored badge showing the risk level

### Part 2 — Flask Backend (The brain)
- A lightweight Python server running on your local machine
- Receives email data from the extension
- Runs two machine learning models on the data
- Combines the results into a final risk score
- Sends the score and reasons back to the extension

### Part 3 — Machine Learning Models (The intelligence)
- **Model 1:** Reads the email text and decides if it sounds like phishing
- **Model 2:** Analyzes each URL for suspicious structural patterns
- Both scores are combined using a weighted fusion formula:

```
Risk Score = 0.6 × Email Text Score + 0.4 × URL Score
```

Email text gets 60% weight because it achieved 98% accuracy vs 88% for URLs.

---

## 4. System Architecture

```
[Gmail Browser]
      |
      v
[content.js] — MutationObserver detects email opened
      |         Debounce 800ms → extract subject + sender + body + URLs
      |         Generate fingerprint → check local cache
      |
      v  (HTTP POST → http://127.0.0.1:5000/predict)
      |
[Flask Backend — app.py]
      |
      |——> tfidf.pkl + text_model.pkl ——> p_text  (0.0 to 1.0)
      |——> url_features.py + url_model.pkl ——> p_url (0.0 to 1.0)
      |——> fusion: risk = 0.6 × p_text + 0.4 × p_url_max
      |——> text_explain.py ——> top suspicious words
      |——> url_reasons.py  ——> rule-based URL reasons
      |
      v  (JSON response)
      |
[content.js] — injects badge into Gmail reading pane
      |
      v
[User sees badge] 🟢 LOW / 🟡 MEDIUM / 🔴 HIGH
```

---

## 5. Complete File Structure

```
PhishGuard/
│
├── training/
│   ├── phishing_email.csv        ← Email dataset (download, not in repo)
│   ├── malicious_phish.csv       ← URL dataset (download, not in repo)
│   ├── eda_email.ipynb           ← Exploratory Data Analysis — emails
│   ├── eda_url.ipynb             ← Exploratory Data Analysis — URLs
│   ├── train_email.ipynb         ← Email classifier training notebook
│   ├── train_url.ipynb           ← URL classifier training notebook
│   └── eval_models.py            ← Evaluates both models, latency, cache simulation
│
├── backend/
│   ├── app.py                    ← Flask server (main backend)
│   ├── models/
│   │   ├── tfidf.pkl             ← Saved TF-IDF vectorizer
│   │   ├── text_model.pkl        ← Saved Logistic Regression (email)
│   │   └── url_model.pkl         ← Saved Random Forest (URL)
│   ├── features/
│   │   └── url_features.py       ← URL feature extractor (15 features)
│   └── explain/
│       ├── text_explain.py       ← Top TF-IDF word explainer
│       └── url_reasons.py        ← Rule-based URL reason generator
│
├── extension/
│   ├── manifest.json             ← Chrome extension configuration
│   ├── content.js                ← Gmail scanner & UI badge injector
│   ├── ui.css                    ← Badge styling (green/yellow/red)
│   └── icon.png                  ← Extension icon
│
├── requirements.txt
└── README.md                     ← This file
```

---

## 6. Datasets Used

| Dataset | Source | Size | Purpose |
|---------|--------|------|---------|
| `phishing_email.csv` | Kaggle — naserabdullahalam | 82,486 emails | Train email text classifier |
| `malicious_phish.csv` | Kaggle — sid321axn | 651,191 URLs | Train URL classifier |

> The datasets are **not included** in this repo (the email dataset is over GitHub's 100 MB file limit). The trained models in `backend/models/` **are** included, so you only need the datasets if you want to re-run the notebooks. Download them from Kaggle ([Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset), [Malicious URLs Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset)) and place both CSV files in `training/`.

### Email Dataset Details
- Combines multiple well-known sources: **Enron** (legitimate), **CEAS 2008**, **Nazario**, **Nigerian Fraud**, **SpamAssassin**
- Nearly balanced: 52% phishing, 48% ham
- Zero missing values
- Average email length: Ham = 1,536 chars, Phishing = 1,060 chars

### URL Dataset Details
- Four classes: benign (65%), defacement (15%), phishing (14%), malware (5%)
- For binary classification: phishing + defacement + malware → **malicious (1)**, benign → **benign (0)**
- Only 1.55% duplicate URLs — very clean dataset
- HTTPS usage is low across all types — HTTPS alone is NOT a reliable safety indicator

---

## 7. Machine Learning Models

### 7.1 Email Text Classifier — TF-IDF + Logistic Regression

#### What is TF-IDF?
**TF-IDF = Term Frequency — Inverse Document Frequency**

It converts raw email text into numbers:
- **TF (Term Frequency):** How often a word appears in ONE email
- **IDF (Inverse Document Frequency):** How rare that word is across ALL emails
- Words unique to phishing emails (like `verify account`) get **high scores**
- Common words like `the`, `and`, `is` get **low scores** and are ignored

We use `ngram_range=(1,2)` — captures both single words (`verify`) and two-word phrases (`verify account`, `click here`). Bigrams capture context that single words miss.

#### Why Logistic Regression?
- **Speed:** Predicts in under 1ms — perfect for real-time detection
- **Explainability:** Coefficients directly show which words caused the prediction
- **Performance:** 98.48% accuracy — deep learning is unnecessary
- **Lightweight:** Model file is tiny, loads instantly at server startup

#### Email Model Results

| Metric | Score |
|--------|-------|
| Accuracy | **98.48%** |
| Precision | **98.55%** |
| Recall | **98.53%** |
| F1 Score | **98.54%** |
| ROC-AUC | **99.85%** |
| p95 Inference Latency | **< 1ms** |

---

### 7.2 URL Classifier — Lexical Features + Random Forest

#### What are Lexical Features?
Instead of visiting the URL (network calls are forbidden), we extract **15 string-based features** from the URL structure:

| Feature | Why It Matters |
|---------|----------------|
| `url_length` | Malicious URLs tend to be longer |
| `hostname_length` | Long hostnames suggest fake domains |
| `num_dots` | Many dots suggest fake subdomains |
| `num_subdomains` | Attackers use many subdomains to hide |
| `has_ip` | Using IP instead of domain name is suspicious |
| `has_https` | Lack of HTTPS is a warning sign |
| `has_login` | login keyword is a phishing signal |
| `has_verify` | verify keyword is a phishing signal |
| `has_secure` | secure keyword used to trick users |
| `has_account` | account keyword common in phishing |
| `num_hyphens` | Hyphens used to mimic real domains (paypal-verify.com) |
| `num_slashes` | Deep paths common in malicious URLs |
| `num_digits` | Many digits suggest auto-generated domains |
| `num_special_chars` | Many special chars suggest obfuscation |
| `num_underscores` | Underscores used to hide keywords |

#### LR vs Random Forest Comparison

| Metric | Logistic Regression | Random Forest | Improvement |
|--------|--------------------|--------------:|-------------|
| Accuracy | 78.57% | **88.40%** | +10% |
| Precision | 67.11% | **79.54%** | +12% |
| Recall | 73.45% | **89.04%** | +16% |
| F1 Score | 70.13% | **84.03%** | +14% |
| ROC-AUC | 0.8182 | **0.9547** | +14% |
| p95 Latency | 1ms | **20ms** | Both pass 250ms ✅ |

Random Forest was selected because URL classification involves **non-linear relationships** between features. For example, many dots AND many subdomains AND has_login combined is far more suspicious than any single feature alone. Random Forest captures these interactions naturally.

#### Why NOT 99% Accuracy Models from Kaggle?

Some Kaggle notebooks report 99% accuracy on this dataset. They achieve this by:
- Using **network-based features** (WHOIS lookups, DNS queries) — our spec forbids network calls
- Using **deep learning** on raw URL characters — too slow for real-time, banned by constraints
- **Data leakage** — accidentally training and testing on overlapping data
- Using **external domain reputation APIs** — requires internet, not privacy-preserving

Our system achieves **88% using only 15 lexical string features** — a deliberate and justified engineering tradeoff for real-time, privacy-preserving detection.

---

## 8. Flask Backend Explained

The Flask backend (`backend/app.py`) is a lightweight Python web server that:

- Loads all three model files **once at startup** (not on every request)
- Exposes a `POST /predict` endpoint that the Chrome extension calls
- Maintains an **in-memory cache** keyed by email fingerprint
- Returns JSON with risk score, risk level, reasons, and latency

### The Fingerprint System
Every email gets a unique fingerprint hash generated from:
`subject + sender + first 100 chars of body + list of URLs`

If the same email is scanned again → cached result returned instantly, no models run. Across **200 real Gmail email opens**, debouncing, fingerprint caching and rate limiting together cut redundant scans by **74%**. (`training/eval_models.py` also includes an offline cache simulation.)

### The Trusted Domain System

To avoid false positives on legitimate company emails, we use:
1. **Explicit whitelist:** google.com, paypal.com, chase.com, microsoft.com, etc.
2. **Dynamic rules:**
   - Any `.gov` or `.edu` actual TLD → automatically trusted
   - Short HTTPS URL + no suspicious keywords + ≤3 subdomains → trusted

> ⚠️ Note: We check the **actual TLD**, not just if the word appears in the URL. `harvard.edu` ✅ is trusted but `harvard-edu-login.phishing.com` ❌ is not.

### API Response Format

```json
{
  "risk_score": 84,
  "risk_level": "HIGH",
  "text_prob": 99.77,
  "url_max_prob": 59.1,
  "top_reasons": [
    "Suspicious word detected: 'verify'",
    "Suspicious word detected: 'account'",
    "URL contains suspicious keyword 'login'",
    "URL does not use HTTPS",
    "Excessive subdomains detected"
  ],
  "top_url": {
    "url": "http://paypal-verify.login-account.com/secure/update",
    "score": 59
  },
  "latency_ms": 39.67,
  "cached": false
}
```

---

## 9. Chrome Extension Explained

### `manifest.json`
Tells Chrome what the extension is allowed to do. We request **minimal permissions**:
- Only access to `mail.google.com` — nowhere else
- Only access to `127.0.0.1:5000` — our local Flask server
- No persistent storage permissions
- No access to credentials or account data

### `content.js`
The main script that runs inside Gmail:
- Uses **MutationObserver** to detect when an email is opened (Gmail is a SPA — no page reloads)
- **Debounces** calls by 800ms to avoid scanning on every minor DOM change
- Extracts subject, sender, body text, and all anchor URLs from the reading pane
- Generates a fingerprint → checks local cache → rate-limits to 1 call/second
- Injects the colored badge HTML directly above the email body

### `ui.css`
Styles the badge to match Gmail's design:
- 🟢 **Green badge** — LOW risk (score 0–39)
- 🟡 **Yellow badge** — MEDIUM risk (score 40–69)
- 🔴 **Red badge** — HIGH risk (score 70–100)

---

## 10. Performance Results

| Metric | Target | Achieved | Pass? |
|--------|--------|----------|-------|
| Email Model Accuracy | > 90% | **98.48%** | ✅ |
| URL Model Accuracy | > 80% | **88.40%** | ✅ |
| Email ROC-AUC | > 0.95 | **0.9985** | ✅ |
| URL ROC-AUC | > 0.85 | **0.9547** | ✅ |
| p50 End-to-End Latency | — | **118ms** | ✅ |
| p95 End-to-End Latency | < 250ms | **187ms** | ✅ |
| Redundant Scans Avoided | > 70% | **74%** | ✅ |
| Persistent Storage Used | None | **None** | ✅ |
| Network Calls from URL Model | None | **None** | ✅ |

---

## 11. Privacy & Security Design

- ✅ No raw email text is ever logged or stored on disk
- ✅ All processing happens **locally** on the user's machine
- ✅ The extension only has permission to run on `mail.google.com`
- ✅ No credentials, passwords, or account data are ever accessed
- ✅ The backend runs on `localhost` — no data ever leaves the user's computer
- ✅ In-memory cache is cleared when Flask server restarts
- ✅ No third-party APIs called — completely self-contained

---

## 12. How To Run The Project

### Prerequisites
- Python 3.10+ (Anaconda or plain Python both work)
- Google Chrome browser
- Gmail account

### Step 1 — Set Up the Environment
```bash
git clone https://github.com/meesalagit/PhishGuard.git
cd PhishGuard

# Option A: Anaconda
conda create -n phish python=3.10 -y
conda activate phish

# Option B: plain Python
# python3 -m venv .venv && source .venv/bin/activate

pip install -r requirements.txt
cd backend
```

### Step 2 — Start Flask Server
```bash
python app.py
```
You should see:
```
Loading models...
✅ All models loaded!
* Running on http://127.0.0.1:5000
```

### Step 3 — Load Chrome Extension
1. Open Chrome and go to `chrome://extensions`
2. Turn on **Developer Mode** (top right toggle)
3. Click **Load Unpacked**
4. Select the `PhishGuard/extension` folder
5. PhishGuard extension appears with blue icon ✅

### Step 4 — Test It
1. Open `gmail.com` in Chrome
2. Click any email to open it
3. PhishGuard badge appears automatically above the email body
4. 🟢 Green = safe, 🟡 Yellow = medium risk, 🔴 Red = high risk

### Step 5 — Test With curl (Optional)
```bash
# Test phishing email
curl -X POST http://127.0.0.1:5000/predict \
-H "Content-Type: application/json" \
-d '{
  "subject": "Urgent: Verify your account now",
  "from": "security@paypal-verify.com",
  "body": "Your account has been suspended. Click here to verify your login credentials.",
  "urls": ["http://paypal-verify.login-account.com/secure/update"],
  "fingerprint": "test001"
}'

# Test legitimate email
curl -X POST http://127.0.0.1:5000/predict \
-H "Content-Type: application/json" \
-d '{
  "subject": "Team meeting tomorrow at 10am",
  "from": "john@company.com",
  "body": "Hi team, just a reminder about our weekly standup tomorrow morning.",
  "urls": ["https://calendar.google.com/meeting/123"],
  "fingerprint": "test002"
}'
```

---

## 13. Design Decisions (Q&A)

### Q: Why TF-IDF instead of BERT or transformers?
Our spec explicitly requires no deep learning in real-time inference. TF-IDF with Logistic Regression achieves **98.48% accuracy** and predicts in **under 1ms**. Transformers would take 500ms+ per inference, violating our 250ms latency target. The marginal accuracy gain from transformers does not justify the massive latency cost for a real-time browser extension.

### Q: Why is URL accuracy only 88% when Kaggle shows 99%?
Kaggle notebooks achieving 99% use network-based features (WHOIS lookups, DNS queries, domain reputation APIs). Our system uses only **15 lexical string features with zero network calls**. This is a deliberate design constraint for privacy preservation, low latency, and offline operation. 88% from pure string analysis of URL structure alone is genuinely strong performance.

### Q: Why use a hybrid approach instead of just one model?
Neither model alone is sufficient:
- The email text model cannot detect phishing emails with neutral language but malicious links
- The URL model cannot detect phishing emails with no URLs
- Combined, they cover each other's weaknesses
- The weighted fusion (0.6 text + 0.4 URL) reflects their respective accuracy levels

### Q: How does the extension protect user privacy?
All processing is **100% local** — no data ever leaves the user's machine. The backend runs on localhost:5000. The extension only accesses mail.google.com. No email content is ever logged, stored, or sent to external servers. The in-memory cache clears on server restart.

### Q: What is the MutationObserver and why use it?
Gmail is a Single Page Application — it does not reload the page when you click an email. MutationObserver watches the DOM for when Gmail dynamically adds new email content to the page. This lets us detect email opens without polling or page reloads. The 800ms debounce prevents scanning on every minor DOM change.

### Q: How does fingerprinting and caching work?
Each email gets a unique hash from: `subject + sender + first 100 chars + URL list`. Before calling the backend, the extension checks its local memory cache. If the same email has been scanned before, the cached result returns instantly — no backend call made. Combined with debouncing and rate limiting, this cut redundant scans by **74%** across 200 real Gmail opens.

### Q: Why Random Forest for URLs but Logistic Regression for email text?
URL classification involves **non-linear feature interactions** — many dots AND many subdomains AND has_login combined is far more suspicious than any single feature. Random Forest captures these interactions naturally and improved accuracy by 10% over LR. For email text, TF-IDF with LR is the gold standard — the linear relationship between word weights and phishing probability is strong, direct, and highly interpretable.

### Q: What is the fusion formula and why those weights?
`risk = 0.6 × p_text + 0.4 × p_url_max`

The email text model gets 60% weight because it achieves higher accuracy (98% vs 88%). The URL model gets 40% weight. If no URLs are present, the URL score defaults to 0 and the text model carries the entire prediction. This ensures the system works even for text-only phishing emails.

### Q: How is the system explainable without SHAP?
For the email text model, we use Logistic Regression coefficients directly. Features (TF-IDF tokens) with the highest positive coefficients in the context of the current email are the top contributing words. This is similar in spirit to SHAP for linear models (a token's contribution is its coefficient times its TF-IDF value) but runs in microseconds. For URLs, we use rule-based reasons from extracted features — no post-hoc explanation needed.

---

## 14. Limitations & Future Work

### Current Limitations
- The URL model uses no network calls — a phishing site with a normal-looking URL will not be flagged
- The trusted domain whitelist is manually curated — doesn't cover every legitimate company
- Flask server must be running locally — not user-friendly for non-technical users
- Extension is not published to Chrome Web Store — requires manual installation
- Adversarial attacks (emails crafted to fool the model) are not evaluated

### Future Work
- Deploy Flask backend to cloud (Railway, Render, AWS) to remove local server requirement
- Submit to Chrome Web Store for public distribution
- Add domain age checking via WHOIS API as an optional feature
- Extend to Outlook and other webmail clients
- Implement active learning to improve models with user feedback
- Add adversarial robustness evaluation

---

## 15. Summary

PhishGuard is a complete end-to-end real-time phishing detection system combining:

| Component | Technology | Result |
|-----------|-----------|--------|
| Email classifier | TF-IDF + Logistic Regression | 98.48% accuracy |
| URL classifier | 15 lexical features + Random Forest | 88.40% accuracy |
| Backend | Flask + in-memory cache | ~25-50ms inference |
| Extension | Chrome MV3 + MutationObserver | 118ms p50 / 187ms p95 end-to-end |
| Privacy | 100% local processing | Zero data leakage |

The system meets all project requirements: no deep learning in real-time, explainable predictions, p95 latency under 250ms, no persistent storage of email content, and minimal browser permissions.

---

*Built with Python 3.10, scikit-learn, Flask, and Chrome Extension Manifest V3*
