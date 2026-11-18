// content.js — PhishGuard Gmail Content Script
// Detects opened emails, extracts content, sends to Flask backend

const BACKEND_URL = 'http://127.0.0.1:5000/predict';
const DEBOUNCE_MS = 800;
const RATE_LIMIT_MS = 1000;

// In-memory cache and rate limiting
const scanCache = new Map();
let lastScanTime = 0;
let debounceTimer = null;

// ── Fingerprint ───────────────────────────────────
function makeFingerprint(subject, sender, snippet, urls) {
  const str = `${subject}|${sender}|${snippet}|${urls.join(',')}`;
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return String(hash);
}

// ── Extract Email Data ────────────────────────────
function extractEmailData() {
  try {
    // Subject
    const subjectEl = document.querySelector('h2.hP');
    const subject = subjectEl ? subjectEl.innerText.trim() : '';

    // Sender
    const senderEl = document.querySelector('span.gD');
    const sender = senderEl ? senderEl.getAttribute('email') || senderEl.innerText : '';

    // Body
    const bodyEl = document.querySelector('div.a3s');
    const body = bodyEl ? bodyEl.innerText.trim().slice(0, 3000) : '';

    // URLs
    const anchors = bodyEl ? bodyEl.querySelectorAll('a[href]') : [];
    const urls = [...anchors]
      .map(a => a.href)
      .filter(h => h.startsWith('http'))
      .slice(0, 10);

    if (!subject && !body) return null;

    return { subject, sender, body, urls };
  } catch (e) {
    return null;
  }
}

// ── Inject Badge ──────────────────────────────────
function injectBadge(data) {
  // Remove existing badge
  const existing = document.getElementById('phishguard-badge');
  if (existing) existing.remove();

  const badge = document.createElement('div');
  badge.id = 'phishguard-badge';

  if (data === 'loading') {
    badge.className = 'loading';
    badge.innerHTML = `
      <div class="pg-header">
        <div class="pg-title">🛡️ PhishGuard — Scanning...</div>
      </div>
    `;
  } else {
    const level = data.risk_level.toLowerCase();
    const emoji = level === 'high' ? '🚨' : level === 'medium' ? '⚠️' : '✅';
    badge.className = level;

    const reasonsHTML = data.top_reasons
      .map(r => `<li>${r}</li>`)
      .join('');

    const urlHTML = data.top_url
      ? `<div class="pg-url">🔗 Riskiest URL (${data.top_url.score}/100): ${data.top_url.url}</div>`
      : '';

    badge.innerHTML = `
      <div class="pg-header">
        <div class="pg-title">${emoji} PhishGuard — ${data.risk_level} RISK</div>
        <div class="pg-score">${data.risk_score}/100</div>
      </div>
      <ul class="pg-reasons">${reasonsHTML}</ul>
      ${urlHTML}
      <div class="pg-latency">⚡ ${data.latency_ms}ms ${data.cached ? '(cached)' : ''}</div>
    `;
  }

  // Insert before email body
  const insertTarget = document.querySelector('div.a3s') ||
                       document.querySelector('div.AO') ||
                       document.querySelector('div[role="main"]');

  if (insertTarget && insertTarget.parentNode) {
    insertTarget.parentNode.insertBefore(badge, insertTarget);
  }
}

// ── Scan Email ────────────────────────────────────
async function scanEmail() {
  const now = Date.now();
  if (now - lastScanTime < RATE_LIMIT_MS) return;

  const emailData = extractEmailData();
  if (!emailData) return;

  const { subject, sender, body, urls } = emailData;
  const snippet = body.slice(0, 100);
  const fingerprint = makeFingerprint(subject, sender, snippet, urls);

  // Check cache
  if (scanCache.has(fingerprint)) {
    injectBadge(scanCache.get(fingerprint));
    return;
  }

  lastScanTime = now;
  injectBadge('loading');

  try {
    const startTime = Date.now();
    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject, from: sender, body, urls, fingerprint })
    });

    const result = await response.json();
    scanCache.set(fingerprint, result);
    injectBadge(result);

  } catch (err) {
    const existing = document.getElementById('phishguard-badge');
    if (existing) existing.remove();
  }
}

// ── Debounced Scan ────────────────────────────────
function debouncedScan() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(scanEmail, DEBOUNCE_MS);
}

// ── MutationObserver ──────────────────────────────
const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node.nodeType === 1) {
        // Check if email reading pane opened
        if (node.querySelector && (
          node.querySelector('div.a3s') ||
          node.querySelector('h2.hP')
        )) {
          debouncedScan();
          return;
        }
      }
    }
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

// Initial scan
setTimeout(scanEmail, 1500);