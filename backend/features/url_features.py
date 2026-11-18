# url_features.py — Lexical URL Feature Extractor
# Extracts 15 string-based features from a URL — no network calls

import re

def extract_url_features(url):
    url = str(url)
    hostname = re.sub(r'https?://', '', url).split('/')[0]

    return {
        'url_length':        len(url),
        'hostname_length':   len(hostname),
        'num_dots':          url.count('.'),
        'num_hyphens':       url.count('-'),
        'num_underscores':   url.count('_'),
        'num_slashes':       url.count('/'),
        'num_digits':        sum(c.isdigit() for c in url),
        'num_special_chars': sum(c in '@?=&%#' for c in url),
        'num_subdomains':    len(hostname.split('.')) - 2,
        'has_ip':            1 if re.search(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
        'has_https':         1 if url.startswith('https') else 0,
        'has_login':         1 if 'login' in url.lower() else 0,
        'has_verify':        1 if 'verify' in url.lower() else 0,
        'has_secure':        1 if 'secure' in url.lower() else 0,
        'has_account':       1 if 'account' in url.lower() else 0,
    }