# url_reasons.py — Rule-based URL explainability
# Returns human-readable reasons why a URL is suspicious

def get_url_reasons(url, features):
    """
    Returns a list of human-readable reasons why a URL is suspicious
    based on its extracted lexical features.
    """
    reasons = []

    if features['url_length'] > 75:
        reasons.append(f"Unusually long URL ({features['url_length']} characters)")

    if features['num_subdomains'] > 2:
        reasons.append(f"Excessive subdomains detected ({features['num_subdomains']} subdomains)")

    if features['has_ip'] == 1:
        reasons.append("URL uses IP address instead of domain name")

    if features['has_login'] == 1:
        reasons.append("URL contains suspicious keyword 'login'")

    if features['has_verify'] == 1:
        reasons.append("URL contains suspicious keyword 'verify'")

    if features['has_secure'] == 1:
        reasons.append("URL contains suspicious keyword 'secure'")

    if features['has_account'] == 1:
        reasons.append("URL contains suspicious keyword 'account'")

    if features['num_dots'] > 4:
        reasons.append(f"Abnormal number of dots in URL ({features['num_dots']} dots)")

    if features['has_https'] == 0:
        reasons.append("URL does not use HTTPS")

    if features['num_special_chars'] > 4:
        reasons.append(f"High number of special characters ({features['num_special_chars']})")

    return reasons[:5]  # return max 5 reasons