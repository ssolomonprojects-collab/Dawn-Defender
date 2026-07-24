"""
Fast, deterministic checks for URLs, SMS, and Email text.
Provides heuristic red flags and initial score hints.
"""
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
    "site", "info", "online", "live", "tech", "club", "store", "vip", "cc", "icu"
}

KNOWN_BRANDS = [
    "google", "paypal", "amazon", "microsoft", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "sbi", "hdfc", "icici",
    "axis", "kotak", "paytm", "phonepe", "flipkart", "irctc", "uidai", "zerodha"
]

SCAM_KEYWORDS = [
    "urgent", "verify now", "act now", "suspended", "click here",
    "limited time", "your account will be", "immediately", "winner",
    "claim your", "otp", "password expired", "congratulations",
    "blocked", "unauthorized", "locked", "deactivated", "expire",
    "security alert", "action required", "unusual activity", "refund",
    "lottery", "prize", "won", "free", "cashback", "reward", "lakh",
    "kyc", "aadhaar", "pan card", "income tax", "epfo", "customs",
    "delivery failed", "package held", "wire transfer", "payment failed",
    "dispute", "penalty", "legal action", "disconnection", "trai",
    "scam", "phishing", "fake", "malware", "virus", "hacked", "compromised"
]


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def analyze_url(url: str) -> dict:
    flags = []
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.netloc.lower().split(":")[0]
    except Exception:
        return {"flags": ["Could not parse this as a valid URL"], "score_hint": 50}

    if not url.startswith("https://"):
        flags.append("Not using HTTPS (unencrypted connection)")

    tld = host.split(".")[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Uncommon/high-risk domain extension (.{tld})")

    for brand in KNOWN_BRANDS:
        if brand in host and not host.endswith(f"{brand}.com") and not host.endswith(f"{brand}.in") and not host.endswith(f"{brand}.co.in"):
            dist = _levenshtein(host, f"{brand}.com")
            if 0 < dist <= 3 or "-" in host:
                flags.append(f"Domain looks like a lookalike/spoof of '{brand}'")

    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
        flags.append("URL uses a raw IP address instead of a domain name")

    if host.count("-") >= 2:
        flags.append("Unusually many hyphens in domain (common obfuscation trick)")

    if re.search(r"bit\.ly|tinyurl|t\.ly|is\.gd|cutt\.ly", host):
        flags.append("Uses URL shortener service to hide final destination")

    return {"flags": flags, "score_hint": min(95, len(flags) * 25)}


def analyze_text(text: str) -> dict:
    flags = []
    lowered = text.lower()

    matched_keywords = []
    for word in SCAM_KEYWORDS:
        if word in lowered:
            matched_keywords.append(word)

    if matched_keywords:
        sample_words = ", ".join([f'"{w}"' for w in matched_keywords[:3]])
        flags.append(f"Contains suspicious/urgency keywords: {sample_words}")

    urls_found = re.findall(r"https?://\S+|www\.\S+|\S+\.(?:xyz|top|site|click|info|work|gq|tk)\S*", text)
    if urls_found:
        flags.append(f"Contains suspicious embedded link: {urls_found[0][:40]}")

    if re.search(r"\b(?:otp|pin|password|cvv|account number|aadhaar|pan)\b", lowered):
        flags.append("Requests sensitive credentials or personal financial information")

    if re.search(r"rs\.?\s*\d+|\$\d+|\b\d+\s*lakh\b|\b\d+\s*crore\b", lowered):
        flags.append("Mentions monetary values or financial transactions")

    score_hint = min(95, len(flags) * 25 + len(matched_keywords) * 10)
    return {"flags": flags, "score_hint": score_hint, "urls_found": urls_found}
