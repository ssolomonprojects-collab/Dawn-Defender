"""
Fast, deterministic checks for URLs, SMS, and Email text.
Provides heuristic red flags and initial score hints.
"""
import re
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
    "site", "info", "online", "live", "tech", "club", "store", "vip", "cc", "icu"
}

KNOWN_BRANDS = [
    "google", "paypal", "amazon", "microsoft", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "sbi", "hdfc", "icici",
    "axis", "kotak", "paytm", "phonepe", "flipkart", "irctc", "uidai", "zerodha", "chase"
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
    confidence = 0.0

    raw_url = url.strip()
    if not raw_url:
        return {"flags": ["Empty URL provided"], "score_hint": 0}

    full_url = raw_url if "://" in raw_url else f"https://{raw_url}"

    try:
        ext = tldextract.extract(full_url)
        registered_domain = ext.registered_domain.lower()
        tld = ext.suffix.lower()
    except Exception:
        return {"flags": ["Could not parse URL structure"], "score_hint": 50}

    parsed = urlparse(full_url)
    host = parsed.netloc.lower().split(":")[0]

    # 1. Raw IP address check
    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        flags.append("URL uses a raw IP address instead of a domain name")
        confidence += 0.90

    # 2. High-risk TLD check
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"High-risk/suspicious domain extension (.{tld})")
        confidence += 0.40

    # 3. URL Shortener check
    if registered_domain in {"bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "is.gd", "goo.gl"}:
        flags.append("Uses URL shortener to conceal target destination")
        confidence += 0.35

    # 4. Brand lookalike / typosquatting check
    for brand in KNOWN_BRANDS:
        if brand in host:
            official_domains = {
                f"{brand}.com", f"{brand}.in", f"{brand}.co.in", f"{brand}.org",
                f"{brand}.net", f"{brand}.gov.in", f"{brand}.ac.in", f"{brand}.us", f"{brand}.io"
            }
            if registered_domain not in official_domains:
                flags.append(f"Domain looks like a lookalike or spoof of '{brand}'")
                confidence += 0.50
                break

    # 5. Multi-hyphen obfuscation & subdomains
    if host.count("-") >= 2 and registered_domain not in {"scikit-learn.org", "stack-overflow.com"}:
        flags.append("Unusually many hyphens in domain (common obfuscation trick)")
        confidence += 0.25

    if host.count(".") >= 4:
        flags.append("Excessive subdomains used in hostname")
        confidence += 0.20

    # 6. Unencrypted http check (only if explicitly typed by user)
    if raw_url.startswith("http://"):
        flags.append("Unencrypted connection (HTTP)")
        confidence += 0.10

    score_hint = int(round(max(0.0, min(1.0, confidence)) * 100))
    return {"flags": flags, "score_hint": score_hint}


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
