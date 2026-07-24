"""
Fast, deterministic checks. These run regardless of whether the trained
models are plugged in yet, so the app always gives a sensible answer even
before Colab models are downloaded and wired up.
"""
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click"}

KNOWN_BRANDS = [
    "google", "paypal", "amazon", "microsoft", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "sbi", "hdfc", "icici",
]

URGENCY_WORDS = [
    "urgent", "verify now", "act now", "suspended", "click here",
    "limited time", "your account will be", "immediately", "winner",
    "claim your", "otp", "password expired", "congratulations",
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
        flags.append("Not using HTTPS")

    tld = host.split(".")[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Uncommon/high-risk domain extension (.{tld})")

    for brand in KNOWN_BRANDS:
        if brand in host and not host.endswith(f"{brand}.com"):
            dist = _levenshtein(host, f"{brand}.com")
            if 0 < dist <= 3:
                flags.append(f"Domain looks like a lookalike of '{brand}'")

    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
        flags.append("URL uses a raw IP address instead of a domain name")

    if host.count("-") >= 3:
        flags.append("Unusually many hyphens in domain (common obfuscation trick)")

    return {"flags": flags, "score_hint": min(90, len(flags) * 20)}


def analyze_text(text: str) -> dict:
    flags = []
    lowered = text.lower()
    for word in URGENCY_WORDS:
        if word in lowered:
            flags.append(f'Contains urgency/pressure language: "{word}"')
    urls_found = re.findall(r"https?://\S+", text)
    if urls_found:
        flags.append("Contains an embedded link")
    return {"flags": flags, "score_hint": min(90, len(flags) * 15), "urls_found": urls_found}
