"""
Fast, deterministic checks for URLs, SMS, and Email text / Email addresses.
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

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "github.com", "wikipedia.org", "amazon.com", "amazon.in",
    "microsoft.com", "apple.com", "instagram.com", "facebook.com", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "netflix.com", "whatsapp.com", "sathyabama.ac.in",
    "stackoverflow.com", "python.org", "zoom.us", "yahoo.com", "bing.com", "cloudflare.com",
    "medium.com", "quora.com", "coursera.org", "udemy.com", "w3schools.com", "geeksforgeeks.org",
    "kaggle.com", "huggingface.co", "pypi.org", "npmjs.com", "sbi.co.in", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotak.com", "paytm.com", "phonepe.com", "flipkart.com",
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in", "epfindia.gov.in", "openai.com",
    "steampowered.com", "twitch.tv", "adobe.com", "canva.com", "figma.com", "notion.so",
    "gmail.com", "outlook.com", "hotmail.com", "icloud.com", "protonmail.com", "proton.me",
    "aol.com", "zoho.com", "gmx.com", "mail.com"
}

PHISHING_INTENTS = [
    (r"\b(?:enter|verify|provide|update|submit)\s+(?:your\s+)?(?:otp|pin|password|cvv|account number|netbanking|aadhaar|pan|atm pin)\b", "Requests sensitive credentials or personal financial information"),
    (r"\b(?:account|access|card|netbanking|services?)\s+(?:has been|will be|is)\s+(?:suspended|blocked|locked|terminated|deactivated|frozen|restricted)\b", "Urgency threat: claims account or card is suspended, blocked, or restricted"),
    (r"\b(?:hdfc|sbi|icici|axis|kotak|paytm|paypal|amazon|netflix|apple|microsoft|income tax|epfo|trai|customs)\b.*\b(?:http|www|\.xyz|\.top|\.site|\.click|\.info|\.work)\b", "Impersonates bank, government, or service provider with embedded link"),
    (r"\b(?:won|winner|selected for|claimed?|lottery|lucky draw|cash prize)\b.*\b(?:rs\.?\s*\d+|\$\d+|\b\d+\s*lakh\b|\b\d+\s*crore\b|\b\d+\s*thousand\b)\b", "Promises unsolicited money, lottery, or prize rewards"),
    (r"\b(?:virus|malware|infected|warrant|arrest|legal action|court|police|cybercrime)\b.*\b(?:pay|call|click|verify)\b", "Scareware threat: claims malware infection or legal action"),
    (r"https?://\S+\.(?:xyz|top|click|site|info|work|gq|tk|ml|cf|ga)\S*", "Contains link using high-risk/suspicious domain extension"),
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


def is_trusted_domain(url: str) -> bool:
    try:
        ext = tldextract.extract(url)
        registered = ext.registered_domain.lower()
        return registered in TRUSTED_DOMAINS
    except Exception:
        return False


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


def analyze_email_address(text: str) -> tuple[float, list[str]]:
    flags = []
    confidence = 0.0

    email_pattern = r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    matches = re.findall(email_pattern, text)

    if not matches:
        return 0.0, []

    for domain_str in matches:
        domain_str = domain_str.lower()
        try:
            ext = tldextract.extract(domain_str)
            registered_domain = ext.registered_domain.lower()
            tld = ext.suffix.lower()
        except Exception:
            continue

        if registered_domain in TRUSTED_DOMAINS:
            continue

        if tld in SUSPICIOUS_TLDS:
            flags.append(f"Sender email uses high-risk domain extension (.{tld})")
            confidence += 0.45

        for brand in KNOWN_BRANDS:
            if brand in domain_str:
                official_domains = {
                    f"{brand}.com", f"{brand}.in", f"{brand}.co.in", f"{brand}.org",
                    f"{brand}.net", f"{brand}.gov.in", f"{brand}.ac.in", f"{brand}.us"
                }
                if registered_domain not in official_domains:
                    flags.append(f"Sender email domain ('{domain_str}') is a lookalike/spoof of '{brand}'")
                    confidence += 0.55
                    break

        if domain_str.count("-") >= 2:
            flags.append(f"Sender domain ('{domain_str}') uses multi-hyphen obfuscation")
            confidence += 0.25

    confidence = max(0.0, min(1.0, confidence))
    return confidence, flags


def analyze_text(text: str) -> dict:
    flags = []
    confidence = 0.0
    lowered = text.lower()

    # 1. Analyze Email Address / Sender Domain if present
    addr_conf, addr_flags = analyze_email_address(text)
    if addr_flags:
        flags.extend(addr_flags)
        confidence += addr_conf

    # 2. Analyze Phishing Intent Patterns
    for pattern, description in PHISHING_INTENTS:
        if re.search(pattern, lowered):
            flags.append(description)
            confidence += 0.35

    # 3. Analyze Embedded Links
    urls = re.findall(r"https?://\S+", text)
    if urls:
        for url in urls:
            try:
                ext = tldextract.extract(url)
                if ext.suffix in SUSPICIOUS_TLDS and not any("High-risk" in f for f in flags):
                    flags.append(f"Contains embedded link with high-risk domain extension (.{ext.suffix})")
                    confidence += 0.40
                    break
            except Exception:
                pass

    confidence = max(0.0, min(1.0, confidence))
    score_hint = int(round(confidence * 100))
    return {"flags": flags, "score_hint": score_hint, "urls_found": urls}
