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

CRITICAL_THREAT_PATTERNS = [
    (r"\b(?:enter|verify|provide|update|submit|restore|confirm)\s+(?:your\s+)?(?:otp|pin|password|cvv|account number|netbanking|aadhaar|pan|atm pin|login|access)\b", "Requests sensitive credentials, login, or personal financial information", 0.75),
    (r"\b(?:account|access|card|netbanking|services?)\s+(?:has been|will be|is)\s+(?:suspended|blocked|locked|terminated|deactivated|frozen|restricted)\b", "Urgency threat: claims account or card is suspended, blocked, or restricted", 0.75),
    (r"\b(?:hdfc|sbi|icici|axis|kotak|paytm|paypal|amazon|netflix|apple|microsoft|income tax|epfo|trai|customs)\b.*\b(?:http|www|\.xyz|\.top|\.site|\.click|\.info|\.work|\.com|\.org|\.net)\b", "Impersonates bank, government, or service provider with embedded link", 0.75),
    (r"\b(?:won|winner|selected for|claimed?|lottery|lucky draw|cash prize)\b.*\b(?:rs\.?\s*\d+|\$\d+|\b\d+\s*lakh\b|\b\d+\s*crore\b|\b\d+\s*thousand\b)\b", "Promises unsolicited money, lottery, or prize rewards", 0.75),
    (r"\b(?:virus|malware|infected|warrant|arrest|legal action|court|police|cybercrime)\b.*\b(?:pay|call|click|verify)\b", "Scareware threat: claims malware infection or legal action", 0.75),
    (r"https?://\S+\.(?:xyz|top|click|site|info|work|gq|tk|ml|cf|ga)\S*", "Contains link using high-risk/suspicious domain extension", 0.85),
]


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

    if is_trusted_domain(full_url):
        return {"flags": [], "score_hint": 0}

    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        flags.append("URL uses a raw IP address instead of a domain name")
        confidence += 0.90

    if tld in SUSPICIOUS_TLDS:
        flags.append(f"High-risk/suspicious domain extension (.{tld})")
        confidence += 0.40

    if registered_domain in {"bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "is.gd", "goo.gl"}:
        flags.append("Uses URL shortener to conceal target destination")
        confidence += 0.35

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

    if host.count("-") >= 2 and registered_domain not in {"scikit-learn.org", "stack-overflow.com"}:
        flags.append("Unusually many hyphens in domain (common obfuscation trick)")
        confidence += 0.25

    if host.count(".") >= 4:
        flags.append("Excessive subdomains used in hostname")
        confidence += 0.20

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
            confidence += 0.85

        for brand in KNOWN_BRANDS:
            if brand in domain_str:
                official_domains = {
                    f"{brand}.com", f"{brand}.in", f"{brand}.co.in", f"{brand}.org",
                    f"{brand}.net", f"{brand}.gov.in", f"{brand}.ac.in", f"{brand}.us"
                }
                if registered_domain not in official_domains:
                    flags.append(f"Sender email domain ('{domain_str}') is a lookalike/spoof of '{brand}'")
                    confidence += 0.85
                    break

        if domain_str.count("-") >= 2:
            flags.append(f"Sender domain ('{domain_str}') uses multi-hyphen obfuscation")
            confidence += 0.25

    confidence = max(0.0, min(1.0, confidence))
    return confidence, flags


def analyze_text(text: str) -> dict:
    critical_flags = []
    info_flags = []
    confidence = 0.0
    lowered = text.lower()

    # 1. Email Address / Sender Domain check
    addr_conf, addr_flags = analyze_email_address(text)
    if addr_flags:
        critical_flags.extend(addr_flags)
        confidence = max(confidence, addr_conf)

    # 2. Critical Threat Intent Patterns
    for pattern, description, weight in CRITICAL_THREAT_PATTERNS:
        if re.search(pattern, lowered):
            critical_flags.append(description)
            confidence = max(confidence, weight)

    # 3. Informational Flags (only active if critical flags exist or confidence is high)
    if re.search(r"rs\.?\s*\d+|\$\d+|\b\d+\s*lakh\b|\b\d+\s*crore\b", lowered):
        info_flags.append("Mentions monetary values or financial transactions")

    urls = re.findall(r"https?://\S+", text)

    all_flags = critical_flags + (info_flags if (critical_flags or confidence >= 0.40) else [])
    score_hint = int(round(max(0.0, min(1.0, confidence)) * 100)) if critical_flags else 0

    return {
        "flags": all_flags,
        "critical_flags": critical_flags,
        "score_hint": score_hint,
        "urls_found": urls
    }
