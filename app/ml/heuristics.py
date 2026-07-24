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

# 1. High-Threat Phishing / Malicious Patterns (Weight >= 0.85 -> DANGEROUS)
DANGEROUS_PATTERNS = [
    (r"\b(?:action required|urgent action|attention required|immediate response)\b.*\b(?:pay|invoice|bill|verify|login|click|account|suspended|link|http)\b", "Urgent action demand combined with payment, invoice, or verification link", 0.85),
    (r"\b(?:invoice|billing statement|payment receipt|overdue payment|outstanding invoice|unpaid bill)\b.*\b(?:http|www|\.xyz|\.top|\.site|\.click|\.info|\.work|\.com|\.org|\.net|pay|verify|click)\b", "Invoice or billing demand requiring payment or link verification", 0.85),
    (r"\b(?:enter|verify|provide|update|submit|restore|confirm|reset)\b.*\b(?:otp|pin|password|cvv|account|netbanking|aadhaar|pan|card|atm pin|login|credentials|identity)\b", "Requests sensitive credentials, account verification, or login details", 0.85),
    (r"\b(?:account|access|card|netbanking|services?)\b.*\b(?:suspended|blocked|locked|terminated|deactivated|frozen|restricted)\b", "Urgency threat: claims account or card is suspended, blocked, or restricted", 0.85),
    (r"\b(?:hdfc|sbi|icici|axis|kotak|paytm|paypal|amazon|netflix|apple|microsoft|income tax|epfo|trai|customs)\b.*\b(?:http|www|\.xyz|\.top|\.site|\.click|\.info|\.work|\.com|\.org|\.net)\b", "Impersonates bank, government, or service provider with embedded link", 0.90),
    (r"\b(?:won|winner|selected for|claimed?|lottery|lucky draw|cash prize)\b.*\b(?:rs\.?\s*\d+|\$\d+|\b\d+\s*lakh\b|\b\d+\s*crore\b|\b\d+\s*thousand\b)\b", "Promises unsolicited money, lottery, or prize rewards", 0.85),
    (r"\b(?:virus|malware|infected|warrant|arrest|legal action|court|police|cybercrime)\b.*\b(?:pay|call|click|verify)\b", "Scareware threat: claims malware infection or legal action", 0.90),
    (r"https?://\S+\.(?:xyz|top|click|site|info|work|gq|tk|ml|cf|ga)\S*", "Contains link using high-risk/suspicious domain extension", 0.85),
]

# 2. Medium-Threat Suspicious Patterns (Weight = 0.35-0.45 -> SUSPICIOUS)
SUSPICIOUS_PATTERNS = [
    (r"\b(?:package delivery|shipment update|parcel status|delivery notification)\b", "Mentions package delivery or shipment notifications (verify before clicking)", 0.35),
    (r"\b(?:action required|urgent action|attention required)\b", "Uses urgent action language in subject line", 0.35),
    (r"\b(?:invoice|billing statement|payment receipt)\b", "Mentions generic invoice or payment receipt", 0.35),
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

        # Check for Brand Spoofing (DANGEROUS: 0.95)
        for brand in KNOWN_BRANDS:
            if brand in domain_str and registered_domain not in {f"{brand}.com", f"{brand}.in", f"{brand}.co.in", f"{brand}.org"}:
                flags.append(f"Sender email domain ('{domain_str}') is a lookalike/spoof of '{brand}'")
                confidence = max(confidence, 0.95)
                break

        # Check for High-Risk TLD without brand spoofing (SUSPICIOUS: 0.40)
        if not flags and tld in SUSPICIOUS_TLDS:
            flags.append(f"Sender email uses high-risk domain extension (.{tld})")
            confidence = max(confidence, 0.40)

    return confidence, flags


def analyze_text(text: str) -> dict:
    flags = []
    confidence = 0.0
    lowered = text.lower()

    # 1. Sender Email Address Check
    addr_conf, addr_flags = analyze_email_address(text)
    if addr_flags:
        flags.extend(addr_flags)
        confidence = max(confidence, addr_conf)

    # 2. Embedded Link Phishing Analysis
    urls = re.findall(r"https?://\S+|www\.\S+|\S+\.(?:xyz|top|site|click|info|work|gq|tk)\S*", text)
    for u in urls:
        u_res = analyze_url(u)
        if u_res["flags"]:
            for f in u_res["flags"]:
                flags.append(f"Embedded Link Warning: {f}")
            confidence = max(confidence, u_res["score_hint"] / 100.0)

    # 3. Check DANGEROUS Patterns (High Priority >= 0.85 -> DANGEROUS)
    for pattern, description, weight in DANGEROUS_PATTERNS:
        if re.search(pattern, lowered):
            flags.append(description)
            confidence = max(confidence, weight)

    # 4. Check SUSPICIOUS Patterns (Medium Priority = 0.35 -> SUSPICIOUS)
    if confidence < 0.60:
        for pattern, description, weight in SUSPICIOUS_PATTERNS:
            if re.search(pattern, lowered):
                flags.append(description)
                confidence = max(confidence, weight)

    final_score = int(round(max(0.0, min(1.0, confidence)) * 100)) if flags else 0
    return {
        "flags": flags,
        "score_hint": final_score,
        "urls_found": urls
    }
