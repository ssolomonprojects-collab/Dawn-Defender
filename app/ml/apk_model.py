"""
APK File & Manifest Analyzer for Dawn Defender.
Inspects APK permissions, package signatures, dangerous API intents, and autostart hooks.
"""
import re
import zipfile

DANGEROUS_PERMISSIONS = {
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Requests ability to silently install unknown APK apps", 0.35),
    "android.permission.INSTALL_PACKAGES": ("Silently installs packages without user prompt", 0.40),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("Requests Accessibility Service access (can hijack screen & tap buttons)", 0.45),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Requests Overlay permission (can draw fake banking/login popups over real apps)", 0.35),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("Autostarts background service on device reboot", 0.20),
    "android.permission.READ_SMS": ("Reads private SMS & OTP verification codes", 0.30),
    "android.permission.SEND_SMS": ("Can send premium rate SMS text messages", 0.35),
    "android.permission.RECEIVE_SMS": ("Intercepts incoming SMS notifications & OTPs", 0.30),
    "android.permission.RECORD_AUDIO": ("Can record background microphone audio", 0.25),
    "android.permission.CAMERA": ("Can access hardware camera silently", 0.20),
    "android.permission.READ_CONTACTS": ("Harvests private phone contacts", 0.15),
    "android.permission.READ_CALL_LOG": ("Reads phone call history", 0.20),
    "android.permission.ACCESS_FINE_LOCATION": ("Tracks precise GPS location", 0.15),
}

SUSPICIOUS_APK_PATTERNS = [
    (r"mod_|\bfree_premium\b|\bcracked\b|\bhack_\b|\bunlimited_coins\b", "Filename suggests modified, cracked, or pirated application", 0.35),
    (r"\b(?:bank|hdfc|sbi|icici|axis|paytm|crypto|wallet|secure)\b", "Claims to be a financial or banking application (verify official developer signature)", 0.25),
]


def analyze_apk_bytes(file_bytes: bytes, filename: str = "") -> dict:
    flags = []
    confidence = 0.0

    # 1. Inspect Filename Heuristics
    lowered_filename = filename.lower()
    for pattern, desc, weight in SUSPICIOUS_APK_PATTERNS:
        if re.search(pattern, lowered_filename):
            flags.append(desc)
            confidence += weight

    # 2. Inspect APK Zip Archive & Manifest
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zip_file:
            file_list = zip_file.namelist()

            if "AndroidManifest.xml" not in file_list:
                flags.append("Invalid APK format: AndroidManifest.xml missing")
                return {"confidence": 0.90, "flags": flags, "model_used": True}

            manifest_data = zip_file.read("AndroidManifest.xml").decode("latin-1", errors="ignore")

            # Check Dangerous Permissions
            for perm, (desc, weight) in DANGEROUS_PERMISSIONS.items():
                perm_short = perm.split(".")[-1]
                if perm in manifest_data or perm_short in manifest_data:
                    flags.append(f"Dangerous Permission: {perm_short} ({desc})")
                    confidence += weight

            # Check for missing certificate META-INF signature
            sig_files = [f for f in file_list if f.startswith("META-INF/") and (f.endswith(".RSA") or f.endswith(".DSA") or f.endswith(".EC"))]
            if not sig_files:
                flags.append("Unsigned APK: Missing cryptographic META-INF signature certificate")
                confidence += 0.40

    except Exception as e:
        flags.append(f"Could not parse APK structure: {str(e)[:100]}")
        confidence += 0.30

    final_conf = max(0.0, min(1.0, confidence))
    return {
        "confidence": float(final_conf),
        "flags": flags,
        "model_used": True
    }
