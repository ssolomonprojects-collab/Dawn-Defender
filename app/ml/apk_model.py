"""
APK File & Manifest Security Inspection.
Provides simple, plain-English security explanations without technical code jargon.
"""
import re
import zipfile

DANGEROUS_PERMISSIONS = {
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Tries to silently install other apps on your phone without asking you first", 0.35),
    "android.permission.INSTALL_PACKAGES": ("Tries to secretly install background software on your device", 0.40),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("Asks for complete control over your screen and tap actions", 0.45),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Can draw fake login screens over your real banking or payment apps", 0.35),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("Automatically starts running in the background as soon as your phone turns on", 0.20),
    "android.permission.READ_SMS": ("Asks to read your private text messages and bank OTP codes", 0.30),
    "android.permission.SEND_SMS": ("Can send paid text messages from your phone number without your permission", 0.35),
    "android.permission.RECEIVE_SMS": ("Intercepts incoming verification codes and password reset texts", 0.30),
    "android.permission.RECORD_AUDIO": ("Can turn on your microphone to record background audio", 0.25),
    "android.permission.CAMERA": ("Can access your camera without showing an active screen icon", 0.20),
    "android.permission.READ_CONTACTS": ("Harvests your saved phone contacts", 0.15),
    "android.permission.READ_CALL_LOG": ("Reads your private phone call history", 0.20),
    "android.permission.ACCESS_FINE_LOCATION": ("Tracks your exact GPS location continuously", 0.15),
}

SUSPICIOUS_APK_PATTERNS = [
    (r"mod_|\bfree_premium\b|\bcracked\b|\bhack_\b|\bunlimited_coins\b", "App filename indicates a modified, pirated, or tampered app file", 0.35),
    (r"\b(?:bank|hdfc|sbi|icici|axis|paytm|crypto|wallet|secure)\b", "Claims to be an official bank or payment app (verify official store source)", 0.25),
]


def analyze_apk_bytes(file_bytes: bytes, filename: str = "") -> dict:
    flags = []
    confidence = 0.0

    lowered_filename = filename.lower()
    for pattern, desc, weight in SUSPICIOUS_APK_PATTERNS:
        if re.search(pattern, lowered_filename):
            flags.append(desc)
            confidence += weight

    try:
        import io
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zip_file:
            file_list = zip_file.namelist()

            if "AndroidManifest.xml" not in file_list:
                flags.append("Invalid application package file structure")
                return {"confidence": 0.90, "flags": flags, "model_used": True}

            manifest_data = zip_file.read("AndroidManifest.xml").decode("latin-1", errors="ignore")

            for perm, (desc, weight) in DANGEROUS_PERMISSIONS.items():
                perm_short = perm.split(".")[-1]
                if perm in manifest_data or perm_short in manifest_data:
                    flags.append(f"Security Alert: {desc}")
                    confidence += weight

            sig_files = [f for f in file_list if f.startswith("META-INF/") and (f.endswith(".RSA") or f.endswith(".DSA") or f.endswith(".EC"))]
            if not sig_files:
                flags.append("Unverified App: Missing official publisher security certificate")
                confidence += 0.40

    except Exception:
        if filename:
            flags.append("App package requires security review before installation")
            confidence += 0.30

    final_conf = max(0.0, min(1.0, confidence))
    return {
        "confidence": float(final_conf),
        "flags": flags,
        "model_used": True
    }
