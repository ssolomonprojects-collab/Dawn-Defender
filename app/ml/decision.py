"""
Combines heuristic flags + trained model confidence into the final
risk_score / verdict / explanation / recommendation shown to the user.

This is deliberately rule-based, not an LLM call - it works immediately
with zero API keys and zero network dependency, which matters for a live
demo. Once your trained models are wired in (see url_model.py, sms_model.py,
email_model.py, qr_model.py), their confidence score feeds directly into
this same function - nothing else needs to change.
"""

EXPLANATIONS = {
    "url": {
        "dangerous": "This link shows strong signs of being a phishing attempt. It may be trying to steal your login details or personal information.",
        "suspicious": "This link has some warning signs. It might be legitimate, but proceed carefully.",
        "safe": "This link doesn't show any common phishing indicators.",
    },
    "sms": {
        "dangerous": "This message has strong characteristics of a scam - likely trying to pressure you into acting quickly or clicking a bad link.",
        "suspicious": "This message has a few warning signs typical of spam or scam texts.",
        "safe": "This message doesn't show common scam/spam patterns.",
    },
    "email": {
        "dangerous": "This email shows strong signs of phishing - it may be impersonating a real company to steal information.",
        "suspicious": "This email has some red flags. Double-check the sender before trusting it.",
        "safe": "This email doesn't show common phishing indicators.",
    },
    "qr": {
        "dangerous": "This QR code leads somewhere that shows strong phishing indicators.",
        "suspicious": "This QR code has some warning signs in where it leads.",
        "safe": "This QR code doesn't lead anywhere flagged as suspicious.",
    },
    "qr_unreadable": "We couldn't detect a valid QR code in this image. Try a clearer photo, or the code may be intentionally damaged/fake.",
}

RECOMMENDATIONS = {
    "dangerous": "Do not click, reply, or enter any information. Delete or report this.",
    "suspicious": "Verify through an official source before trusting this - don't act on it directly.",
    "safe": "No action needed, but always stay alert for anything that feels off.",
}


def _verdict_from_score(score: int) -> str:
    if score >= 65:
        return "dangerous"
    if score >= 30:
        return "suspicious"
    return "safe"


def build_verdict(scan_type: str, flags: list, heuristic_score_hint: int,
                   model_confidence: float = 0.0, model_used: bool = False) -> dict:
    """
    flags: list of human-readable red flag strings from heuristics
    heuristic_score_hint: 0-100 rough score from rule-based checks
    model_confidence: 0.0-1.0 from the trained model (0 if not wired up yet)
    model_used: whether a real trained model produced model_confidence
    """
    if model_used:
        model_score = int(round(model_confidence * 100))
        # If the model is confident in a scam/phishing attempt, ensure risk score reflects that
        combined_score = max(model_score, int(round(model_score * 0.7 + heuristic_score_hint * 0.3)), heuristic_score_hint)
    else:
        combined_score = heuristic_score_hint

    combined_score = max(0, min(100, combined_score))
    verdict = _verdict_from_score(combined_score)

    if not flags:
        flags = ["No specific red flags detected"] if verdict == "safe" else ["Flagged by trained model"]

    return {
        "risk_score": combined_score,
        "verdict": verdict,
        "red_flags": flags,
        "explanation": EXPLANATIONS[scan_type][verdict],
        "recommendation": RECOMMENDATIONS[verdict],
        "requires_confirmation": verdict != "safe",
    }
