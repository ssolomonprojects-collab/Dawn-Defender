"""
Combines heuristic flags + trained model confidence into the final
risk_score / verdict / explanation / recommendation shown to the user.
"""

EXPLANATIONS = {
    "url": {
        "dangerous": "This link shows strong signs of being a phishing attempt. It may be trying to steal your login details or personal information.",
        "suspicious": "This link has some warning signs. It might be legitimate, but proceed carefully.",
        "safe": "This link doesn't show any common phishing indicators.",
    },
    "sms": {
        "dangerous": "This message has strong characteristics of a scam — likely trying to pressure you into acting quickly or clicking a malicious link.",
        "suspicious": "This message has warning signs typical of spam or scam texts.",
        "safe": "This message doesn't show common scam/spam patterns.",
    },
    "email": {
        "dangerous": "This email shows strong signs of phishing — it may be impersonating a real company or bank to steal sensitive information.",
        "suspicious": "This email has red flags. Double-check the sender before trusting it.",
        "safe": "This email doesn't show common phishing indicators.",
    },
}

RECOMMENDATIONS = {
    "dangerous": "Do not click, reply, or enter any information. Delete or report this immediately.",
    "suspicious": "Verify through an official source before trusting this — don't act on it directly.",
    "safe": "No immediate threat detected, but always stay alert for unexpected requests.",
}


def _verdict_from_score(score: int) -> str:
    if score >= 50:
        return "dangerous"
    if score >= 25:
        return "suspicious"
    return "safe"


def build_verdict(scan_type: str, flags: list, heuristic_score_hint: int,
                   model_confidence: float = 0.0, model_used: bool = False) -> dict:
    """
    flags: list of human-readable red flag strings from heuristics
    heuristic_score_hint: 0-100 rough score from rule-based checks
    model_confidence: 0.0-1.0 from the trained model
    model_used: whether a real trained model produced model_confidence
    """
    if model_used:
        model_score = int(round(model_confidence * 100))
        # Ensure high risk from either ML model OR heuristics triggers appropriate alert
        combined_score = max(model_score, heuristic_score_hint, int(round(model_score * 0.7 + heuristic_score_hint * 0.3)))
    else:
        combined_score = heuristic_score_hint

    combined_score = max(0, min(100, combined_score))
    verdict = _verdict_from_score(combined_score)

    if not flags:
        if verdict == "dangerous":
            flags = ["Flagged by AI model as a high-probability scam/phishing attempt"]
        elif verdict == "suspicious":
            flags = ["Flagged by AI model as suspicious content"]
        else:
            flags = ["No specific red flags detected"]

    return {
        "risk_score": combined_score,
        "verdict": verdict,
        "red_flags": flags,
        "explanation": EXPLANATIONS[scan_type][verdict],
        "recommendation": RECOMMENDATIONS[verdict],
        "requires_confirmation": verdict != "safe",
    }
