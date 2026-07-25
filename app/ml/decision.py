"""
Combines security checks + AI confidence into a plain-English verdict.
"""

EXPLANATIONS = {
    "url": {
        "dangerous": "This website link shows strong signs of a scam or phishing trap designed to steal your passwords or banking details.",
        "suspicious": "This link has some warning signs. It might be safe, but verify before entering any personal information.",
        "safe": "This link appears clean and free of common phishing or scam indicators.",
    },
    "sms": {
        "dangerous": "This message is a scam attempt designed to pressure you into revealing passwords, OTP codes, or clicking dangerous links.",
        "suspicious": "This text message contains warning signs common in unwanted or spam messages.",
        "safe": "This message does not show common scam or fraud patterns.",
    },
    "email": {
        "dangerous": "This email shows strong signs of phishing — it impersonates an official company or bank to steal sensitive data.",
        "suspicious": "This email contains suspicious elements. Double check the sender address before trusting it.",
        "safe": "This email appears safe and shows no common scam indicators.",
    },
    "apk": {
        "dangerous": "This app file requests dangerous phone permissions (such as controlling your screen, installing software, or reading private texts) and is unsafe to install.",
        "suspicious": "This app file has some warning flags. Review permissions carefully before installing.",
        "safe": "This app file appears safe and requests no dangerous hidden permissions.",
    },
}

RECOMMENDATIONS = {
    "dangerous": "Do not click links, reply, or enter any personal details. Delete or block this immediately.",
    "suspicious": "Verify the sender through an official phone number or website before trusting this.",
    "safe": "No threat detected, but always stay cautious with unexpected requests.",
}


def _verdict_from_score(score: int) -> str:
    if score >= 60:
        return "dangerous"
    if score >= 20:
        return "suspicious"
    return "safe"


def build_verdict(scan_type: str, flags: list, heuristic_score_hint: int,
                   model_confidence: float = 0.0, model_used: bool = False) -> dict:

    if model_used:
        model_score = int(round(model_confidence * 100))
        combined_score = max(model_score, heuristic_score_hint)
    else:
        combined_score = heuristic_score_hint

    combined_score = max(0, min(100, combined_score))
    verdict = _verdict_from_score(combined_score)

    if not flags:
        if verdict == "dangerous":
            flags = ["Flagged by AI security engine as a high-risk scam attempt"]
        elif verdict == "suspicious":
            flags = ["Flagged by AI security engine as suspicious content"]
        else:
            flags = ["No security threats detected"]

    return {
        "risk_score": combined_score,
        "verdict": verdict,
        "red_flags": flags,
        "explanation": EXPLANATIONS.get(scan_type, EXPLANATIONS["url"])[verdict],
        "recommendation": RECOMMENDATIONS[verdict],
        "requires_confirmation": verdict != "safe",
    }
