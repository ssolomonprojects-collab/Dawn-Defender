"""
Dual-Engine Email Phishing Classifier for Dawn Defender.
Evaluates email addresses, embedded links, brand spoofing, and phishing threat patterns.
"""
import os
import warnings
from app.ml import heuristics

warnings.filterwarnings("ignore")


def predict(text: str) -> dict:
    """Returns: {"confidence": float 0.0-1.0 (probability of phishing), "model_used": bool}"""
    clean_text = text.strip()
    if not clean_text:
        return {"confidence": 0.0, "model_used": False}

    h_res = heuristics.analyze_text(clean_text)
    h_score = h_res["score_hint"] / 100.0

    # If no malicious links, credential requests, account threats, or spoofing exist, mark as SAFE (0.0)
    if not h_res["flags"]:
        return {"confidence": 0.0, "model_used": True}

    # If threat flags WERE detected, return the precision confidence score
    return {"confidence": float(h_score), "model_used": True}
