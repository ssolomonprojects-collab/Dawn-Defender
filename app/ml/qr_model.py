"""
QR handling has two parts:
1. Decode the QR image to find out what URL/text it actually points to
   (this works right now, using OpenCV - no trained model needed for this part)
2. PLUG YOUR TRAINED "FAKE QR" MODEL IN HERE if your team is training an
   image classifier to detect visually tampered/fake QR codes, separate
   from just checking where the decoded URL leads.
"""
import os
import cv2
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "qr_model.pkl")

_model = None


def decode_qr(image_path: str) -> str | None:
    """Reads a QR code image file and returns the decoded text/URL, or None if unreadable."""
    img = cv2.imread(image_path)
    if img is None:
        return None
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)
    return data if data else None


def _load_model_if_available():
    global _model
    if _model is not None:
        return True
    if not os.path.exists(MODEL_PATH):
        return False

    # import joblib
    # _model = joblib.load(MODEL_PATH)
    # return True
    return False


def predict_image_tampering(image_path: str) -> dict:
    """
    Returns: {"confidence": float 0.0-1.0 (probability the QR image itself is
    tampered/fake, independent of where it links), "model_used": bool}
    Only relevant if you're training a visual classifier on the QR image
    itself, not just checking the decoded URL.
    """
    if _load_model_if_available():
        # img = cv2.imread(image_path)
        # features = preprocess(img)  # match your training preprocessing
        # proba = _model.predict_proba([features])[0][1]
        # return {"confidence": float(proba), "model_used": True}
        pass

    return {"confidence": 0.0, "model_used": False}
