"""
Trained URL Phishing Classifier Integration for Dawn Defender.
Evaluates 79 structural/lexical features and domain risk factors.
"""
import os
import warnings
import pandas as pd
from app.ml.heuristics import analyze_url

warnings.filterwarnings("ignore")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "url_model.pkl")
FEATURE_NAMES_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "feature_names.pkl")
LABEL_ENCODER_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "label_encoder.pkl")

_model = None
_feature_names = None
_label_encoder = None
_load_attempted = False


def _load_model_if_available():
    """Loads the model and feature extraction metadata once and caches them."""
    global _model, _feature_names, _label_encoder, _load_attempted
    if _model is not None:
        return True
    if _load_attempted:
        return False
        
    _load_attempted = True
    
    if not os.path.exists(MODEL_PATH):
        return False

    try:
        import joblib
        _model = joblib.load(MODEL_PATH)
        if os.path.exists(FEATURE_NAMES_PATH):
            _feature_names = joblib.load(FEATURE_NAMES_PATH)
        if os.path.exists(LABEL_ENCODER_PATH):
            _label_encoder = joblib.load(LABEL_ENCODER_PATH)
        print("[URL Model] Successfully loaded trained URL classifier!")
        return True
    except Exception as e:
        print(f"[URL Model] Error loading model file: {e}")
        return False


def predict(url: str) -> dict:
    """
    Returns: {"confidence": float 0.0-1.0 (probability of phishing), "model_used": bool}
    """
    clean_url = url.strip()
    if not clean_url:
        return {"confidence": 0.0, "model_used": False}

    h_res = analyze_url(clean_url)
    h_score = h_res["score_hint"] / 100.0

    # If no structural red flags are triggered, the URL is clean & safe
    if not h_res["flags"]:
        return {"confidence": 0.0, "model_used": True}

    # If structural red flags WERE triggered, calculate final confidence
    if not _load_model_if_available():
        return {"confidence": float(h_score), "model_used": True}

    full_url = clean_url if "://" in clean_url else f"https://{clean_url}"

    try:
        if _feature_names is not None:
            from app.ml.feature_extractor import FeatureExtractor
            extractor = FeatureExtractor(full_url, fetch_page=False)
            feature_values = extractor.extract_all(_feature_names)
            row = pd.DataFrame([[feature_values[name] for name in _feature_names]], columns=_feature_names)

            if hasattr(_model, "predict_proba"):
                probas = _model.predict_proba(row)[0]
                classes = _model.classes_
                if _label_encoder is not None:
                    decoded_classes = [str(c).lower() for c in _label_encoder.inverse_transform(classes)]
                    proba_dict = dict(zip(decoded_classes, probas))
                    phish_proba = proba_dict.get("phishing", proba_dict.get("bad", proba_dict.get("1", probas[-1])))
                else:
                    phish_proba = probas[1] if len(probas) > 1 else probas[0]
                final_proba = max(h_score, float(phish_proba))
                return {"confidence": float(final_proba), "model_used": True}

        return {"confidence": float(h_score), "model_used": True}

    except Exception as e:
        print(f"[URL Model] Error during prediction: {e}")
        return {"confidence": float(h_score), "model_used": True}
