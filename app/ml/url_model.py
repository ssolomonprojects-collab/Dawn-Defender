"""
Trained URL Phishing Classifier Integration for Dawn Defender.

Loads url_model.pkl, feature_names.pkl, and label_encoder.pkl from trained_models,
and extracts 79 features via app.ml.feature_extractor.FeatureExtractor.
"""
import os
import warnings
import pandas as pd
from app.ml.heuristics import is_trusted_domain

warnings.filterwarnings("ignore")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "url_model.pkl")
FEATURE_NAMES_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "feature_names.pkl")
LABEL_ENCODER_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "label_encoder.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "url_vectorizer.pkl")

_model = None
_feature_names = None
_label_encoder = None
_vectorizer = None
_load_attempted = False


def _load_model_if_available():
    """Loads the model and feature extraction metadata once and caches them."""
    global _model, _feature_names, _label_encoder, _vectorizer, _load_attempted
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
        if os.path.exists(VECTORIZER_PATH):
            _vectorizer = joblib.load(VECTORIZER_PATH)
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

    # Fast-path for verified legitimate domains
    if is_trusted_domain(clean_url):
        return {"confidence": 0.0, "model_used": True}

    if not _load_model_if_available():
        return {"confidence": 0.0, "model_used": False}

    # Normalize scheme if missing
    full_url = clean_url if "://" in clean_url else f"https://{clean_url}"

    try:
        # Case 1: 79-Feature Extractor Model (RandomForest / DecisionTree)
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
                return {"confidence": float(phish_proba), "model_used": True}
            else:
                pred = _model.predict(row)[0]
                if _label_encoder is not None:
                    label = str(_label_encoder.inverse_transform([pred])[0]).lower()
                    confidence = 0.95 if label in ("phishing", "bad", "1") else 0.05
                else:
                    confidence = 0.95 if pred == 1 else 0.05
                return {"confidence": confidence, "model_used": True}

        # Case 2: Separate vectorizer provided
        if _vectorizer is not None:
            features = _vectorizer.transform([full_url])
            if hasattr(_model, "predict_proba"):
                proba = _model.predict_proba(features)[0][1]
            else:
                proba = float(_model.predict(features)[0])
            return {"confidence": float(proba), "model_used": True}

        # Case 3: Sklearn Pipeline accepting raw text
        if hasattr(_model, "predict_proba"):
            proba = _model.predict_proba([full_url])[0][1]
        else:
            proba = float(_model.predict([full_url])[0])
        return {"confidence": float(proba), "model_used": True}

    except Exception as e:
        print(f"[URL Model] Error during prediction: {e}")
        return {"confidence": 0.0, "model_used": False}
