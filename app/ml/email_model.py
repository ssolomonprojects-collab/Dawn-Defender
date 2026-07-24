"""
Smart, flexible loader for trained Email phishing classification models.
Supports Sklearn Pipeline or Model + Vectorizer (email_model.pkl + email_vectorizer.pkl).
"""
import os
import warnings

warnings.filterwarnings("ignore")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "email_model.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "trained_models", "email_vectorizer.pkl")

_model = None
_vectorizer = None
_load_attempted = False


def _load_model_if_available():
    global _model, _vectorizer, _load_attempted
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
        if os.path.exists(VECTORIZER_PATH):
            _vectorizer = joblib.load(VECTORIZER_PATH)
        return True
    except Exception as e:
        print(f"[Email Model] Error loading model file: {e}")
        return False


def predict(text: str) -> dict:
    """Returns: {"confidence": float 0.0-1.0 (probability of phishing), "model_used": bool}"""
    if not _load_model_if_available():
        return {"confidence": 0.0, "model_used": False}

    try:
        if _vectorizer is not None:
            features = _vectorizer.transform([text])
            if hasattr(_model, "predict_proba"):
                proba = _model.predict_proba(features)[0][1]
            else:
                proba = float(_model.predict(features)[0])
            return {"confidence": float(proba), "model_used": True}

        if hasattr(_model, "predict_proba"):
            proba = _model.predict_proba([text])[0][1]
        else:
            proba = float(_model.predict([text])[0])
        return {"confidence": float(proba), "model_used": True}

    except Exception as e:
        print(f"[Email Model] Error during prediction: {e}")
        return {"confidence": 0.0, "model_used": False}

