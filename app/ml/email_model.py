"""
Smart, flexible loader for trained Email phishing classification models.
Combines TF-IDF classification with intent-based heuristic analysis.
"""
import os
import warnings
from app.ml import heuristics

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
        print("[Email Model] Successfully loaded trained Email classifier!")
        return True
    except Exception as e:
        print(f"[Email Model] Error loading model file: {e}")
        return False


def predict(text: str) -> dict:
    """Returns: {"confidence": float 0.0-1.0 (probability of phishing), "model_used": bool}"""
    clean_text = text.strip()
    if not clean_text:
        return {"confidence": 0.0, "model_used": False}

    h_res = heuristics.analyze_text(clean_text)
    h_score = h_res["score_hint"] / 100.0

    if not _load_model_if_available():
        return {"confidence": float(h_score), "model_used": True}

    try:
        if _vectorizer is not None:
            features = _vectorizer.transform([clean_text])
            if hasattr(_model, "predict_proba"):
                proba = _model.predict_proba(features)[0][1]
            else:
                proba = float(_model.predict(features)[0])

            # If no heuristic red flags triggered AND model probability is low (< 0.50), mark as SAFE
            if not h_res["flags"] and proba < 0.50:
                final_proba = 0.0
            else:
                final_proba = max(h_score, float(proba))

            return {"confidence": float(final_proba), "model_used": True}

        return {"confidence": float(h_score), "model_used": True}

    except Exception as e:
        print(f"[Email Model] Error during prediction: {e}")
        return {"confidence": float(h_score), "model_used": True}
