
from pathlib import Path

import joblib


# Locate the saved model
ML_DIR = Path(__file__).parent
MODEL_PATH = ML_DIR / "models" / "security_classifier.joblib"


def load_model():
    """
    Load the trained ML pipeline from disk.
    """
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Trained model not found at: {MODEL_PATH}. "
            "Run train_model.py first."
        )

    return joblib.load(MODEL_PATH)


# Load model once when this module is imported
model = load_model()


def predict_code(source_code: str) -> dict:
    """
    Predict whether Python source code resembles
    risky-like or safe-like training examples.
    """

    if not isinstance(source_code, str) or not source_code.strip():
        raise ValueError("Source code cannot be empty.")

    prediction = int(model.predict([source_code])[0])

    probabilities = model.predict_proba([source_code])[0]

    # Get probability associated with risky class (label 1)
    classes = list(model.classes_)
    risky_index = classes.index(1)
    risk_score = float(probabilities[risky_index])

    return {
        "prediction": "risky_like" if prediction == 1 else "safe_like",
        "risk_score": round(risk_score, 4),
        "model": "TF-IDF + Logistic Regression"
    }
