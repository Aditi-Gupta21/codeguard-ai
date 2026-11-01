
import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# --------------------------------------------------
# 1. Define project paths
# --------------------------------------------------

ML_DIR = Path(__file__).parent

DATASET_PATH = ML_DIR / "dataset" / "security_dataset.csv"
MODEL_DIR = ML_DIR / "models"

MODEL_PATH = MODEL_DIR / "security_classifier.joblib"
METRICS_PATH = MODEL_DIR / "evaluation_metrics.json"


# --------------------------------------------------
# 2. Load dataset
# --------------------------------------------------

print("\nLoading security dataset...")

df = pd.read_csv(DATASET_PATH)

# Check required columns
if not {"code", "label"}.issubset(df.columns):
    raise ValueError("Dataset must contain 'code' and 'label' columns.")

# Remove missing values
df = df.dropna(subset=["code", "label"])

# Remove duplicate code snippets
df = df.drop_duplicates(subset=["code"])

# Separate features and target
X = df["code"].astype(str)
y = df["label"].astype(int)

print(f"Total examples: {len(df)}")
print(f"Risky examples: {(y == 1).sum()}")
print(f"Safe examples: {(y == 0).sum()}")


# --------------------------------------------------
# 3. Split dataset into training and testing sets
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nDataset split completed.")
print(f"Training examples: {len(X_train)}")
print(f"Testing examples: {len(X_test)}")


# --------------------------------------------------
# 4. Create ML pipeline
# --------------------------------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 5),
            lowercase=True,
            max_features=5000
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        )
    )
])


# --------------------------------------------------
# 5. Train the model
# --------------------------------------------------

print("\nTraining Logistic Regression model...")

model.fit(X_train, y_train)

print("Model training completed!")


# --------------------------------------------------
# 6. Make predictions
# --------------------------------------------------

y_pred = model.predict(X_test)


# --------------------------------------------------
# 7. Evaluate the model
# --------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

conf_matrix = confusion_matrix(
    y_test,
    y_pred,
    labels=[0, 1]
)

print("\n========== MODEL EVALUATION ==========")

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        labels=[0, 1],
        target_names=["Safe-like", "Risky-like"],
        zero_division=0
    )
)

print("\nConfusion Matrix:")
print(conf_matrix)

print("\nConfusion Matrix Interpretation:")
print(f"True Safe (TN): {conf_matrix[0][0]}")
print(f"False Risky (FP): {conf_matrix[0][1]}")
print(f"Missed Risky (FN): {conf_matrix[1][0]}")
print(f"Detected Risky (TP): {conf_matrix[1][1]}")


# --------------------------------------------------
# 8. Save trained model and metrics
# --------------------------------------------------

MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Save the complete pipeline:
# TF-IDF vectorizer + Logistic Regression classifier
joblib.dump(model, MODEL_PATH)

metrics = {
    "model": "TF-IDF + Logistic Regression",
    "dataset_size": len(df),
    "training_size": len(X_train),
    "testing_size": len(X_test),
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "confusion_matrix": conf_matrix.tolist()
}

with METRICS_PATH.open("w", encoding="utf-8") as file:
    json.dump(metrics, file, indent=4)

print("\n========== SAVED FILES ==========")
print(f"Model: {MODEL_PATH}")
print(f"Metrics: {METRICS_PATH}")

print("\ Training pipeline completed successfully!")
