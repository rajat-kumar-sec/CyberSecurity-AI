import csv
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report
from joblib import dump


DATA_FILE = Path("data/ml/training_data.csv")
MODEL_DIR = Path("models")
MODEL_FILE = MODEL_DIR / "threat_classifier.joblib"


texts = []
labels = []

with DATA_FILE.open("r", encoding="utf-8", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        texts.append(row["log"])
        labels.append(row["threat_type"])


model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2)
    )),
    ("classifier", LogisticRegression(
        max_iter=1000
    ))
])


cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)


scores = cross_val_score(
    model,
    texts,
    labels,
    cv=cv,
    scoring="accuracy"
)


model.fit(texts, labels)

MODEL_DIR.mkdir(exist_ok=True)
dump(model, MODEL_FILE)


print("=== ML MODEL VALIDATION ===")
print("Total samples:", len(texts))
print("Threat classes:", sorted(set(labels)))
print()
print("=== 5-FOLD CROSS-VALIDATION ===")

for i, score in enumerate(scores, start=1):
    print(f"Fold {i}: {score * 100:.2f}%")

print()
print("Mean Accuracy:", round(scores.mean() * 100, 2), "%")
print("Standard Deviation:", round(scores.std() * 100, 2), "%")
print()
print("Model trained on all samples.")
print("Model saved to:", MODEL_FILE)
