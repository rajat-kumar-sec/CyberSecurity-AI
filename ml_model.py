import csv
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
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


model.fit(texts, labels)

MODEL_DIR.mkdir(exist_ok=True)

dump(model, MODEL_FILE)

print("ML model trained successfully.")
print("Training samples:", len(texts))
print("Threat classes:", sorted(set(labels)))
print("Model saved to:", MODEL_FILE)
