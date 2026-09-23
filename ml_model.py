import csv
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
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


X_train, X_test, y_train, y_test = train_test_split(
    texts,
    labels,
    test_size=0.25,
    random_state=42,
    stratify=labels
)


model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2)
    )),
    ("classifier", LogisticRegression(
        max_iter=1000
    ))
])


model.fit(X_train, y_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)


MODEL_DIR.mkdir(exist_ok=True)

dump(model, MODEL_FILE)


print("=== ML MODEL TRAINING ===")
print("Total samples:", len(texts))
print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))
print("Threat classes:", sorted(set(labels)))
print()
print("=== UNSEEN TEST RESULTS ===")
print("Accuracy:", round(accuracy * 100, 2), "%")
print()
print(classification_report(
    y_test,
    predictions,
    zero_division=0
))
print("Model saved to:", MODEL_FILE)
