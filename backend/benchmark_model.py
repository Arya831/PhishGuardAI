import time
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

start = time.time()

print("Loading dataset...")
data = pd.read_csv("backend/phishing_site_urls.csv")

data = data.dropna(subset=["URL", "Label"])
data["URL"] = data["URL"].astype(str)
data["Label"] = data["Label"].astype(str).str.lower().str.strip()

# Remove URLs that have conflicting labels
print("Checking duplicate URLs...")
conflicts = data.groupby("URL")["Label"].nunique()
conflict_urls = conflicts[conflicts > 1].index

data = data[~data["URL"].isin(conflict_urls)]
data = data.drop_duplicates(subset=["URL"])

print("Clean records:", len(data))
print("Labels:", data["Label"].value_counts().to_dict())

# Use a reproducible, stratified 150,000-record sample
sample_size = min(150000, len(data))

sample, _ = train_test_split(
    data,
    train_size=sample_size,
    random_state=42,
    stratify=data["Label"]
)

X_train, X_test, y_train, y_test = train_test_split(
    sample["URL"],
    sample["Label"],
    test_size=0.20,
    random_state=42,
    stratify=sample["Label"]
)

print("\nTraining records:", len(X_train))
print("Testing records:", len(X_test))

# Learn character-level URL patterns
print("\nBuilding TF-IDF features...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    min_df=2,
    max_features=200000,
    sublinear_tf=True,
    dtype=np.float32
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

print("Feature count:", len(vectorizer.vocabulary_))

# Train a class-balanced classifier
print("\nTraining SGD classifier...")

model = SGDClassifier(
    loss="log_loss",
    class_weight="balanced",
    max_iter=20,
    tol=0.001,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_vec, y_train)

# Evaluate only on held-out records
predictions = model.predict(X_test_vec)

print("\n========== NEW MODEL RESULTS ==========")
print("Accuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")

print("\nConfusion Matrix:")
print(confusion_matrix(
    y_test,
    predictions,
    labels=["bad", "good"]
))

print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    labels=["bad", "good"],
    zero_division=0
))

# Check illustrative URLs
test_urls = [
    "https://www.google.com",
    "http://paypal-login-security-update.com",
    "http://192.168.1.1/login",
    "https://www.microsoft.com"
]

test_features = vectorizer.transform(test_urls)

print("\nSample URL Predictions:")
for url, prediction, probabilities in zip(
    test_urls,
    model.predict(test_features),
    model.predict_proba(test_features)
):
    bad_index = list(model.classes_).index("bad")
    print(url)
    print("Prediction:", prediction)
    print("Phishing probability:", round(probabilities[bad_index] * 100, 2), "%")

# Save as candidate files, not production files
joblib.dump(model, "backend/phishing_model_candidate.pkl")
joblib.dump(vectorizer, "backend/vectorizer_candidate.pkl")

print("\nCandidate model saved successfully.")
print("Time taken:", round(time.time() - start, 2), "seconds")
