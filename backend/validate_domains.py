import time
import re
import ipaddress
import pandas as pd
import numpy as np
import joblib
import tldextract

from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

start = time.time()

def normalize_url(url):
    url = str(url).strip()
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    return url

print("Loading dataset...")
data = pd.read_csv("backend/phishing_site_urls.csv")
data = data.dropna(subset=["URL", "Label"])
data["URL"] = data["URL"].astype(str).str.strip()
data["Label"] = data["Label"].astype(str).str.lower().str.strip()

print("Removing conflicting and duplicate URLs...")
conflicts = data.groupby("URL")["Label"].nunique()
conflict_urls = conflicts[conflicts > 1].index
data = data[~data["URL"].isin(conflict_urls)]
data = data.drop_duplicates(subset=["URL"]).copy()

extractor = tldextract.TLDExtract(suffix_list_urls=())

def get_domain(url):
    try:
        url = str(url).strip()
        parsed = urlparse(url if "://" in url else "//" + url)
        host = (parsed.hostname or "").lower().strip()

        if not host:
            return "invalid:" + url

        try:
            return "ip:" + str(ipaddress.ip_address(host))
        except ValueError:
            pass

        result = extractor(host)
        domain = result.top_domain_under_public_suffix
        return domain if domain else host

    except (ValueError, UnicodeError, TypeError):
        return "invalid:" + str(url)

print("Extracting registered domains...")
data["domain"] = data["URL"].map(get_domain)

print("Clean records:", len(data))
print("Unique domains:", data["domain"].nunique())

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(data["URL"], data["Label"], groups=data["domain"])
)

train = data.iloc[train_idx]
test = data.iloc[test_idx]

overlap = set(train["domain"]) & set(test["domain"])

print("\nTraining records:", len(train))
print("Testing records:", len(test))
print("Domain overlap:", len(overlap))

if overlap:
    raise RuntimeError("Domain leakage detected!")

print("\nNormalizing training and testing URLs...")
X_train_text = train["URL"].map(normalize_url)
X_test_text = test["URL"].map(normalize_url)

print("Building character TF-IDF features...")
vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    min_df=2,
    max_features=200000,
    sublinear_tf=True,
    dtype=np.float32
)

X_train = vectorizer.fit_transform(X_train_text)
X_test = vectorizer.transform(X_test_text)

print("Feature count:", len(vectorizer.vocabulary_))

print("\nTraining normalized URL classifier...")
model = SGDClassifier(
    loss="log_loss",
    class_weight="balanced",
    max_iter=20,
    tol=0.001,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, train["Label"])

predictions = model.predict(X_test)
bad_index = list(model.classes_).index("bad")

print("\n========== NORMALIZED UNSEEN-DOMAIN RESULTS ==========")
print("Accuracy:", round(
    accuracy_score(test["Label"], predictions) * 100, 2
), "%")

print("\nConfusion Matrix (bad, good):")
print(confusion_matrix(
    test["Label"],
    predictions,
    labels=["bad", "good"]
))

print("\nClassification Report:")
print(classification_report(
    test["Label"],
    predictions,
    labels=["bad", "good"],
    zero_division=0
))

print("\nKnown legitimate URL checks:")
known_urls = [
    "https://google.com",
    "https://www.google.com",
    "https://microsoft.com",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org"
]

known_features = vectorizer.transform(
    [normalize_url(url) for url in known_urls]
)
known_scores = model.predict_proba(known_features)[:, bad_index]

for url, score in zip(known_urls, known_scores):
    print(f"{url:35} Phishing score: {score * 100:.2f}%")

print("\nSaving normalized model candidate...")
joblib.dump(model, "backend/phishing_model_normalized_candidate.pkl")
joblib.dump(vectorizer, "backend/vectorizer_normalized_candidate.pkl")

print("Candidate saved successfully.")
print("Time taken:", round(time.time() - start, 2), "seconds")
