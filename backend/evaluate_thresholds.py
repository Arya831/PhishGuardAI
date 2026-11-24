import re
import ipaddress
import pandas as pd
import joblib
import tldextract

from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

def normalize_url(url):
    return re.sub(r"^https?://", "", str(url).strip(), flags=re.I)

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

print("Extracting domains...")
data["domain"] = data["URL"].map(get_domain)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

_, test_idx = next(
    splitter.split(data["URL"], data["Label"], groups=data["domain"])
)

test = data.iloc[test_idx]

print("Loading candidate model...")
model = joblib.load("backend/phishing_model_normalized_candidate.pkl")
vectorizer = joblib.load("backend/vectorizer_normalized_candidate.pkl")

print("Transforming test URLs...")
X_test = vectorizer.transform(test["URL"].map(normalize_url))
y_test = (test["Label"] == "bad").astype(int)
scores = model.predict_proba(X_test)[:, list(model.classes_).index("bad")]

print("\n========== THRESHOLD COMPARISON ==========")
print("Test records:", len(test))
print("Test domains:", test["domain"].nunique())

for threshold in [0.40, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80]:
    predictions = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    print("\nThreshold:", threshold)
    print("Precision:", round(precision_score(y_test, predictions, zero_division=0), 3))
    print("Recall:", round(recall_score(y_test, predictions, zero_division=0), 3))
    print("F1:", round(f1_score(y_test, predictions, zero_division=0), 3))
    print("False positives:", fp)
    print("Missed phishing URLs:", fn)
    print("Correct legitimate URLs:", tn)
    print("Detected phishing URLs:", tp)

print("\nEvaluation complete. No model training or saving performed.")
