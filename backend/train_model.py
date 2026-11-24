import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load dataset
data = pd.read_csv(r"phishing_site_urls.csv")
data = data.sample(5000)

# Website URLs
X = data["URL"]

# Labels (safe or phishing)
y = data["Label"]

# Convert text into numbers
vectorizer = CountVectorizer()

X_vectorized = vectorizer.fit_transform(X)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.2,
    random_state=42
)

# Create AI model
model = RandomForestClassifier(
    n_estimators=10,
    max_depth=10
)    

# Train model
model.fit(X_train, y_train)

# Check accuracy
accuracy = model.score(X_test, y_test)

print("Accuracy:", accuracy)

# Save model
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("AI Model Saved Successfully")