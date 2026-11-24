# PhishGuard AI

### Machine Learning-Based Phishing URL Detection System

PhishGuard AI is a full-stack web application that analyzes URLs to identify potentially malicious and phishing websites.

It combines a machine-learning classification model with an independent heuristic risk assessment engine. Scan results are stored in MongoDB Atlas, and users can review scan history and generate PDF security reports.

## Features

- Machine-learning-based phishing URL classification.
- Character-level TF-IDF feature extraction.
- SGDClassifier for binary classification.
- Configurable phishing classification threshold (0.55).
- Independent heuristic risk scoring.
- URL validation and normalization.
- Scan history using MongoDB Atlas.
- PDF security report generation.
- React dashboard with FastAPI backend.

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React.js |
| Backend | Python, FastAPI |
| Machine Learning | Scikit-learn |
| Feature Extraction | TF-IDF |
| Classification | SGDClassifier |
| Database | MongoDB Atlas, PyMongo |
| PDF Reports | ReportLab |

## System Architecture

1. The user submits a URL through the React dashboard.
2. FastAPI validates and normalizes the URL.
3. The TF-IDF vectorizer converts the URL into numerical features.
4. The trained classifier generates a model-derived phishing score.
5. A classification threshold of 0.55 determines the ML verdict.
6. A separate heuristic engine calculates a risk score and identifies suspicious URL characteristics.
7. Scan results are stored in MongoDB Atlas.
8. Users can view scan history and generate PDF reports.

## Machine Learning Model

The model uses character-level TF-IDF features with character n-grams of length 3 to 5, followed by an SGDClassifier using logistic loss.

The model was evaluated using a domain-grouped train/test split to reduce overlap between domains in the training and testing datasets.

### Held-out Domain Evaluation

At the selected classification threshold of 0.55:

| Metric | Result |
|---|---:|
| Phishing Precision | 88.5% |
| Phishing Recall | 80.9% |
| Phishing F1-score | 84.5% |

The threshold was selected based on the precision-recall trade-off observed during evaluation.

**Important:** The displayed ML phishing score is a model-derived score, not a calibrated probability of real-world maliciousness. Dataset composition and evolving phishing techniques can affect performance. This project is a prototype, not a production security or browser-blocking solution.

## Heuristic Risk Assessment

The application separately calculates a heuristic risk score using URL characteristics such as:

- Suspicious keywords including login, verify, account and payment.
- URL length.
- Use of HTTP instead of HTTPS.
- IP-address-based hosts.
- Multiple hyphens in the hostname.

The ML classification and heuristic risk level are independent outputs and may differ.

## Project Structure

- backend/main.py — FastAPI application
- backend/requirements.txt — Python dependencies
- backend/train_model.py — Model training script
- backend/phishing_model_normalized_candidate.pkl — Trained classifier
- backend/vectorizer_normalized_candidate.pkl — TF-IDF vectorizer
- frontend/src/ — React application
- frontend/public/ — Static frontend assets
- README.md — Project documentation
- .gitignore — Git exclusions

## Installation and Setup

### 1. Clone the repository

After publishing this project on GitHub, clone it using the repository URL:

```bash
git clone YOUR_REPOSITORY_URL
cd PhishGuardAI
```

### 2. Backend Setup

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:MONGO_URI = 'your_mongodb_connection_string'
uvicorn main:app --reload
```

The backend API will be available at http://127.0.0.1:8000.

### 3. Frontend Setup

Open a second terminal from the project root:

```powershell
cd frontend
npm install
npm start
```

The React dashboard will be available at http://localhost:3000.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | / | API status |
| POST | /predict | Analyze a submitted URL |
| GET | /history | Retrieve previous scans |
| GET | /generate-report | Generate and download a PDF report |

## Limitations

- Model performance depends on the quality and coverage of the training dataset.
- New phishing techniques and unseen domains may not be detected correctly.
- The ML score is model-derived and is not a calibrated probability.
- Heuristic risk scoring is independent of the ML classification.
- This project is an academic prototype, not a production-grade security solution.

## Future Improvements

- Expand and regularly update the training dataset.
- Improve model evaluation on newer, unseen domains.
- Add automated model retraining and monitoring.
- Enhance URL analysis and security reporting.

## Disclaimer

This project is intended for educational and research purposes. Do not rely on it as the sole protection against phishing or malicious websites.
