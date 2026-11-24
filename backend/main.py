import os
import re
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import joblib
from pymongo import MongoClient
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# -------------------------
# CONFIGURATION
# -------------------------

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "phishing_model_normalized_candidate.pkl"
VECTORIZER_PATH = BASE_DIR / "vectorizer_normalized_candidate.pkl"
REPORT_PATH = BASE_DIR / "PhishGuard_Report.pdf"

PHISHING_THRESHOLD = 0.55

app = FastAPI(
    title="PhishGuard AI",
    description="Machine-learning-powered phishing URL detection API",
    version="3.0"
)

allowed_origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in allowed_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# LOAD MODEL
# -------------------------

if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
    raise FileNotFoundError(
        "Normalized candidate model files are missing from backend."
    )

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

bad_index = list(model.classes_).index("bad")

# -------------------------
# DATABASE
# -------------------------

mongo_client = MongoClient(
    os.getenv("MONGO_URI", "mongodb://localhost:27017"),
    serverSelectionTimeoutMS=1500,
    connectTimeoutMS=1500
)

collection = mongo_client["phishguard"]["scan_history"]

# Fallback when MongoDB is unavailable
memory_history = []

def save_scan(record):
    memory_history.insert(0, record)
    del memory_history[100:]

    try:
        collection.insert_one(record.copy())
        return True
    except Exception as e:
        print(f"MongoDB insert failed: {type(e).__name__}: {e}")
        return False


def read_history():
    try:
        return list(
            collection.find(
                {},
                {"_id": 0}
            ).sort("timestamp", -1).limit(20)
        )
    except Exception:
        return memory_history[:20]


def latest_scan():
    try:
        record = collection.find_one(
            sort=[("timestamp", -1)]
        )
        if record:
            return record
    except Exception:
        pass

    return memory_history[0] if memory_history else None


def serialize_record(record):
    result = dict(record)
    timestamp = result.get("timestamp")

    if isinstance(timestamp, datetime):
        result["timestamp"] = timestamp.isoformat()

    return result

# -------------------------
# REQUEST VALIDATION
# -------------------------

class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


def validate_url(raw_url):
    url = raw_url.strip()

    if not url:
        raise HTTPException(status_code=422, detail="URL cannot be empty.")

    # Reject whitespace and backslashes anywhere in the URL.
    if re.search(r"\s", url) or "\\" in url:
        raise HTTPException(
            status_code=422,
            detail="URL must not contain spaces or backslashes."
        )

    # Reject explicitly supplied schemes other than HTTP/HTTPS.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise HTTPException(
                status_code=422,
                detail="Only HTTP and HTTPS URLs are supported."
            )
    else:
        url = "https://" + url

    try:
        import ipaddress

        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError()

        hostname = parsed.hostname

        if not hostname:
            raise ValueError()

        if parsed.username or parsed.password:
            raise HTTPException(
                status_code=422,
                detail="URLs containing embedded credentials are not supported."
            )

        # Validate the port if one is supplied.
        _ = parsed.port

        # Accept valid IP addresses or properly formatted domain names.
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            domain = hostname.rstrip(".").encode("idna").decode("ascii")

            if len(domain) > 253 or "." not in domain:
                raise ValueError()

            labels = domain.split(".")

            for label in labels:
                if (
                    not label
                    or len(label) > 63
                    or not re.fullmatch(
                        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
                        label
                    )
                ):
                    raise ValueError()

            if not re.fullmatch(r"[a-zA-Z]{2,}|xn--[a-zA-Z0-9-]+", labels[-1]):
                raise ValueError()

        return url

    except HTTPException:
        raise
    except (ValueError, UnicodeError):
        raise HTTPException(
            status_code=422,
            detail="Please enter a valid HTTP or HTTPS URL."
        )
# -------------------------
# URL NORMALIZATION
# -------------------------

def normalize_url(url):
    return re.sub(
        r"^https?://",
        "",
        url.strip(),
        flags=re.IGNORECASE
    )

# -------------------------
# HEURISTIC RISK ENGINE
# -------------------------

def calculate_risk(url):
    risk_score = 0
    reasons = []

    suspicious_keywords = [
        "login", "verify", "secure", "update",
        "account", "bank", "paypal", "payment",
        "wallet", "free", "gift"
    ]

    url_lower = url.lower()

    for keyword in suspicious_keywords:
        if keyword in url_lower:
            risk_score += 15
            reasons.append(f"Contains '{keyword}'")

    if len(url) > 40:
        risk_score += 10
        reasons.append("Long URL")

    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        risk_score += 10
        reasons.append("Not using HTTPS")

    try:
        ipaddress.ip_address(parsed.hostname or "")
        risk_score += 25
        reasons.append("Uses an IP address")
    except ValueError:
        pass

    hostname = parsed.hostname or ""

    if hostname.count("-") >= 3:
        risk_score += 15
        reasons.append("Multiple hyphens in hostname")

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_score, risk_level, reasons

# -------------------------
# HOME
# -------------------------

@app.get("/")
def home():
    return {
        "message": "PhishGuard AI Running",
        "version": "3.0",
        "model": "Normalized Character TF-IDF + SGDClassifier",
        "classification_threshold": PHISHING_THRESHOLD
    }

# -------------------------
# PREDICTION
# -------------------------

@app.post("/predict")
def predict(data: URLRequest):
    url = validate_url(data.url)

    normalized = normalize_url(url)
    features = vectorizer.transform([normalized])

    phishing_score = float(
        model.predict_proba(features)[0][bad_index]
    )

    prediction = (
        "bad" if phishing_score >= PHISHING_THRESHOLD else "good"
    )

    heuristic_score, risk_level, reasons = calculate_risk(url)

    record = {
        "url": url,
        "prediction": prediction,
        "ml_phishing_score": round(phishing_score * 100, 2),
        "classification_threshold": PHISHING_THRESHOLD,
        "risk_score": heuristic_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "timestamp": datetime.now(timezone.utc)
    }

    database_saved = save_scan(record)

    response = serialize_record(record)
    response["database_saved"] = database_saved

    return response

# -------------------------
# SCAN HISTORY
# -------------------------

@app.get("/history")
def get_history():
    return [
        serialize_record(record)
        for record in read_history()
    ]

# -------------------------
# PDF REPORT
# -------------------------

@app.get("/generate-report")
def generate_report():
    scan = latest_scan()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="No scan history found. Scan a URL first."
        )

    styles = getSampleStyleSheet()
    content = []

    content.append(
        Paragraph("PhishGuard AI Security Report", styles["Title"])
    )
    content.append(Spacer(1, 20))

    fields = [
        ("URL", scan.get("url", "N/A")),
        ("ML Prediction", scan.get("prediction", "N/A")),
        ("ML Phishing Score", f'{scan.get("ml_phishing_score", 0)}%'),
        ("Classification Threshold", str(scan.get("classification_threshold", 0.55))),
        ("Heuristic Risk Score", f'{scan.get("risk_score", 0)}/100'),
        ("Heuristic Risk Level", scan.get("risk_level", "N/A")),
        ("Generated", str(scan.get("timestamp", "N/A")))
    ]

    for label, value in fields:
        content.append(
            Paragraph(
                f"<b>{escape(str(label))}:</b> {escape(str(value))}",
                styles["Normal"]
            )
        )
        content.append(Spacer(1, 10))

    reasons = scan.get("reasons", [])

    content.append(Spacer(1, 10))
    content.append(Paragraph("Security Indicators", styles["Heading2"]))

    if reasons:
        for reason in reasons:
            content.append(
                Paragraph(f"• {escape(str(reason))}", styles["Normal"])
            )
    else:
        content.append(
            Paragraph("No heuristic indicators detected.", styles["Normal"])
        )

    content.append(Spacer(1, 20))
    content.append(
        Paragraph(
            "Note: The ML phishing score is a model-derived score, "
            "not a calibrated probability of real-world maliciousness. "
            "The heuristic risk score is calculated separately.",
            styles["Italic"]
        )
    )

    doc = SimpleDocTemplate(str(REPORT_PATH))
    doc.build(content)

    return FileResponse(
        str(REPORT_PATH),
        media_type="application/pdf",
        filename="PhishGuard_Report.pdf"
    )

