from fastapi import FastAPI, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import pickle
import os
import pandas as pd
import json
from .feature_extraction import URLFeatureExtractor
from .pdf_generator import generate_pdf_report
import csv
from datetime import datetime

app = FastAPI(title="AI Phishing Detection System")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'model.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, 'features.pkl')
HISTORY_FILE = os.path.join(BASE_DIR, 'history.csv')

def save_to_history(url: str, is_phishing: bool, risk_score: float):
    file_exists = os.path.isfile(HISTORY_FILE)
    try:
        with open(HISTORY_FILE, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['Timestamp', 'URL', 'Result', 'Risk Score'])
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result = 'Phishing' if is_phishing else 'Safe'
            writer.writerow([timestamp, url, result, f"{risk_score:.2f}%"])
    except Exception as e:
        print(f"Failed to save history: {e}")

try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(FEATURES_PATH, 'rb') as f:
        feature_cols = pickle.load(f)
except Exception as e:
    print(f"Warning: Could not load model. Ensure you run model_trainer.py. Error: {e}")
    model = None
    feature_cols = []

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "../frontend")), name="static")

class URLRequest(BaseModel):
    url: str

class TextRequest(BaseModel):
    text: str

PHISHING_KEYWORDS = [
    'password', 'bank', 'account', 'urgent', 'click here', 'verify', 'login',
    'credit card', 'social security', 'wire transfer', 'paypal', 'amazon',
    'free', 'win', 'prize', 'lottery', 'inheritance', 'confidential'
]

def analyze_text_for_phishing(text: str):
    text_lower = text.lower()
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
    risk_score = min(len(found_keywords) * 20, 100)  # Simple scoring
    is_phishing = risk_score >= 50
    risk_factors = [f"Contains suspicious keyword: '{kw}'" for kw in found_keywords]
    if not risk_factors:
        risk_factors = ["No obvious phishing indicators found"]
    return is_phishing, risk_score, risk_factors

@app.post("/api/predict")
async def predict(request: URLRequest):
    if not model:
        raise HTTPException(status_code=500, detail="Model not loaded. Please train the model first.")
        
    url = request.url
    extractor = URLFeatureExtractor(url)
    features_dict = extractor.extract_features()
    
    input_df = pd.DataFrame([features_dict], columns=feature_cols)
    probs = model.predict_proba(input_df)[0]
    risk_score = float(probs[1]) * 100
    
    is_phishing = risk_score >= 50.0
    explanations = extractor.explain_features(features_dict)
    
    save_to_history(url, bool(is_phishing), risk_score)
    
    return {
        "url": url,
        "is_phishing": bool(is_phishing),
        "risk_score": round(risk_score, 2),
        "risk_factors": explanations
    }

@app.post("/api/analyze_text")
async def analyze_text(request: TextRequest):
    text = request.text
    is_phishing, risk_score, risk_factors = analyze_text_for_phishing(text)
    
    # Save to history with text as URL placeholder
    save_to_history(f"Voice: {text[:50]}...", bool(is_phishing), risk_score)
    
    return {
        "text": text,
        "is_phishing": bool(is_phishing),
        "risk_score": round(risk_score, 2),
        "risk_factors": risk_factors
    }

@app.post("/api/report")
async def get_report(url: str = Form(...), is_phishing: str = Form(...), risk_score: str = Form(...), risk_factors: str = Form(...)):
    try:
        is_phishing_bool = is_phishing.lower() == 'true'
        risk_score_float = float(risk_score)
        factors_list = json.loads(risk_factors)
        
        pdf_path = generate_pdf_report(
            url=url,
            is_phishing=is_phishing_bool,
            risk_score=risk_score_float,
            risk_factors=factors_list
        )
        return FileResponse(pdf_path, media_type='application/pdf', filename="Targeted_Risk_Report.pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history")
async def get_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        history = []
        with open(HISTORY_FILE, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                history.append(row)
        return list(reversed(history))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read history: {e}")

@app.get("/")
async def root():
    return FileResponse(os.path.join(BASE_DIR, "../frontend/index.html"))
