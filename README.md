# AI-Based Phishing Detection System

An interactive, explainable AI-driven cybersecurity tool designed to detect phishing URLs. The system extracts syntactic and structural features from input URLs, classifies them using a Machine Learning (Random Forest) classifier, computes a real-time risk percentage, and explains the contributing danger vectors. Additionally, users can download a dynamically generated PDF risk analysis report.

---

## 🚀 Key Features

* **Real-Time Risk Scoring**: Calculates the danger level of a website from `0%` (Legitimate) to `100%` (Phishing).
* **Explainable AI (XAI)**: Demystifies predictions by explaining the structural irregularities in the URL (e.g., hidden IP addresses, excessive subdomains, lack of HTTPS, character entropy).
* **PDF Risk Reports**: Generates downloadable, styled PDF reports detailing the threat level, feature breakdowns, and custom safety precautions.
* **Modern Premium UI**: Featuring a beautiful, dark-themed responsive "glassmorphism" interface with interactive animations.

---

## 🛠️ Tech Stack

* **Backend**: Python, FastAPI, Scikit-Learn, FPDF2, Pandas, NumPy
* **Frontend**: HTML5, Vanilla CSS3 (Custom Variables, Gradients & Transitions), JavaScript ES6

---

## 📦 Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Sarikhakr/AI-Phishing-Detection-System.git
   cd AI-Phishing-Detection-System
   ```

2. **Create and activate a Virtual Environment**:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Train the ML Model (Optional - Pre-trained model included)**:
   ```bash
   python backend/model_trainer.py
   ```

5. **Start the FastAPI server**:
   ```bash
   uvicorn backend.main:app --reload
   ```

6. **Open the App**:
   Navigate to **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

---

## 🛡️ Example Threat Explanations
* **IP Addresses**: Detects if standard domains are replaced with numerical IPs to bypass domain registry validation.
* **Typo-squatting & Mimicry**: Highlights excess hyphens (e.g., `-update-`, `-paypal-`) used to impersonate brands.
* **Obfuscation**: Identifies `@` characters where browsers ignore preceding components, masking target destinations.
