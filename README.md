# 🔐 AI API Security & Attack Detection Platform

An AI-powered API security platform that monitors API traffic, detects abnormal behavior, calculates security risk, and recommends automated security actions.

## 🚀 Features

- 🔑 JWT-based authentication
- 🛡️ API security middleware
- 🚦 Request rate limiting
- 📊 Real-time API behavioral monitoring
- 🤖 Isolation Forest anomaly detection
- 🎯 AI-based risk scoring
- 🚨 Attack type classification
- ⚡ Automated security decisions
- 📈 Behavioral security metrics
- 🌐 Interactive Streamlit dashboard
- 🔌 FastAPI backend

## 🧠 AI Detection

The platform uses an *Isolation Forest* machine-learning model for behavioral anomaly detection.

The model analyzes API traffic features such as:

- Requests per minute
- Failed requests
- Unique endpoints
- Average response time
- Error rate

The system identifies whether the observed API behavior is normal or anomalous.

## 🎯 Risk-Based Security Response

| Risk Score | Security Action |
|------------|-----------------|
| 0–39 | ALLOW |
| 40–59 | MONITOR |
| 60–79 | RATE_LIMIT |
| 80–100 | BLOCK |

## 🚨 Attack Detection

The platform can identify abnormal traffic patterns such as API flooding.

Example:

```text
Requests/minute: 100
Failed requests: 100
Risk Score: 90/100
Severity: CRITICAL
Attack Type: API Flooding
Recommended Action: BLOCK

🏗️ System Architecture

Client
   ↓
FastAPI Backend
   ↓
Security Middleware
   ↓
Rate Limiting
   ↓
API Traffic Monitoring
   ↓
Feature Engineering
   ↓
Isolation Forest
   ↓
Risk Scoring
   ↓
Security Decision
   ↓
Streamlit Dashboard

🛠️ Technologies

Python
FastAPI
Streamlit
SQL
JWT Authentication
Scikit-learn
Isolation Forest
Pandas
Uvicorn

📂 Project Structure

AI-powered API Security & Attack Detection Platform/
│
├── backend/
│   └── app/
│       ├── main.py
│       ├── database.py
│       ├── models.py
│       ├── security.py
│       ├── middleware.py
│       ├── security_middleware.py
│       └── routes/
│
├── ml/
│   ├── detector.py
│   ├── feature_engineering.py
│   ├── traffic_simulator.py
│   └── train.py
│
├── dashboard/
│   └── app.py
│
├── tests/
│
├── requirements.txt
├── README.md
└── .gitignore

 ▶️ Running the Project

1. Activate virtual environment
venv\Scripts\activate

2. Start FastAPI
python -m uvicorn backend.app.main:app --reload

3. Start Streamlit
Open another terminal:
streamlit run dashboard/app.py

The dashboard will open in the browser.

🧪 Testing

Normal Traffic
The system should produce a low-risk result such as:
Risk Score: LOW
Attack Type: Normal Traffic
Recommended Action: ALLOW

Simulated Attack Traffic
The traffic simulator generates abnormal API activity.
Example detection:
AI ANOMALY DETECTED
Risk Score: 90/100
Severity: CRITICAL
Attack Type: API Flooding
Recommended Action: BLOCK

🔐 Security Components

JWT Authentication
Only authenticated users can access protected security endpoints.

Rate Limiting
Excessive requests are detected and rejected with HTTP 429.

Behavioral Detection
API behavior is converted into numerical features and analyzed using machine learning.

Automated Response
The risk score determines the recommended security action.

📌 Project Goal
The goal of this project is to demonstrate how machine learning can be integrated with modern API security systems to detect abnormal traffic and support automated security responses.

👩‍💻 Author

Manya M V

Electronics & Communication Engineering Student
AI & Machine Learning Enthusiast
Python Developer | AI Application Builder

Passionate about building real-world AI solutions in cybersecurity, computer vision, and intelligent automation.