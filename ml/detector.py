import os
from pyexpat import features
import sqlite3
import numpy as np
import pandas as pd
import joblib
from backend.app.security_state import block_ip


DATABASE_PATH = "security.db"

MODEL_PATH = "ml/models/api_anomaly_model.pkl"
SCALER_PATH = "ml/models/feature_scaler.pkl"


FEATURE_COLUMNS = [
    "requests_per_minute",
    "failed_requests",
    "unique_endpoints",
    "avg_response_time",
    "unique_status_codes",
    "error_rate"
]


def load_model():

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "AI anomaly model not found."
        )

    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(
            "Feature scaler not found."
        )

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    return model, scaler


def get_latest_behavior():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    query = """
        SELECT
            id,
            timestamp,
            endpoint,
            status_code,
            response_time_ms,
            client_ip
        FROM security_events
        ORDER BY timestamp DESC
        LIMIT 500
    """

    df = pd.read_sql_query(
        query,
        connection
    )

    connection.close()

    if df.empty:
        return None

    df["timestamp"] = pd.to_datetime(
        df["timestamp"]
    )

    # --------------------------------------------------------
    # Use a rolling 60-second window instead of a fixed
    # clock minute. This prevents a burst from being missed
    # simply because it crossed a minute boundary.
    # --------------------------------------------------------

    latest_time = df["timestamp"].max()

    window_start = (
        latest_time - pd.Timedelta(seconds=60)
    )

    window_df = df[
        df["timestamp"] >= window_start
    ].copy()

    if window_df.empty:
        return None

    # Most active client IP
    ip_counts = (
        window_df["client_ip"]
        .value_counts()
    )

    client_ip = ip_counts.index[0]

    ip_df = window_df[
        window_df["client_ip"] == client_ip
    ]

    failed_requests = (
        ip_df["status_code"] >= 400
    ).sum()

    requests_per_minute = len(ip_df)

    unique_endpoints = (
        ip_df["endpoint"].nunique()
    )

    avg_response_time = (
        ip_df["response_time_ms"].mean()
    )

    unique_status_codes = (
        ip_df["status_code"].nunique()
    )

    error_rate = (
        failed_requests /
        requests_per_minute
        if requests_per_minute > 0
        else 0
    )

    features = pd.DataFrame(
        [{
            "requests_per_minute":
                requests_per_minute,

            "failed_requests":
                failed_requests,

            "unique_endpoints":
                unique_endpoints,

            "avg_response_time":
                avg_response_time,

            "unique_status_codes":
                unique_status_codes,

            "error_rate":
                error_rate
        }]
    )

    return (
        client_ip,
        latest_time,
        features
    )
def calculate_risk_score(anomaly_score):

    # Isolation Forest:
    # lower decision scores = more suspicious

    risk = 50 - (anomaly_score * 200)

    risk = np.clip(
        risk,
        0,
        100
    )

    return round(float(risk), 2)


def determine_severity(risk_score):

    if risk_score >= 80:
        return "CRITICAL"

    if risk_score >= 60:
        return "HIGH"

    if risk_score >= 40:
        return "MEDIUM"

    return "LOW"


def classify_attack(features, is_anomaly):

    row = features.iloc[0]

    requests_per_minute = row[
        "requests_per_minute"
    ]

    failed_requests = row[
        "failed_requests"
    ]

    unique_endpoints = row[
        "unique_endpoints"
    ]

    error_rate = row[
        "error_rate"
    ]

    if not is_anomaly:
        return "Normal Traffic"

    # Very high request volume
    if requests_per_minute >= 50:
        return "API Flooding"

    # Large number of failed requests
    if failed_requests >= 20 and error_rate >= 0.5:
        return "Brute Force / Excessive Failures"

    # Probing many endpoints
    if unique_endpoints >= 10:
        return "Endpoint Scanning"

    # General abnormal API behavior
    return "API Abuse"


def generate_reasons(features):

    reasons = []

    row = features.iloc[0]

    if row["requests_per_minute"] >= 50:
        reasons.append(
            "Extremely high request rate"
        )

    elif row["requests_per_minute"] >= 20:
        reasons.append(
            "Elevated request rate"
        )

    if row["error_rate"] >= 0.7:
        reasons.append(
            "Very high API error rate"
        )

    elif row["error_rate"] >= 0.3:
        reasons.append(
            "Elevated API error rate"
        )

    if row["failed_requests"] >= 20:
        reasons.append(
            "Large number of failed requests"
        )

    if row["unique_endpoints"] >= 10:
        reasons.append(
            "Unusual endpoint exploration"
        )

    if not reasons:
        reasons.append(
            "Behavior differs from learned baseline"
        )

    return reasons


def detect_latest_behavior():

    model, scaler = load_model()

    result = get_latest_behavior()

    if result is None:
        return {
            "status": "insufficient_data",
            "message":
                "Not enough API activity to analyze."
        }

    client_ip, time_window, features = result

    X = features[
        FEATURE_COLUMNS
    ]

    X_scaled = scaler.transform(X)

    prediction = model.predict(
        X_scaled
    )[0]

    anomaly_score = model.decision_function(
        X_scaled
    )[0]

    risk_score = calculate_risk_score(
        anomaly_score
    )

    is_anomaly = prediction == -1

    # ============================================================
    # HYBRID SECURITY RULES
    # ============================================================
    # The ML model detects unusual behavior, while these
    # deterministic security rules catch obvious high-risk
    # API abuse patterns that a small ML dataset may miss.

    row = features.iloc[0]

    requests_per_minute = row[
    "requests_per_minute"
    ]

    failed_requests = row[
    "failed_requests"
    ]

    error_rate = row[
        "error_rate"
    ]

    # High-volume API flooding
    if requests_per_minute >= 50:

       is_anomaly = True

       risk_score = max(
        risk_score,
        85
       )

    # Severe failed-request burst
    if (
        failed_requests >= 20
        and error_rate >= 0.5
       ):

       is_anomaly = True

       risk_score = max(
           risk_score,
           90
        )

    # Recalculate severity after hybrid rules
    severity = determine_severity(
        risk_score
    )

    attack_type = classify_attack(
    features,
    is_anomaly
    )

    reasons = generate_reasons(
        features
    )

    # ============================================================
    # AUTOMATED SECURITY RESPONSE ENGINE
    # ============================================================

    if risk_score < 40:

       action = "ALLOW"

    elif risk_score < 60:

        action = "MONITOR"

    elif risk_score < 80:

        action = "RATE_LIMIT"

    else:
        action = "BLOCK"

        # Temporarily block the suspicious IP
        block_ip(
            client_ip,
            duration_seconds=300
        )

    return {
        "status": "analysis_complete",

        "client_ip": client_ip,

        "time_window":
            str(time_window),

        "is_anomaly":
            bool(is_anomaly),

        "risk_score":
            risk_score,

        "severity":
            severity,

        "recommended_action":
            action,

        "attack_type":
            attack_type,

        "reasons":
            reasons,

        "behavior": {
            "requests_per_minute":
                int(
                    features.iloc[0]
                    ["requests_per_minute"]
                ),

            "failed_requests":
                int(
                    features.iloc[0]
                    ["failed_requests"]
                ),

            "unique_endpoints":
                int(
                    features.iloc[0]
                    ["unique_endpoints"]
                ),

            "average_response_time_ms":
                round(
                    float(
                        features.iloc[0]
                        ["avg_response_time"]
                    ),
                    2
                ),

            "error_rate":
                round(
                    float(
                        features.iloc[0]
                        ["error_rate"]
                    ),
                    4
                )
        },

        "model":
            "Isolation Forest"
    }


if __name__ == "__main__":

    result = detect_latest_behavior()

    print("\n===================================")
    print(" AI SECURITY ANALYSIS")
    print("===================================\n")

    for key, value in result.items():
        print(f"{key}: {value}")