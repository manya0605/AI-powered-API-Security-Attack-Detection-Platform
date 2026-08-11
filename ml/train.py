import os
from pyexpat import features
import sqlite3

import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


DATABASE_PATH = "security.db"

MODEL_DIR = "ml/models"

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "api_anomaly_model.pkl"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "feature_scaler.pkl"
)


FEATURE_COLUMNS = [
    "requests_per_minute",
    "failed_requests",
    "unique_endpoints",
    "avg_response_time",
    "unique_status_codes",
    "error_rate"
]


def load_events():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    query = """
        SELECT
            id,
            timestamp,
            method,
            endpoint,
            status_code,
            response_time_ms,
            client_ip,
            user_agent
        FROM security_events
    """

    df = pd.read_sql_query(
        query,
        connection
    )

    connection.close()

    return df


def create_features(df):

    if df.empty:
        return pd.DataFrame()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"]
    )

    df["time_window"] = (
        df["timestamp"].dt.floor("min")
    )

    df["is_failed"] = (
        df["status_code"] >= 400
    ).astype(int)

    features = (
        df.groupby(
            ["client_ip", "time_window"]
        )
        .agg(
            requests_per_minute=(
                "id",
                "count"
            ),

            failed_requests=(
                "is_failed",
                "sum"
            ),

            unique_endpoints=(
                "endpoint",
                "nunique"
            ),

            avg_response_time=(
                "response_time_ms",
                "mean"
            ),

            unique_status_codes=(
                "status_code",
                "nunique"
            )
        )
        .reset_index()
    )

    features["error_rate"] = (
        features["failed_requests"]
        / features["requests_per_minute"]
    )

    features = features.replace(
        [float("inf"), float("-inf")],
        0
    )

    features = features.fillna(0)

    return features


def train_model():

    print("\n===================================")
    print(" AI API ANOMALY DETECTION TRAINING")
    print("===================================\n")

    events = load_events()

    print(
        f"Security events loaded: {len(events)}"
    )

    features = create_features(events)

    if features.empty:

        print(
            "ERROR: No features available."
        )

        return

    print(
        f"Behavior windows created: "
        f"{len(features)}"
    )

    # Train primarily on baseline/normal behavior.
    # High-volume and high-error windows are excluded
    # so the anomaly detector learns the normal baseline.

    normal_baseline = features[
    (features["requests_per_minute"] <= 20)
    &
    (features["error_rate"] <= 0.10)
    ].copy()

    if len(normal_baseline) < 3:
       print(
        "\nWARNING: Not enough normal baseline windows."
    )
       print(
        "Using all available windows for training."
    )
    normal_baseline = features.copy()

    X = normal_baseline[FEATURE_COLUMNS]

    X = features[FEATURE_COLUMNS]

    print("\nTraining features:")

    print(X)

    # Scale features
    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X)

    # Isolation Forest
    model = IsolationForest(
        n_estimators=200,
        contamination=0.15,
        random_state=42
    )

    model.fit(X_scaled)

    # Predictions
    predictions = model.predict(
        X_scaled
    )

    features["prediction"] = predictions

    features["is_anomaly"] = (
        predictions == -1
    ).astype(int)

    # Anomaly score
    scores = model.decision_function(
        X_scaled
    )

    features["anomaly_score"] = scores

    print("\n===================================")
    print(" TRAINING COMPLETE")
    print("===================================\n")

    print(
        "Normal windows detected:",
        sum(predictions == 1)
    )

    print(
        "Anomalous windows detected:",
        sum(predictions == -1)
    )

    print("\nDetection results:")

    print(
        features[
            [
                "client_ip",
                "time_window",
                "requests_per_minute",
                "failed_requests",
                "error_rate",
                "prediction",
                "anomaly_score"
            ]
        ]
    )

    # Create model directory
    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    # Save model
    joblib.dump(
        model,
        MODEL_PATH
    )

    # Save scaler
    joblib.dump(
        scaler,
        SCALER_PATH
    )

    print("\nModels saved:")

    print(MODEL_PATH)

    print(SCALER_PATH)


if __name__ == "__main__":
    train_model()