import sqlite3
import pandas as pd


DATABASE_PATH = "security.db"


def load_security_events():
    connection = sqlite3.connect(DATABASE_PATH)

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

    df = pd.read_sql_query(query, connection)

    connection.close()

    return df


def create_features(df):

    if df.empty:
        return pd.DataFrame()

    # Convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Create one-minute time window
    df["time_window"] = df["timestamp"].dt.floor("min")

    # Mark failed requests
    df["is_failed"] = (
        df["status_code"] >= 400
    ).astype(int)

    # Aggregate behavior by IP and time window
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

    # Error rate
    features["error_rate"] = (
        features["failed_requests"]
        / features["requests_per_minute"]
    )

    # Replace possible NaN/inf values
    features = features.replace(
        [float("inf"), float("-inf")],
        0
    )

    features = features.fillna(0)

    return features


if __name__ == "__main__":

    print("Loading security events...")

    events = load_security_events()

    print(
        f"Loaded {len(events)} security events."
    )

    features = create_features(events)

    print("\nGenerated features:")

    print(features)

    print("\nFeature columns:")

    print(
        list(features.columns)
    )