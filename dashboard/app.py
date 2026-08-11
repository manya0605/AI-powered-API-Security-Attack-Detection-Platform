import streamlit as st
import requests
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

API_URL = "http://127.0.0.1:8000"


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI API Security Platform",
    page_icon="🔐",
    layout="wide"
)


# ============================================================
# HEADER
# ============================================================

st.title("🔐 AI API Security & Attack Detection Platform")

st.markdown(
    """
    **AI-powered API monitoring, behavioral anomaly detection,
    risk scoring and security analytics**
    """
)

st.divider()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.header("🔑 Authentication")

token = st.sidebar.text_input(
    "JWT Access Token",
    type="password"
)

st.sidebar.markdown("---")

st.sidebar.info(
    """
    *AI Engine*

    Model: Isolation Forest

    Detection type:
    Behavioral anomaly detection
    """
)


# ============================================================
# HELPER FUNCTION
# ============================================================

def get_security_analysis():

    if not token:
        return None, "Please enter your JWT token."

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:

        response = requests.get(
            f"{API_URL}/api/security/detect",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:

            return response.json(), None

        return None, (
            f"API returned "
            f"{response.status_code}: "
            f"{response.text}"
        )

    except requests.RequestException as e:

        return None, str(e)


# ============================================================
# REFRESH / ANALYZE BUTTON
# ============================================================

if st.button(
    "🔍 Analyze Current API Behavior",
    use_container_width=True
):

    data, error = get_security_analysis()

    if error:

        st.error(error)

    else:

        st.session_state["security_data"] = data


# ============================================================
# DISPLAY RESULTS
# ============================================================

if "security_data" not in st.session_state:

    st.info(
        "Enter your JWT token and click "
        "*Analyze Current API Behavior*."
    )

else:

    data = st.session_state["security_data"]

    analysis = data.get(
        "ai_security_analysis",
        {}
    )

    if analysis.get("status") != "analysis_complete":

        st.warning(
            analysis.get(
                "message",
                "Insufficient data."
            )
        )

    else:

        # ----------------------------------------------------
        # MAIN VALUES
        # ----------------------------------------------------

        risk_score = analysis.get(
            "risk_score",
            0
        )

        severity = analysis.get(
            "severity",
            "UNKNOWN"
        )

        is_anomaly = analysis.get(
            "is_anomaly",
            False
        )

        action = analysis.get(
            "recommended_action",
            "UNKNOWN"
        )

        attack_type = analysis.get(
          "attack_type",
          "Unknown"
        )

        client_ip = analysis.get(
            "client_ip",
            "Unknown"
        )

        model = analysis.get(
            "model",
            "Unknown"
        )

        behavior = analysis.get(
            "behavior",
            {}
        )

        reasons = analysis.get(
            "reasons",
            []
        )


        # ----------------------------------------------------
        # SECURITY STATUS
        # ----------------------------------------------------

        if is_anomaly:

            st.error(
                "🚨 AI ANOMALY DETECTED"
            )

        else:

            st.success(
                "🟢 API BEHAVIOR APPEARS NORMAL"
            )


        st.divider()


        # ----------------------------------------------------
        # METRICS
        # ----------------------------------------------------

        col1, col2, col3, col4 = st.columns(4)


        with col1:

            st.metric(
                "Risk Score",
                f"{risk_score}/100"
            )


        with col2:

            st.metric(
                "Severity",
                severity
            )


        with col3:

            st.metric(
                "Requests / Minute",
                behavior.get(
                    "requests_per_minute",
                    0
                )
            )


        with col4:

            st.metric(
                "Failed Requests",
                behavior.get(
                    "failed_requests",
                    0
                )
            )


        st.divider()


        # ----------------------------------------------------
        # SECURITY INFORMATION
        # ----------------------------------------------------

        col1, col2 = st.columns(2)


        with col1:

            st.subheader(
                "🛡️ Security Decision"
            )

            st.write(
                f"**Recommended Action:** "
                f"{action}"
            )

            st.write(
               f"*Attack Type:* "
               f"{attack_type}"
            )

            st.write(
                f"**Client IP:** "
                f"{client_ip}"
            )

            st.write(
                f"**ML Model:** "
                f"{model}"
            )


        with col2:

            st.subheader(
                "📊 Behavioral Metrics"
            )

            metrics = {

                "Requests per minute":
                    behavior.get(
                        "requests_per_minute",
                        0
                    ),

                "Failed requests":
                    behavior.get(
                        "failed_requests",
                        0
                    ),

                "Unique endpoints":
                    behavior.get(
                        "unique_endpoints",
                        0
                    ),

                "Average response time":
                    behavior.get(
                        "average_response_time_ms",
                        0
                    ),

                "Error rate":
                    behavior.get(
                        "error_rate",
                        0
                    )
            }

            for name, value in metrics.items():

                st.write(
                    f"*{name}:* {value}"
                )


        st.divider()


        # ----------------------------------------------------
        # THREAT REASONS
        # ----------------------------------------------------

        st.subheader(
            "🔎 AI Detection Reasoning"
        )

        if reasons:

            for reason in reasons:

                if is_anomaly:

                    st.warning(
                        f"⚠️ {reason}"
                    )

                else:

                    st.info(
                        f"ℹ️ {reason}"
                    )

        else:

            st.success(
                "No suspicious behavioral indicators."
            )


        st.divider()


        # ----------------------------------------------------
        # FEATURE VISUALIZATION
        # ----------------------------------------------------

        st.subheader(
            "📈 Behavioral Feature Analysis"
        )

        chart_data = pd.DataFrame({

            "Feature": [

                "Requests / min",
                "Failed requests",
                "Unique endpoints",
                "Response time (ms)",
                "Error rate"
            ],

            "Value": [

                behavior.get(
                    "requests_per_minute",
                    0
                ),

                behavior.get(
                    "failed_requests",
                    0
                ),

                behavior.get(
                    "unique_endpoints",
                    0
                ),

                behavior.get(
                    "average_response_time_ms",
                    0
                ),

                behavior.get(
                    "error_rate",
                    0
                )
            ]
        })

        st.bar_chart(
            chart_data.set_index(
                "Feature"
            )
        )


        st.divider()


        # ----------------------------------------------------
        # RAW AI RESPONSE
        # ----------------------------------------------------

        with st.expander(
            "🔬 View Raw AI Security Analysis"
        ):

            st.json(
                analysis
            )