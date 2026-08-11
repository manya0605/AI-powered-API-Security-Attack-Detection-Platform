import time
import random
import requests


BASE_URL = "http://127.0.0.1:8000"


def normal_traffic(token):
    """Simulate normal user behavior."""

    headers = {
        "Authorization": f"Bearer {token}"
    }

    endpoints = [
        "/api/profile",
        "/api/data",
        "/health"
    ]

    for _ in range(20):

        endpoint = random.choice(endpoints)

        try:
            response = requests.get(
                BASE_URL + endpoint,
                headers=headers,
                timeout=5
            )

            print(
                f"[NORMAL] "
                f"{endpoint} -> {response.status_code}"
            )

        except requests.RequestException as e:
            print(f"Request error: {e}")

        time.sleep(random.uniform(0.5, 2.0))


def suspicious_traffic(token):
    """Simulate controlled abnormal request behavior."""

    headers = {
        "Authorization": f"Bearer {token}"
    }

    # Rapid repeated requests
    for _ in range(100):

        try:
            response = requests.get(
                BASE_URL + "/api/data",
                headers=headers,
                timeout=5
            )

            print(
                f"[BURST] "
                f"/api/data -> {response.status_code}"
            )

        except requests.RequestException as e:
            print(f"Request error: {e}")


def failed_request_burst():
    """Generate controlled failed requests."""

    for _ in range(50):

        try:
            response = requests.get(
                BASE_URL + "/api/nonexistent-endpoint",
                timeout=5
            )

            print(
                f"[FAILED] "
                f"/api/nonexistent-endpoint -> "
                f"{response.status_code}"
            )

        except requests.RequestException as e:
            print(f"Request error: {e}")


if __name__ == "__main__":

    print("\n====================================")
    print(" API SECURITY TRAFFIC SIMULATOR")
    print("====================================\n")

    token = input(
        "Enter your JWT access token: "
    ).strip()

    print("\nChoose traffic type:")
    print("1 - Normal traffic")
    print("2 - Suspicious burst traffic")
    print("3 - Failed request burst")

    choice = input("\nEnter choice: ").strip()

    if choice == "1":

        print("\nGenerating normal traffic...\n")

        normal_traffic(token)

    elif choice == "2":

        print("\nGenerating suspicious burst...\n")

        suspicious_traffic(token)

    elif choice == "3":

        print("\nGenerating failed requests...\n")

        failed_request_burst()

    else:

        print("Invalid choice.")

    print("\nTraffic generation completed.")