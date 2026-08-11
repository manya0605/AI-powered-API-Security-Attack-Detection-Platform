import time


# IP -> blocked until timestamp
blocked_ips = {}


def block_ip(client_ip: str, duration_seconds: int = 300):
    """
    Temporarily block an IP address.

    Default block duration:
    300 seconds = 5 minutes
    """

    blocked_ips[client_ip] = (
        time.time() + duration_seconds
    )


def is_ip_blocked(client_ip: str) -> bool:

    if client_ip not in blocked_ips:
        return False

    blocked_until = blocked_ips[client_ip]

    if time.time() < blocked_until:
        return True

    # Block expired
    del blocked_ips[client_ip]

    return False