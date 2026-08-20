import socket
from datetime import datetime
import requests
import csv
import os


HOST = "0.0.0.0"
PORT = 2222

LOG_FILE = "honeypot.log"


# Create log file if it doesn't exist
if not os.path.exists(LOG_FILE):
    open(LOG_FILE, "a").close()


def get_location(ip):
    """
    Get approximate geographic information for an IP.
    """

    try:

        # Local/private IPs cannot be geolocated
        if ip.startswith(("127.", "10.", "192.168.", "172.")):
            return "Unknown", "Unknown", 0.0, 0.0

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,country,city,lat,lon"
            },
            timeout=5
        )

        data = response.json()

        if data.get("status") == "success":

            return (
                data.get("country", "Unknown"),
                data.get("city", "Unknown"),
                data.get("lat", 0.0),
                data.get("lon", 0.0)
            )

    except Exception:
        pass

    return "Unknown", "Unknown", 0.0, 0.0


def log_attempt(
    ip,
    username,
    password,
    user_agent
):

    country, city, lat, lon = get_location(ip)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(LOG_FILE, "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            ip,
            "SSH",
            username,
            password,
            user_agent,
            country,
            city,
            lat,
            lon
        ])


def start_honeypot():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # Allow quick restart after stopping
    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        (HOST, PORT)
    )

    server.listen(5)

    print(
        f"[+] SSH Honeypot running on port {PORT}"
    )

    print(
        "[+] Waiting for connections..."
    )

    while True:

        client, addr = server.accept()

        ip = addr[0]

        print(
            f"[!] Connection detected from {ip}"
        )

        try:

            # Username prompt
            client.sendall(
                b"Username: "
            )

            username = client.recv(100).decode(
                "utf-8",
                errors="ignore"
            ).strip()

            # Password prompt
            client.sendall(
                b"Password: "
            )

            password = client.recv(100).decode(
                "utf-8",
                errors="ignore"
            ).strip()

            # Socket does not provide HTTP User-Agent
            user_agent = "SSH/Custom-Honeypot"

            # Log attack
            log_attempt(
                ip,
                username,
                password,
                user_agent
            )

            print(
                f"[!] Login attempt: "
                f"{username}:{password}"
            )

            # Always deny access
            client.sendall(
                b"\nAccess Denied\n"
            )

        except Exception as e:

            print(
                f"[-] Connection error: {e}"
            )

        finally:

            client.close()


if __name__ == "__main__":
    start_honeypot()
