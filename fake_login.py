from flask import Flask, request, render_template_string
from datetime import datetime
import requests
import os
import csv

app = Flask(__name__)

LOG_FILE = "honeypot.log"


# Create log file if it doesn't exist
if not os.path.exists(LOG_FILE):
    open(LOG_FILE, "a").close()


def get_location(ip):
    """
    Get approximate geographic information for an IP address.
    Private/local IPs such as 127.0.0.1 will return Unknown.
    """

    try:
        # Don't send private/local IPs to the GeoIP service
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


def log_attempt(username, password, ip, user_agent):
    """
    Store web login attempt using the common honeypot log format.
    """

    country, city, lat, lon = get_location(ip)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            ip,
            "WEB",
            username,
            password,
            user_agent,
            country,
            city,
            lat,
            lon
        ])


HTML = """
<!DOCTYPE html>
<html>

<head>
    <title>Secure Login</title>

    <style>
        body {
            background-color: #111;
            color: white;
            font-family: Arial;
            text-align: center;
            padding-top: 100px;
        }

        .login-box {
            width: 350px;
            margin: auto;
            background: #222;
            padding: 30px;
            border-radius: 10px;
        }

        input {
            width: 90%;
            padding: 12px;
            margin: 10px;
            border-radius: 5px;
            border: none;
        }

        button {
            padding: 12px 30px;
            background: orange;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }

        button:hover {
            background: darkorange;
        }

        .error {
            color: red;
        }
    </style>
</head>

<body>

<div class="login-box">

    <h2>Secure Login</h2>

    <form method="POST">

        <input
            name="username"
            placeholder="Username"
            required
        />

        <input
            type="password"
            name="password"
            placeholder="Password"
            required
        />

        <br>

        <button type="submit">
            Login
        </button>

    </form>

    {% if message %}
        <p class="error">{{ message }}</p>
    {% endif %}

</div>

</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():

    message = None

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Get connecting IP
        ip = request.remote_addr or "Unknown"

        # User-Agent
        user_agent = request.headers.get(
            "User-Agent",
            "Unknown"
        )

        # Record the attack
        log_attempt(
            username,
            password,
            ip,
            user_agent
        )

        # Never authenticate
        message = "Invalid credentials"

    return render_template_string(
        HTML,
        message=message
    )


if __name__ == "__main__":

    print("[+] Web Honeypot running on port 8080")

    app.run(
        host="0.0.0.0",
        port=8080
    )
