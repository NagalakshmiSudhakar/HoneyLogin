from flask import Flask, request, render_template_string
from datetime import datetime
import requests
import os

app = Flask(__name__)

LOG_FILE = "honeypot.log"
if not os.path.exists(LOG_FILE):
    open(LOG_FILE, "w").close()

def get_location(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon")
        data = r.json()
        if data["status"] == "success":
            return data["country"], data["city"], data["lat"], data["lon"]
    except:
        pass
    return "Unknown", "Unknown", 0, 0


def log_credentials(username, password, ip, agent):
    country, city, lat, lon = get_location(ip)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp},{ip},WEB_PORTAL,{username},{password},{agent},{country},{city},{lat},{lon}\n")


HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
</head>
<body>
    <form method="POST">
        <input name="username" placeholder="Username" required />
        <input type="password" name="password" placeholder="Password" required />
        <button type="submit">Login</button>
    </form>
    {% if message %}<p>{{ message }}</p>{% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    msg = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        agent = request.headers.get("User-Agent")
        log_credentials(username, password, ip, agent)
        msg = "Invalid credentials"
    return render_template_string(HTML, message=msg)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
