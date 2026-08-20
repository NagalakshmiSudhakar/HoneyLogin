from flask import Flask, render_template_string
import csv
import folium
import os

app = Flask(__name__)

LOG_FILE = "honeypot.log"
MAP_FILE = "templates/map.html"
TEMPLATE_DIR = "templates"

# Ensure templates folder exists
if not os.path.exists(TEMPLATE_DIR):
    os.makedirs(TEMPLATE_DIR)

# HTML Dashboard Template
dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard</title>
    <meta http-equiv="refresh" content="5">  <!-- Auto refresh every 5 sec -->
    <style>
        body { background-color: #111; color: white; font-family: Arial; text-align: center; }
        h1 { margin-top: 20px; }
        table { width: 90%; margin: auto; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #666; padding: 8px; }
        th { background-color: #333; }
        tr:nth-child(even) { background-color: #222; }
        iframe { width: 90%; height: 500px; border: none; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>🛡 Honeypot Dashboard</h1>
    <iframe src="/map"></iframe>

    <h2>Attack Logs</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>IP Address</th>
            <th>Username</th>
            <th>Password</th>
            <th>Country</th>
            <th>City</th>
        </tr>
        {% for row in logs %}
        <tr>
            <td>{{ row.timestamp }}</td>
            <td>{{ row.ip }}</td>
            <td>{{ row.username }}</td>
            <td>{{ row.password }}</td>
            <td>{{ row.country }}</td>
            <td>{{ row.city }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

def create_map():
    """ Generates/upates the dynamic world map """
    attacker_map = folium.Map(location=[20, 0], zoom_start=2)

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) < 7:  # safety check
                    continue
                timestamp, ip, username, password, country, city, coords = row
                lat, lon = [float(i) for i in coords.split(",")]
                folium.Marker(
                    [lat, lon],
                    popup=f"{ip} ({city}, {country})",
                    icon=folium.Icon(color="red")
                ).add_to(attacker_map)

    attacker_map.save(MAP_FILE)


def read_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) < 7:
                    continue
                timestamp, ip, username, password, country, city, coords = row
                logs.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "username": username,
                    "password": password,
                    "country": country,
                    "city": city
                })
    return logs


@app.route("/")
def index():
    create_map()
    logs = read_logs()
    return render_template_string(dashboard_html, logs=logs)


@app.route("/map")
def map_page():
    create_map()
    return open(MAP_FILE).read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
