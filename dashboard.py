from flask import Flask, render_template_string
import csv
import folium
import os


app = Flask(__name__)

LOG_FILE = "honeypot.log"

TEMPLATE_DIR = "templates"

MAP_FILE = os.path.join(
    TEMPLATE_DIR,
    "map.html"
)


# Create templates directory
os.makedirs(
    TEMPLATE_DIR,
    exist_ok=True
)


dashboard_html = """
<!DOCTYPE html>

<html>

<head>

    <title>HoneyLogin Dashboard</title>

    <meta
        http-equiv="refresh"
        content="5"
    >

    <style>

        body {
            background-color: #111;
            color: white;
            font-family: Arial;
            margin: 0;
            padding: 20px;
        }

        h1 {
            text-align: center;
        }

        .stats {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin: 20px;
        }

        .card {
            background: #222;
            padding: 20px;
            border-radius: 10px;
            min-width: 150px;
            text-align: center;
        }

        table {
            width: 95%;
            margin: auto;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th,
        td {
            border: 1px solid #555;
            padding: 8px;
            text-align: center;
        }

        th {
            background-color: #333;
        }

        tr:nth-child(even) {
            background-color: #222;
        }

        iframe {
            display: block;
            width: 95%;
            height: 500px;
            border: none;
            margin: 20px auto;
        }

    </style>

</head>


<body>

    <h1>
        🛡 HoneyLogin Honeypot Dashboard
    </h1>


    <div class="stats">

        <div class="card">
            <h3>Total Attempts</h3>
            <h2>{{ total_attempts }}</h2>
        </div>

        <div class="card">
            <h3>Web Attacks</h3>
            <h2>{{ web_attacks }}</h2>
        </div>

        <div class="card">
            <h3>SSH Attacks</h3>
            <h2>{{ ssh_attacks }}</h2>
        </div>

    </div>


    <iframe src="/map"></iframe>


    <h2 style="text-align:center;">
        Attack Logs
    </h2>


    <table>

        <tr>

            <th>Timestamp</th>
            <th>IP Address</th>
            <th>Service</th>
            <th>Username</th>
            <th>Password</th>
            <th>Country</th>
            <th>City</th>

        </tr>


        {% for row in logs %}

        <tr>

            <td>
                {{ row.timestamp }}
            </td>

            <td>
                {{ row.ip }}
            </td>

            <td>
                {{ row.service }}
            </td>

            <td>
                {{ row.username }}
            </td>

            <td>
                {{ row.password }}
            </td>

            <td>
                {{ row.country }}
            </td>

            <td>
                {{ row.city }}
            </td>

        </tr>

        {% endfor %}

    </table>

</body>

</html>
"""


def read_logs():

    logs = []

    if not os.path.exists(LOG_FILE):
        return logs

    try:

        with open(
            LOG_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.reader(file)

            for row in reader:

                # New format contains 10 columns
                if len(row) != 10:
                    continue

                (
                    timestamp,
                    ip,
                    service,
                    username,
                    password,
                    user_agent,
                    country,
                    city,
                    lat,
                    lon
                ) = row

                try:

                    lat = float(lat)
                    lon = float(lon)

                except ValueError:

                    lat = 0.0
                    lon = 0.0

                logs.append({

                    "timestamp": timestamp,

                    "ip": ip,

                    "service": service,

                    "username": username,

                    "password": password,

                    "user_agent": user_agent,

                    "country": country,

                    "city": city,

                    "lat": lat,

                    "lon": lon

                })

    except Exception as e:

        print(
            f"[-] Error reading log: {e}"
        )

    return logs


def create_map():

    attacker_map = folium.Map(
        location=[20, 0],
        zoom_start=2
    )

    logs = read_logs()

    for log in logs:

        lat = log["lat"]
        lon = log["lon"]

        # Don't add marker for unknown coordinates
        if lat == 0 and lon == 0:
            continue

        popup_text = (
            f"<b>IP:</b> {log['ip']}<br>"
            f"<b>Service:</b> {log['service']}<br>"
            f"<b>Username:</b> {log['username']}<br>"
            f"<b>Country:</b> {log['country']}<br>"
            f"<b>City:</b> {log['city']}"
        )

        folium.Marker(
            location=[
                lat,
                lon
            ],
            popup=popup_text,
            tooltip=(
                f"{log['ip']} - "
                f"{log['service']}"
            ),
            icon=folium.Icon(
                color="red"
            )
        ).add_to(attacker_map)

    attacker_map.save(
        MAP_FILE
    )


@app.route("/")
def index():

    logs = read_logs()

    create_map()

    total_attempts = len(logs)

    web_attacks = sum(
        1
        for log in logs
        if log["service"] == "WEB"
    )

    ssh_attacks = sum(
        1
        for log in logs
        if log["service"] == "SSH"
    )

    return render_template_string(
        dashboard_html,
        logs=logs,
        total_attempts=total_attempts,
        web_attacks=web_attacks,
        ssh_attacks=ssh_attacks
    )


@app.route("/map")
def map_page():

    create_map()

    if not os.path.exists(MAP_FILE):
        return "Map not available"

    with open(
        MAP_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return file.read()


if __name__ == "__main__":

    print(
        "[+] Dashboard running on port 5000"
    )

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
