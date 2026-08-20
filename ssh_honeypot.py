import socket
from datetime import datetime

LOG_FILE = "honeypot.log"
HOST = "0.0.0.0"
PORT = 2222

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"[+] SSH Honeypot Running on port {PORT}")

while True:
    client, addr = server.accept()
    ip = addr[0]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    client.send(b"Username: ")
    username = client.recv(50).decode().strip()

    client.send(b"Password: ")
    password = client.recv(50).decode().strip()

    lat, lon, country, city, agent = "N/A", "N/A", "N/A", "N/A", "N/A"

    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp},{ip},{PORT},{lat},{lon},{country},{city},{username},{password},{agent}\n")

    client.send(b"Access Denied\n")
    client.close()
