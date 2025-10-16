import random
import requests
import time
import json
traffic_log = []

# Real website search URL base
TARGET_URL = "http://127.0.0.1:5000/search"

# Sample search queries to simulate different traffic
search_queries = [
    "ddos attack",
    "network security",
    "firewall rules",
    "python flask",
    "machine learning",
    "bot detection",
    "cloud security",
    "cyber threats",
    "data privacy",
    "ip blocking"
]

def random_ip():
    return f"192.168.1.{random.randint(1, 50)}"

for _ in range(100):  # reduced number of IPs
    ip = random_ip()
    for _ in range(random.randint(5, 50)):  # moderate requests per IP
        query = random.choice(search_queries)
        params = {"q": query}
        headers = {"X-Forwarded-For": ip}
        headers["User-Agent"] = "bot-simulator/1.0"
        # Simulate honeypot trigger with 30% chance
        honeypot_triggered = random.random() < 0.3
        if honeypot_triggered:
            headers["X-Honeypot-Triggered"] = "true"
        try:
            response = requests.get(TARGET_URL, params=params, headers=headers, timeout=1)
            print(f"IP {ip} searched '{query}' status: {response.status_code} | Honeypot triggered: {honeypot_triggered}")
        except Exception as e:
            print(f"Request failed from IP {ip}: {e} | Honeypot triggered: {honeypot_triggered}")
        entry = {
            "ip": ip,
            "time": time.time(),
            "path": f"/search?q={query}",
            "honeypot_triggered": honeypot_triggered
        }
        traffic_log.append(entry)
        time.sleep(random.uniform(0.1, 0.3))

# --- Aggressive bot traffic burst ---
for _ in range(20):  # 20 bot IPs
    ip = f"10.0.0.{random.randint(1, 254)}"
    for _ in range(50):  # 50 rapid-fire requests per bot
        query = "ddos attack"
        params = {"q": query}
        headers = {
            "X-Forwarded-For": ip,
            "User-Agent": "malicious-bot/9.9",
            "X-Honeypot-Triggered": "true"
        }
        try:
            response = requests.get(TARGET_URL, params=params, headers=headers, timeout=1)
            print(f"[BOT] IP {ip} hit '{query}' | Status: {response.status_code}")
        except Exception as e:
            print(f"[BOT] Request failed from IP {ip}: {e}")
        entry = {
            "ip": ip,
            "time": time.time(),
            "path": f"/search?q={query}",
            "honeypot_triggered": True
        }
        traffic_log.append(entry)
        time.sleep(0.01)  # very fast burst


with open("traffic_data.json", "w") as f:
    json.dump(traffic_log, f, indent=2)

print("Saved fake traffic to traffic_data.json")