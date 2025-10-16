import json
import csv
import statistics
from collections import defaultdict

def extract_features(ip_requests):
    times = sorted(r['time'] for r in ip_requests if 'time' in r)
    if not times:
        return [0, 0, 0, 0, 0]
    intervals = [t2 - t1 for t1, t2 in zip(times, times[1:])]
    avg_interval = sum(intervals) / len(intervals) if intervals else 0
    std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
    endpoints = {r.get('path', '/') for r in ip_requests}
    honeypot_hits = sum(1 for r in ip_requests if r.get('honeypot_triggered', False))
    return [
        len(ip_requests),
        avg_interval,
        std_dev,
        len(endpoints),
        honeypot_hits / len(ip_requests) if ip_requests else 0
    ]

def main():
    # Load traffic data from JSON file
    with open("traffic_data.json", "r") as f:
        traffic_data = json.load(f)

    # Group requests by IP address
    ip_requests_map = defaultdict(list)
    for req in traffic_data:
        ip = req.get("ip", None)
        if ip is None or 'time' not in req:
            continue  # skip malformed entries
        ip_requests_map[ip].append(req)

    # Label IPs as bots if any request triggered honeypot
    bot_ips = set(ip for ip, reqs in ip_requests_map.items()
                  if any(r.get("honeypot_triggered", False) for r in reqs))

    # Write features and labels to CSV
    with open("training_data.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "num_requests", "avg_interval", "std_dev_interval",
            "unique_endpoints", "honeypot_hit_ratio", "label"
        ])
        for ip, reqs in ip_requests_map.items():
            features = extract_features(reqs)
            label = 1 if ip in bot_ips else 0
            writer.writerow(features + [label])

    print("✅ training_data.csv created successfully.")

if __name__ == "__main__":
    main()