from flask import Flask, request, render_template, redirect, url_for, session, jsonify, Response
import time
from collections import defaultdict
import os
import csv
import joblib  # add near the top imports if not present
from sklearn.preprocessing import StandardScaler  # Required for scaling features

RULE_BASED_THRESHOLD = 30

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev')

# Global traffic data
traffic_data = []


import datetime
import statistics

def extract_features(ip_requests):
    times = sorted(r['time'] for r in ip_requests)
    intervals = [t2 - t1 for t1, t2 in zip(times, times[1:])]
    avg_interval = sum(intervals) / len(intervals) if intervals else 0
    std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
    endpoints = {r.get('path', '/') for r in ip_requests}
    honeypot_hits = sum(1 for r in ip_requests if r.get('honeypot_triggered'))
    return [
        len(ip_requests),
        avg_interval,
        std_dev,
        len(endpoints),
        honeypot_hits / len(ip_requests) if ip_requests else 0
    ]

def aggregate_graph_data(entries):
    bucketed = defaultdict(int)
    for r in entries:
        t = datetime.datetime.fromtimestamp(r['time'])
        label = t.strftime('%H:%M:%S')
        bucketed[label] += 1
    sorted_items = sorted(bucketed.items())
    timestamps = [item[0] for item in sorted_items]
    counts = [item[1] for item in sorted_items]
    return {"timestamps": timestamps, "counts": counts}

# Aggregate unique IPs per time bucket for ML graph data
def aggregate_unique_ips_graph_data(entries):
    bucketed = defaultdict(set)  # use set to track unique IPs per timestamp
    for r in entries:
        t = datetime.datetime.fromtimestamp(r['time'])
        label = t.strftime('%H:%M:%S')
        ip = r.get("ip", "unknown")
        bucketed[label].add(ip)
    sorted_items = sorted(bucketed.items())
    timestamps = [item[0] for item in sorted_items]
    counts = [len(item[1]) for item in sorted_items]  # count unique IPs
    return {"timestamps": timestamps, "counts": counts}

# Try to load ML model
MODEL_PATH = "ddos_model.pkl"
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print(f"✅ ML model loaded from {MODEL_PATH}")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
else:
    print(f"⚠️ Model file {MODEL_PATH} not found. ML detection disabled.")

# Try to load scaler
SCALER_PATH = "ddos_scaler.pkl"
scaler = None
if os.path.exists(SCALER_PATH):
    try:
        scaler = joblib.load(SCALER_PATH)
        print(f"✅ Scaler loaded from {SCALER_PATH}")
    except Exception as e:
        print(f"❌ Failed to load scaler: {e}")
else:
    print(f"⚠️ Scaler file {SCALER_PATH} not found. ML detection may misbehave.")

@app.route('/log', methods=['POST'])
def receive_log():
    data = request.get_json()
    print("Received log:", data)
    if data:
        entry = {
            "ip": data.get("ip", "unknown"),
            "time": data.get("time", time.time()),
            "path": data.get("path", ""),
            "user_agent": data.get("user_agent", ""),
            "honeypot_triggered": data.get("honeypot_triggered", False)
        }
        traffic_data.append(entry)
    return '', 204

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('html_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'password':
            session['logged_in'] = True
            return redirect(url_for('html_dashboard'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/dashboard')
def html_dashboard():
    now = time.time()
    recent = [r for r in traffic_data if now - r.get("time", 0) < 300]
    ip_counts = defaultdict(int)
    ip_stats = defaultdict(list)
    for r in recent:
        ip_counts[r.get("ip", "unknown")] += 1
        ip_stats[r.get("ip", "unknown")].append(r)

    ddos_ips = [ip for ip, count in ip_counts.items() if count > RULE_BASED_THRESHOLD]
    ddos_ip_counts = {ip: ip_counts[ip] for ip in ddos_ips}
    honeypot_hits = sum(1 for r in recent if r.get("honeypot_triggered"))
    honeypot_ips = list({r.get("ip", "unknown") for r in recent if r.get("honeypot_triggered")})

    ml_detected = {}
    if model and scaler:
        for ip, reqs in ip_stats.items():
            if ip == '127.0.0.1':
                continue
            features = extract_features(reqs)
            expected_features = scaler.mean_.shape[0]
            if len(features) == expected_features:
                scaled_features = scaler.transform([features])
            else:
                scaled_features = [features]
            proba = model.predict_proba(scaled_features)[0]
            prob = proba[1] if len(proba) == 2 else 0
            if prob >= 0.5:
                ml_detected[ip] = "DDoS"

    ml_recent_ips = set(r['ip'] for r in recent if r.get('ip') in ml_detected)
    ml_count = len(ml_recent_ips)

    ml_graph_data = {
        "timestamps": ["Last 5 min"],
        "counts": [ml_count]
    }

    honeypot_graph_data = aggregate_graph_data([r for r in recent if r.get("honeypot_triggered")])

    ip_labels = list(ddos_ip_counts.keys())
    ip_values = list(ddos_ip_counts.values())

    bot_ips = set(ddos_ips) | set(ml_detected.keys()) | set(honeypot_ips)
    bot_ips = set(ddos_ips) | set(ml_detected.keys()) | set(honeypot_ips)
    total_bot_requests = sum(1 for r in recent if (r.get("honeypot_triggered") or r.get("ip") in bot_ips))

    # Debug print statements and fallback for ML graph data
    print("Dashboard: Recent traffic count:", len(recent))
    print("Dashboard: ML detected IPs:", ml_detected)
    print("Dashboard: ML Graph Data:", ml_graph_data)

    if not ml_graph_data["timestamps"]:
        ml_graph_data = {"timestamps": ["No Data"], "counts": [0]}

    return render_template("dashboard.html",
                           total=len(recent),
                           logs=traffic_data[-5:],
                           ddos_ips=ddos_ips,
                           ddos_ip_counts=ddos_ip_counts,
                           ml_detected=ml_detected,
                           ml_count=ml_count,
                           honeypot_hits=honeypot_hits,
                           honeypot_ips=honeypot_ips,
                           ip_labels=ip_labels,
                           ip_values=ip_values,
                           ml_graph_data=ml_graph_data,
                           honeypot_graph_data=honeypot_graph_data,
                           total_bot_requests=total_bot_requests)

# --- New routes below ---

# Rule-based detection route
@app.route('/rule_based')
def rule_based():
    now = time.time()
    recent = [r for r in traffic_data if now - r.get("time", 0) < 300]
    ip_counts = defaultdict(int)
    for r in recent:
        ip_counts[r.get("ip", "unknown")] += 1
    ddos_ips = [ip for ip, count in ip_counts.items() if count > RULE_BASED_THRESHOLD]
    ddos_ips = [ip for ip in ddos_ips if ip != '127.0.0.1']
    ddos_ip_counts = {ip: ip_counts[ip] for ip in ddos_ips}
    ip_labels = list(ddos_ip_counts.keys())
    ip_values = list(ddos_ip_counts.values())
    return render_template("rule_based.html", ddos_ips=ddos_ips, ip_labels=ip_labels, ip_values=ip_values)

# ML-based detection route
@app.route('/ml_based')
def ml_based():
    now = time.time()
    recent = [r for r in traffic_data if now - r.get("time", 0) < 300]
    ml_detected = {}
    if model:
        ip_stats = defaultdict(list)
        for r in recent:
            ip_stats[r.get("ip", "unknown")].append(r)
        for ip, reqs in ip_stats.items():
            if ip == '127.0.0.1':
                continue
            features = extract_features(reqs)
            if scaler and model:
                expected_features = scaler.mean_.shape[0]
                if len(features) == expected_features:
                    scaled_features = scaler.transform([features])
                else:
                    print(f"⚠️ Feature count mismatch: got {len(features)}, scaler expects {expected_features}. Using unscaled features.")
                    scaled_features = [features]
                proba = model.predict_proba(scaled_features)[0]
            else:
                print("⚠️ Scaler or model not loaded properly. Skipping ML detection.")
                proba = [0, 0]
            print(f"IP: {ip}, Probabilities: {proba}")
            if len(proba) == 2:
                prob = proba[1]
            else:
                prob = 0
            print(f"IP: {ip}, Bot Probability: {prob}")
            if prob >= 0.5:  # lowered threshold for debugging
                print(f"ML detected bot: {ip}")
                ml_detected[ip] = "DDoS"
        print("ML detected IPs:", ml_detected)
    ml_graph_data = aggregate_graph_data([r for r in recent if r.get("ip") in ml_detected]) if ml_detected else {"timestamps": [], "counts": []}
    return render_template("ml_based.html", ml_detected=ml_detected, ml_graph_data=ml_graph_data)


# Honeycap (honeypot) route
@app.route('/honeycap')
def honeycap():
    now = time.time()
    recent = [r for r in traffic_data if now - r.get("time", 0) < 300]
    honeypot_entries = [r for r in recent if r.get("honeypot_triggered")]
    honeypot_hits = len(honeypot_entries)
    honeypot_ips = list({r.get("ip", "unknown") for r in honeypot_entries})
    honeypot_graph_data = aggregate_graph_data(honeypot_entries)

    print("Honeycap: Hits:", honeypot_hits)
    print("Honeycap: Unique IPs:", honeypot_ips)
    print("Honeycap: Graph Data:", honeypot_graph_data)

    if not honeypot_graph_data["timestamps"]:
        honeypot_graph_data = {"timestamps": ["No Data"], "counts": [0]}

    return render_template("honeycap.html",
                           honeypot_hits=honeypot_hits,
                           honeypot_ips=honeypot_ips,
                           honeypot_graph_data=honeypot_graph_data)


# Export logs as CSV
@app.route('/export')
def export_logs():
    def generate():
        data = [['IP', 'Time', 'Path', 'User Agent', 'Honeypot Triggered']]
        for entry in traffic_data:
            row = [
                entry.get("ip", ""),
                entry.get("time", ""),
                entry.get("path", ""),
                entry.get("user_agent", ""),
                "Yes" if entry.get("honeypot_triggered") else "No"
            ]
            data.append(row)
        output = ""
        for row in data:
            output += ','.join(map(str, row)) + '\n'
        return output
    return Response(generate(), mimetype='text/csv',
                    headers={"Content-Disposition": "attachment;filename=traffic_logs.csv"})



# --- API route for summary for JS dynamic refresh ---
@app.route('/api/summary')
def api_summary():
    now = time.time()
    recent = [r for r in traffic_data if now - r.get("time", 0) < 300]
    ip_counts = defaultdict(int)
    ip_stats = defaultdict(list)
    for r in recent:
        ip_counts[r.get("ip", "unknown")] += 1
        ip_stats[r.get("ip", "unknown")].append(r)
    ddos_ips = [ip for ip, count in ip_counts.items() if count > RULE_BASED_THRESHOLD]
    honeypot_hits = sum(1 for r in recent if r.get("honeypot_triggered"))
    honeypot_ips = list({r.get("ip", "unknown") for r in recent if r.get("honeypot_triggered")})
    ml_detected = {}
    if model:
        for ip, reqs in ip_stats.items():
            if ip == '127.0.0.1':
                continue
            features = extract_features(reqs)
            if scaler and model:
                expected_features = scaler.mean_.shape[0]
                if len(features) == expected_features:
                    scaled_features = scaler.transform([features])
                else:
                    print(f"⚠️ Feature count mismatch: got {len(features)}, scaler expects {expected_features}. Using unscaled features.")
                    scaled_features = [features]
                proba = model.predict_proba(scaled_features)[0]
            else:
                print("⚠️ Scaler or model not loaded properly. Skipping ML detection.")
                proba = [0, 0]
            if len(proba) == 2:
                prob = proba[1]
            else:
                prob = 0
            if prob >= 0.5:
                ml_detected[ip] = "DDoS"
    return jsonify({
        "total": len(recent),
        "honeypot_hits": honeypot_hits,
        "rule_count": len(ddos_ips),
        "ml_count": len(ml_detected)
    })


# --- API route for chart data ---
@app.route('/api/chart_data')
def api_chart_data():
    now = time.time()
    # Increase recent window from 5 min (300s) to 10 min (600s)
    recent = [r for r in traffic_data if now - r.get("time", 0) < 600]
    
    ip_counts = defaultdict(int)
    ip_stats = defaultdict(list)
    for r in recent:
        ip_counts[r.get("ip", "unknown")] += 1
        ip_stats[r.get("ip", "unknown")].append(r)

    ddos_ips = [ip for ip, count in ip_counts.items() if count > RULE_BASED_THRESHOLD and ip != '127.0.0.1']
    ddos_ip_counts = {ip: ip_counts[ip] for ip in ddos_ips}

    honeypot_hits = sum(1 for r in recent if r.get("honeypot_triggered"))
    honeypot_ips = list({r.get("ip", "unknown") for r in recent if r.get("honeypot_triggered")})

    ml_detected = {}
    if model and scaler:
        for ip, reqs in ip_stats.items():
            if ip == '127.0.0.1':
                continue
            features = extract_features(reqs)
            expected_features = scaler.mean_.shape[0]
            if len(features) == expected_features:
                scaled_features = scaler.transform([features])
            else:
                print(f"⚠️ Feature count mismatch: got {len(features)}, scaler expects {expected_features}. Using unscaled features.")
                scaled_features = [features]
            proba = model.predict_proba(scaled_features)[0]
            prob = proba[1] if len(proba) == 2 else 0
            if prob >= 0.5:
                ml_detected[ip] = "DDoS"
    else:
        if not model or not scaler:
            print("⚠️ Scaler or model not loaded properly. Skipping ML detection.")

    ml_ips = set(ml_detected.keys())

    ml_count = len(ml_ips)
    ml_graph_data = {
        "timestamps": ["Last 10 min"],
        "counts": [ml_count]
    }
    honeypot_graph_data = aggregate_graph_data([r for r in recent if r.get("honeypot_triggered")])

    ip_labels = list(ddos_ip_counts.keys())
    ip_values = list(ddos_ip_counts.values())

    bot_ips = set(ddos_ips) | set(ml_detected.keys()) | set(honeypot_ips)
    total_bot_requests = sum(1 for r in recent if (r.get("honeypot_triggered") or r.get("ip") in bot_ips))

    print("Pie Chart Update -> Total:", len(recent), "Bot Requests:", total_bot_requests)

    # Debug print statements and fallback for ML graph data
    print("API: Recent traffic count:", len(recent))
    print("API: ML detected IPs:", ml_detected)
    print("API: ML Graph Data:", ml_graph_data)

    if not ml_graph_data["timestamps"]:
        ml_graph_data = {"timestamps": ["No Data"], "counts": [0]}

    return jsonify({
        "ip_labels": ip_labels,
        "ip_values": ip_values,
        "ml_graph_data": ml_graph_data,
        "honeypot_graph_data": honeypot_graph_data,
        "total": len(recent),
        "total_bot_requests": total_bot_requests,
        "honeypot_hits": honeypot_hits,
        "rule_count": len(ddos_ips),
        "ml_count": ml_count,
    })

if __name__ == '__main__':
    app.run(debug=True, port=5001)