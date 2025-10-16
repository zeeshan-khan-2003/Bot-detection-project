from flask import Flask, render_template, request, abort, redirect
import requests
import time

app = Flask(__name__)

DASHBOARD_URL = "http://127.0.0.1:5001/log"

@app.before_request
def log_request_info():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    print(f"Received {request.method} request for {request.path} from {ip}")

@app.route('/')
def home():
    return "Welcome to the Real Website!"

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    try:
        if request.method == 'POST':
            honeypot = request.form.get('honeypot')
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)

            log_data = {
                "ip": ip,
                "time": time.time(),
                "honeypot_triggered": honeypot is not None and honeypot != '',
                "path": "/login",
                "user_agent": request.headers.get("User-Agent"),
            }
            try:
                requests.post(DASHBOARD_URL, json=log_data, timeout=0.5)
            except Exception as e:
                print(f"Failed to send log data to dashboard: {e}")

            if honeypot:
                error = "Bot detected! Access denied."
            else:
                username = request.form.get('username')
                password = request.form.get('password')
                if username == 'user' and password == 'pass':
                    return redirect('/home')
                else:
                    error = "Invalid credentials."

        return render_template('login.html', error=error)
    except Exception as e:
        print(f"Error handling /login: {e}")
        abort(500)

@app.route('/home')
def home_page():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    honeypot = request.headers.get("X-Honeypot-Triggered", "false").lower() == "true"
    log_data = {
        "ip": ip,
        "time": time.time(),
        "path": "/home",
        "honeypot_triggered": honeypot,
        "user_agent": request.headers.get("User-Agent"),
    }
    try:
        requests.post(DASHBOARD_URL, json=log_data, timeout=0.5)
    except Exception:
        pass
    return render_template("home.html")

@app.route('/profile')
def profile_page():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    honeypot = request.headers.get("X-Honeypot-Triggered", "false").lower() == "true"
    log_data = {
        "ip": ip,
        "time": time.time(),
        "path": "/profile",
        "honeypot_triggered": honeypot,
        "user_agent": request.headers.get("User-Agent"),
    }
    try:
        requests.post(DASHBOARD_URL, json=log_data, timeout=0.5)
    except Exception:
        pass
    return render_template("profile.html")

@app.route('/search')
def search_page():
    query = request.args.get('q')
    results = []
    if query:
        results = [
            f"Search result 1 for '{query}'",
            f"Search result 2 related to '{query}'",
            f"Related article: Understanding '{query}'",
        ]
    # Log to dashboard
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    honeypot = request.headers.get("X-Honeypot-Triggered", "false").lower() == "true"
    log_data = {
        "ip": ip,
        "time": time.time(),
        "path": "/search",
        "query": query,
        "user_agent": request.headers.get('User-Agent'),
        "honeypot_triggered": honeypot,
    }
    try:
        requests.post(DASHBOARD_URL, json=log_data, timeout=0.5)
    except Exception:
        pass

    return render_template("search.html", results=results, query=query)

if __name__ == '__main__':
    app.run(port=5000 , debug=True)