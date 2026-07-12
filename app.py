from flask import Flask, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from security.auth import generate_token, verify_token
from collections import defaultdict
import time

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

students = [
    {"id": 1, "name": "Aman", "course": "Computer Science", "email": "aman123@gmail.com", "phone": "9876543210"},
    {"id": 2, "name": "Riya", "course": "Information Technology", "email": "riya456@gmail.com", "phone": "9123456789"}
]

activity_log = []
request_timestamps = defaultdict(list)
blocked_ip_counts = defaultdict(int)
suspicious_ips = set()

USERS = [
    {"username": "admin", "password": "1234", "role": "admin"},
    {"username": "student1", "password": "abcd", "role": "student"}
]


def get_client_ip():
    # Use X-Forwarded-For when behind a proxy, otherwise remote_addr.
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def mark_ip_if_suspicious(ip):
    # Add IP to suspicious list after 3 or more blocked events.
    if blocked_ip_counts[ip] >= 3:
        suspicious_ips.add(ip)


def add_activity(event, status, ip=None, blocked=False):
    # Keep a compact event record for dashboard and logs route.
    ip_address = ip or get_client_ip()
    activity_log.append({
        "event": event,
        "status": status,
        "ip": ip_address,
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    })

    if blocked:
        blocked_ip_counts[ip_address] += 1
        mark_ip_if_suspicious(ip_address)


def extract_token():
    # Support both raw token and "Bearer <token>" styles.
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return auth_header.strip()


@app.before_request
def detect_bot_traffic():
    # Bot rule: more than 5 requests from same IP in 3 seconds.
    ip = get_client_ip()
    now = time.time()

    recent = [ts for ts in request_timestamps[ip] if now - ts <= 3]
    recent.append(now)
    request_timestamps[ip] = recent

    if len(recent) > 5:
        add_activity("BOT DETECTED - Suspicious IP", 429, ip=ip, blocked=True)
        return jsonify({"message": "BOT DETECTED - Suspicious IP"}), 429


@app.route('/login', methods=['POST'])
def login():
    # Validate credentials and return JWT with embedded role.
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    for u in USERS:
        if u["username"] == username and u["password"] == password:
            token = generate_token(username, u["role"])
            add_activity("SUCCESS - Login", 200)
            return jsonify({"token": token})

    add_activity("BLOCKED - Invalid credentials", 401, blocked=True)
    return jsonify({"message": "Invalid credentials"}), 401


@app.route('/students', methods=['GET'])
@limiter.limit("10 per minute")
def get_students():
    # Protected route: valid JWT required.
    token = extract_token()

    if not token:
        add_activity("BLOCKED - No Token", 401, blocked=True)
        return jsonify({"message": "Token is missing"}), 401

    payload = verify_token(token)
    if not payload:
        add_activity("BLOCKED - Invalid Token", 401, blocked=True)
        return jsonify({"message": "Invalid or expired token"}), 401

    safe_students = []
    for s in students:
        safe_students.append({
            "id": s["id"],
            "name": s["name"],
            "course": s["course"]
        })

    add_activity("SUCCESS - Data Accessed", 200)
    return jsonify(safe_students)


@app.route('/dashboard')
def dashboard():
    # Serve the live dashboard page.
    return send_from_directory('dashboard', 'index.html')


@app.route('/students/<int:student_id>', methods=['DELETE'])
def delete_student(student_id):
    # Admin-only route: role is read from JWT payload.
    token = extract_token()

    if not token:
        add_activity("BLOCKED - No Token", 401, blocked=True)
        return jsonify({"message": "Token is missing"}), 401

    payload = verify_token(token)
    if not payload:
        add_activity("BLOCKED - Invalid Token", 401, blocked=True)
        return jsonify({"message": "Invalid or expired token"}), 401

    if payload.get("role") != "admin":
        add_activity("BLOCKED - Student tried admin action", 403, blocked=True)
        return jsonify({"message": "Access denied: Admins only"}), 403

    global students
    original_count = len(students)
    students = [s for s in students if s["id"] != student_id]

    if len(students) == original_count:
        add_activity("BLOCKED - Student not found for delete", 404, blocked=True)
        return jsonify({"message": "Student not found"}), 404

    add_activity("SUCCESS - Admin deleted student", 200)
    return jsonify({"message": "Student deleted"}), 200


@app.errorhandler(429)
def handle_rate_limit(_error):
    # Capture limiter blocks so they appear in dashboard and suspicious tracker.
    add_activity("BLOCKED - Rate limit exceeded", 429, blocked=True)
    return jsonify({"message": "Rate limit exceeded. Try again later."}), 429


@app.route('/logs', methods=['GET'])
def get_logs():
    # Return events and summary metrics for dashboard rendering.
    logs = activity_log[-100:]
    successful = sum(1 for log in logs if log["status"] < 400)
    blocked = sum(1 for log in logs if log["status"] >= 400)
    bot_detected = sum(1 for log in logs if "BOT DETECTED" in log["event"])
    bot_logs = [log for log in logs if "BOT DETECTED" in log["event"]]

    return jsonify({
        "logs": logs,
        "summary": {
            "total_requests": len(logs),
            "blocked": blocked,
            "successful": successful,
            "bots_detected": bot_detected
        },
        "bot_logs": bot_logs
    })


@app.route('/suspicious-ips', methods=['GET'])
def get_suspicious_ips():
    # Dedicated API route for suspicious IP list.
    return jsonify({"suspicious_ips": sorted(list(suspicious_ips))})


if __name__ == '__main__':
    app.run(debug=True)