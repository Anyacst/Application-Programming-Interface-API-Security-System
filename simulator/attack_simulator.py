import requests
import time

BASE_URL = "http://127.0.0.1:5000"

# ------------------------
# Helper
# ------------------------

def print_header(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def print_result(title, response):
    icon = "✓" if response.status_code < 400 else "✗"

    print(f"\n{icon} {title}")
    print(f"Status : {response.status_code}")

    try:
        print("Response :", response.json())
    except:
        print(response.text)


# ------------------------
# Login
# ------------------------

def login(username, password):

    response = requests.post(
        f"{BASE_URL}/login",
        json={
            "username": username,
            "password": password
        }
    )

    print_result(f"Login ({username})", response)

    if response.status_code == 200:
        return response.json()["token"]

    return None


# ------------------------
# Access Students
# ------------------------

def access_students(token=None, ip=None):

    headers = {}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    if ip:
        headers["X-Forwarded-For"] = ip

    response = requests.get(
        f"{BASE_URL}/students",
        headers=headers
    )

    print_result("GET /students", response)


# ------------------------
# Delete Student
# ------------------------

def delete_student(student_id, token, ip=None):

    headers = {
        "Authorization": f"Bearer {token}"
    }

    if ip:
        headers["X-Forwarded-For"] = ip

    response = requests.delete(
        f"{BASE_URL}/students/{student_id}",
        headers=headers
    )

    print_result("DELETE Student", response)


# ------------------------
# Fake JWT
# ------------------------

def fake_token():

    print_header("Invalid JWT")

    access_students(
        token="this.is.fake.jwt"
    )


# ------------------------
# Missing JWT
# ------------------------

def missing_token():

    print_header("Missing JWT")

    access_students()


# ------------------------
# Invalid Login
# ------------------------

def invalid_login():

    print_header("Invalid Login")

    login(
        "hacker",
        "wrongpassword"
    )


# ------------------------
# Rate Limit
# ------------------------

def rate_limit_attack(token):

    print_header("Rate Limit Attack")

    for i in range(8):

        response = requests.get(
            f"{BASE_URL}/students",
            headers={
                "Authorization": f"Bearer {token}"
            }
        )

        print(
            f"Request {i+1} -> {response.status_code}"
        )


# ------------------------
# Bot Attack
# ------------------------

def bot_attack(token):

    print_header("Bot Attack")

    for i in range(6):

        response = requests.get(
            f"{BASE_URL}/students",
            headers={
                "Authorization": f"Bearer {token}"
            }
        )

        print(
            f"Bot Request {i+1} -> {response.status_code}"
        )

        time.sleep(0.2)


# ------------------------
# Admin Attack
# ------------------------

def admin_attack(student_token):

    print_header("Admin Attack Simulation")

    ips = [
        "203.0.113.5",
        "203.0.113.9",
        "198.51.100.23"
    ]

    for ip in ips:

        for student_id in range(1, 4):

            delete_student(
                student_id,
                student_token,
                ip=ip
            )

            time.sleep(0.2)


# ------------------------
# Distributed Attack
# ------------------------

def distributed_attack():

    print_header("Multiple IP Attack")

    ips = [
        "192.168.1.10",
        "192.168.1.20",
        "192.168.1.30",
        "10.0.0.15",
        "172.16.1.9"
    ]

    for ip in ips:

        for _ in range(6):

            response = requests.post(
                f"{BASE_URL}/login",
                json={
                    "username":"abc",
                    "password":"xyz"
                },
                headers={
                    "X-Forwarded-For":ip
                }
            )

            print(ip, response.status_code)

            time.sleep(0.2)


# ------------------------
# Main
# ------------------------

print_header("API SHIELD ATTACK SIMULATOR")

# -------------------------
# Login
# -------------------------

admin_token = login("admin", "1234")
student_token = login("student1", "abcd")


# -------------------------
# Normal User Traffic
# -------------------------

print_header("Normal User Traffic")

for i in range(5):
    access_students(admin_token)
    time.sleep(0.5)

for i in range(5):
    access_students(student_token)
    time.sleep(0.5)


# -------------------------
# Invalid Login
# -------------------------

invalid_login()

# -------------------------
# Missing JWT
# -------------------------

missing_token()

# -------------------------
# Fake JWT
# -------------------------

fake_token()


# -------------------------
# Student tries Admin Action
# -------------------------

print_header("Student Delete")

delete_student(
    1,
    student_token
)


# -------------------------
# Admin Delete
# -------------------------

print_header("Admin Delete")

delete_student(
    2,
    admin_token
)


# -------------------------
# Admin Attack (repeated unauthorized attempts)
# -------------------------

admin_attack(student_token)


# -------------------------
# Rate Limit Attack
# -------------------------

rate_limit_attack(admin_token)

time.sleep(5)


# -------------------------
# Bot Attack
# -------------------------

bot_attack(admin_token)


# -------------------------
# Distributed Attack
# -------------------------

distributed_attack()

print_header("Simulation Finished")


