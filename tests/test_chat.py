import requests

BASE = "http://127.0.0.1:5000"

s = requests.Session()

# Clean start: attempt to register test user (ignore errors)
r = s.post(BASE + "/register", data={"username":"test_ai","password":"testpass","email":"test@example.com"})
print('Register status', r.status_code)

# Log in
r = s.post(BASE + "/login", data={"username":"test_ai","password":"testpass"})
print('Login status', r.status_code)

# Send chat
r = s.post(BASE + "/chat", json={"message":"Hello, can you help me with my budget?"})
print('Chat status', r.status_code)
try:
    print('Chat response:', r.json())
except Exception:
    print('Chat text:', r.text)
