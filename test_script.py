import requests

response = requests.post(
    "http://localhost:8000/key_packages/alice",
    data=kp_bytes
)
print(response.json())