# test_db_api.py
# Tests FastAPI + PostgreSQL connection and KeyPackage operations
# Run this after uvicorn main:app is running on http://localhost:8000

import requests
import os
import hashlib
from uuid import uuid4
import binascii
from create_keypakage import GeneratKeyPackage
BASE_URL = "http://localhost:8000"

# Test files – replace with your real KeyPackage files
# or just use dummy data for testing
DUMMY_KEYPACKAGE = b"MLS-TEST-KEYPACKAGE-DATA-285BYTES-" + os.urandom(200)  # ~285 bytes dummy


def test_db_connection():
    print("\n=== 1. Testing database connection ===")
    try:
        r = requests.get(f"{BASE_URL}/test-db")
        r.raise_for_status()
        print("SUCCESS: Database connected")
        print("Response:", r.json())
    except Exception as e:
        print("FAILED:", str(e))


def test_user_registration(user_name: str, password: str):
    print(f"\n=== 2. Registering user {user_name} ===")
    try:
        r = requests.post(
            f"{BASE_URL}/users", 
            json={"username": user_name, "password": password},
            headers={"Content-Type": "application/json"}
        )
        r.raise_for_status()
        print("SUCCESS: User registered")
        print("Response:", r.json())
        return r.json().get("user_id")
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def test_user_login(user_name: str, password: str):
    print(f"\n=== 3. Logging in user {user_name} ===")
    try:
        r = requests.post(
            f"{BASE_URL}/login",
            data={"username": user_name, "password": password},  # using 'data' not 'json' for form-urlencoded
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        r.raise_for_status()
        print("SUCCESS: User logged in")
        print("Response:", r.json())
        return r.json().get("user_id"), r.json().get("access_token")
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return None

def test_upload_keypackage(user_id: str, key_package_bytes: bytes):
    print(f"\n=== 4. Uploading KeyPackage for {user_id} ===")
    ref_hash = hashlib.sha256(key_package_bytes).digest()
    print("First 32 bytes (hex):", key_package_bytes[:32].hex())
    try:
        r = requests.post(
            f"{BASE_URL}/key_packages/{user_id}",
            data=key_package_bytes,
            headers={"Content-Type": "application/octet-stream"}
        )
        r.raise_for_status()
        print("SUCCESS: Uploaded")
        print("Response:", r.json())
        return r.json().get("ref_hash"),r.json().get("key_package_id")
    except Exception as e:
        print("FAILED:", str(e))
        return None


def test_get_latest_keypackage(user_id: str):
    print(f"\n=== 5. Fetching latest unused KeyPackage for {user_id} ===")
    try:
        r = requests.get(f"{BASE_URL}/key_packages/{user_id}/latest")
        r.raise_for_status()
        print("SUCCESS: Fetched")
        print(f"Size: {len(r.content)} bytes")
        print(f"Content-Type: {r.headers.get('content-type')}")
        return r.content
    except Exception as e:
        print("FAILED:", str(e))
        return None


def test_mark_used(ref_hash_hex: str):
    print(f"\n=== 6. Marking KeyPackage as used (ref_hash: {ref_hash_hex}) ===")
    try:
        r = requests.post(
            f"{BASE_URL}/key_packages/mark-used",
            json={"ref_hash": ref_hash_hex},
            headers={"Content-Type": "application/json"}
        )
        r.raise_for_status()
        print("SUCCESS:", r.json())
    except Exception as e:
        print("FAILED:", str(e))


def test_cleanup():
    print("\n=== 5. Running cleanup (expired/used packages) ===")
    try:
        r = requests.post(f"{BASE_URL}/cleanup")
        r.raise_for_status()
        print("SUCCESS:", r.json())
    except Exception as e:
        print("FAILED:", str(e))


def test_delete_user(user_id: str, token: str):
    print(f"\n=== Deleting user {user_id} ===")
    try:
        r = requests.delete(
            f"{BASE_URL}/users/{user_id}",
            headers={
                "Authorization": f"Bearer {token}"
            }
        )
        r.raise_for_status()
        print("SUCCESS: User deleted")
        if r.text:  # Check if there's a response body
            print("Response:", r.json())
        else:
            print("User deleted successfully (no response body)")
        return True
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print("Response body:", e.response.text)
        return False
    

def test_new_mark_used(ref_hash_hex: str):
    print(f"\n=== 6. Marking KeyPackage as used (ref_hash: {ref_hash_hex}) ===")
    
    # Clean the ref_hash - remove 0x prefix if present
    if ref_hash_hex.startswith('0x'):
        ref_hash_hex = ref_hash_hex[2:]
        print(f"Cleaned ref_hash: {ref_hash_hex}")
    
    try:
        r = requests.post(
            f"{BASE_URL}/key_packages/new-mark-used",
            json={"ref_hash": ref_hash_hex},
            headers={"Content-Type": "application/json"}
        )
        print(f"Response status: {r.status_code}")
        print(f"Response body: {r.text}")
        r.raise_for_status()
        print("SUCCESS:", r.json())
    except Exception as e:
        print("FAILED:", str(e))
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error response: {e.response.text}")

if __name__ == "__main__":
    print("=== Database & API Integration Test ===\n")
    print("Make sure:")
    print("- uvicorn main:app --reload is running")
    print("- PostgreSQL is on, database 'mls_db' exists")
    print("- Tables & functions created\n")

    test_db_connection()
    test_user = "alice"
    user_id = test_user_registration(test_user,"1234")
    if user_id:
        user_id, token = test_user_login(test_user,"1234")
        if user_id and token:
            user_privet, kp_user=GeneratKeyPackage(test_user)
            ref_hash, key_package_id = test_upload_keypackage(user_id, kp_user)
            if ref_hash:
                latest_kp = test_get_latest_keypackage(user_id)
                if latest_kp:
                    test_mark_used(ref_hash)
                    test_cleanup()
                    bool_ret=test_delete_user(user_id, token)
    
