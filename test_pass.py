# Test different scenarios
from passlib.context import CryptContext
from uuid import UUID, uuid4
from datetime import datetime, timedelta
from fastapi.responses import Response
from typing import Dict
from database import db
import hashlib  # for ref_hash computation

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
if __name__ == "__main__":
    test_passwords = [
        "short",
        "a" * 50,
        "a" * 100,  # This will hit the limit
        "😀" * 30,   # Unicode characters take more bytes
    ]

    for pwd in test_passwords:
        try:
            hash_result = pwd_context.hash(pwd)
            byte_length = len(pwd.encode('utf-8'))
            print(f"✓ '{pwd[:20]}...' ({byte_length} bytes) → Hashed successfully")
        except Exception as e:
            print(f"✗ Failed: {e}")