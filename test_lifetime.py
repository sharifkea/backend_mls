# test_lifetime.py
import sys
from datetime import datetime, timedelta

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Misc._lifetime import Lifetime

print("=== Step 11: Creating Lifetime object ===\n")

# Current time as not_before
now = int(datetime.now().timestamp())

# Valid for 30 days from now
thirty_days_later = now + int(timedelta(days=30).total_seconds())

lifetime = Lifetime(
    not_before=now,
    not_after=thirty_days_later
)

print("Lifetime created!")
print(f"  not_before : {datetime.fromtimestamp(lifetime.not_before)}")
print(f"  not_after  : {datetime.fromtimestamp(lifetime.not_after)}")
print(f"  Valid now? : {lifetime.valid()}")  # should be True

# Serialize (should be 16 bytes: 8 + 8)
ser = lifetime.serialize()
print(f"\nSerialized length: {len(ser)} bytes")
print(f"Serialized (hex): {ser.hex()}")