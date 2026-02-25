# test_ciphersuite_methods.py
import sys

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Enums import CipherSuite

print("=== Step 3 REVISED: Correct Calling Style ===\n")

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

print(f"Testing CipherSuite: {cs.name}\n")

methods = [
    "hash_size",
    "get_hpke_ciphersuite",
    "aead_algorithm",
    "hpke_aead_algorithm",
    "hpke_kdf_algorithm",
    "hpke_kem_algorithm",
    "kem_key_type",
    "signature_key_type",
    "hash_type"
]

for name in methods:
    try:
        func = getattr(cs, name)          # get the function
        print(f"{name:25} → ", end="")

        # Try calling as instance method: func()
        try:
            result = func()
            print(f"func()          = {result}")
            continue
        except TypeError:
            pass

        # Try calling as class function: func(cs)
        try:
            result = func(cs)
            print(f"func(cs)        = {result}")
            continue
        except Exception as e:
            print(f"Error: {e}")
            continue

        print("unknown")

    except Exception as e:
        print(f"{name:25} → Failed to get function: {e}")

print("\n🎉 Now we know the exact calling style for every method!")
print("We will use the working style in all future code.")