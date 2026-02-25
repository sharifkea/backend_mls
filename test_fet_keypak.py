import requests

def fetch_keypackage(user_id: str, base_url: str = "http://127.0.0.1:8000") -> bytes | None:
    """
    Fetch a serialized KeyPackage for a given user from the MLS server.
    
    Returns:
        bytes: the raw KeyPackage bytes if successful
        None: if the request fails or user not found
    """
    url = f"{base_url}/key_packages/{user_id}"
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            kp_bytes = response.content
            print(f"Successfully fetched KeyPackage for {user_id}")
            print(f"Size: {len(kp_bytes)} bytes")
            return kp_bytes
        
        elif response.status_code == 404:
            print(f"KeyPackage for {user_id} not found (404)")
            return None
            
        else:
            print(f"Error fetching {user_id}: {response.status_code} - {response.text}")
            return None
            
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None


# ────────────────────────────────────────────────
# Example usage
# ────────────────────────────────────────────────

def fetchkage(user_id: str):
    # user's KeyPackage should already be on the server
    kp = fetch_keypackage(user_id)
    
    if kp:
        # You can now use it to create an Add proposal, etc.
        print(f"{user_id}: First 32 bytes (hex): {kp[:32].hex()}")
        # Example: save it locally
        #with open(f"fetched_{user_id}_keypackage.bin", "wb") as f:
        #    f.write(kp)
        #print("Saved fetched KeyPackage to disk")
def main():
    # After Bob's KeyPackage is generated and uploaded

    # Fetch Alice's KeyPackage (to add her)
    alice_kp_bytes = fetch_keypackage("alice")   # use your fetch function from earlier

    # In real code you'd deserialize alice_kp_bytes back to KeyPackage object
    # But for now, assume we have it as bytes
    print("Ready to add Alice - fetched her KeyPackage:", len(alice_kp_bytes), "bytes")

    # Next big step: create group (requires RatchetTree initialization)
    # This is more involved – tell me if you want to go there now or first upload Bob
if __name__ == "__main__":
    main()