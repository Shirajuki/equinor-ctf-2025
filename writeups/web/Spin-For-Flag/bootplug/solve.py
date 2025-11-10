import requests
import random
import string
import hashlib
import json

# Configuration
BASE_URL = "INSERT-URL-HERE"  # Replace with actual base URL
SURVEY_START_URL = f"{BASE_URL}/api/survey/start"
FINGERPRINT_URL = f"{BASE_URL}/api/fingerprint"
SPIN_URL = f"{BASE_URL}/api/spin"

# Base Headers (will update Referer dynamically)
def get_headers(survey_uuid=None):
    """Get headers with optional survey_uuid in Referer"""
    referer = f"{BASE_URL}/spin/{survey_uuid}" if survey_uuid else BASE_URL
    return {
        "Host": "bootplug-586d8fc1-spin4flag.ept.gg",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Not_A Brand";v="99", "Chromium";v="142"',
        "Content-Type": "application/json",
        "Sec-Ch-Ua-Mobile": "?0",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Origin": BASE_URL,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": referer,
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }

def generate_visitor_id():
    """Generate a random visitorId similar to: 71Gbqt3w7OcF9vSskNJa (20 chars, alphanumeric)"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(20))

def generate_request_id():
    """Generate a random requestId (32 char hex string)"""
    return ''.join(random.choice(string.hexdigits.lower()) for _ in range(32))

def start_survey():
    """Send POST request to start survey and get survey_uuid"""
    print(f"Starting survey at: {SURVEY_START_URL}")
    print("-" * 60)
    
    try:
        response = requests.post(SURVEY_START_URL, headers=get_headers(), json={}, timeout=10)
        
        print(f"Survey Start Status Code: {response.status_code}")
        
        if response.status_code == 200:
            response_json = response.json()
            survey_uuid = response_json.get("survey_uuid")
            print(f"Survey UUID: {survey_uuid}")
            return survey_uuid
        else:
            print(f"Failed to start survey: {response.text}")
            return None
            
    except Exception as e:
        print(f"Error starting survey: {e}")
        return None

def send_fingerprint_request(visitor_id, request_id, survey_uuid):
    """Send the fingerprint POST request with given IDs"""
    
    # Build the JSON payload
    payload = {
        "visitorId": visitor_id,
        "requestId": request_id,
        "version": "3.4.2",
        "confidence": {
            "score": 0.995
        },
        "device": "desktop",
        "browserName": "Chrome",
        "os": "Windows",
        "survey_uuid": survey_uuid
    }
    
    print(f"Sending fingerprint request to: {FINGERPRINT_URL}")
    print("-" * 60)
    
    try:
        response = requests.post(FINGERPRINT_URL, headers=get_headers(survey_uuid), json=payload, timeout=10)
        
        print(f"Fingerprint Status Code: {response.status_code}")
        
        try:
            # Try to parse as JSON
            response_json = response.json()
            print(f"Fingerprint Response: {json.dumps(response_json, indent=2)}")
        except:
            # If not JSON, print as text
            print(f"Fingerprint Response: {response.text}")
        
        return response
        
    except Exception as e:
        print(f"Error sending fingerprint request: {e}")
        return None

def send_spin_request(visitor_id, request_id, survey_uuid):
    """Send the spin POST request with given IDs"""
    
    # Build the JSON payload for spin
    payload = {
        "survey_uuid": survey_uuid,
        "visitorId": visitor_id,
        "requestId": request_id
    }
    
    print(f"\nSending spin request to: {SPIN_URL}")
    print("-" * 60)
    
    try:
        response = requests.post(SPIN_URL, headers=get_headers(survey_uuid), json=payload, timeout=10)
        
        print(f"Spin Status Code: {response.status_code}")
        
        try:
            # Try to parse as JSON
            response_json = response.json()
            result = response_json.get("result", "")
            
            # Print if result is NOT "no_flag"
            if result != "no_flag":
                print("\n" + "="*60)
                print("🎉 FOUND SOMETHING OTHER THAN 'no_flag'!")
                print("="*60)
                print(f"Result: {result}")
                print(f"\nFull Response:")
                print(json.dumps(response_json, indent=2))
                print(f"\nRequest Details:")
                print(f"  visitorId: {visitor_id}")
                print(f"  requestId: {request_id}")
                print("="*60)
                return True
            else:
                print(f"Result: {result}")
                
        except Exception as e:
            # If not JSON, print as text
            print(f"Spin Response: {response.text}")
        
        return False
        
    except Exception as e:
        print(f"Error sending spin request: {e}")
        return False

def main():

    for i in range(1, 60):
        print("="*60)
        print(f"Fingerprint & Spin API Request Sender - Attempt {i}")
        print("="*60)
        print()
        
        # Start survey to get survey_uuid
        survey_uuid = start_survey()
        if not survey_uuid:
            print("Failed to get survey UUID, skipping this attempt...")
            continue
        
        print()
        
        # Generate random IDs
        visitor_id = generate_visitor_id()
        request_id = generate_request_id()
        
        print(f"Generated visitorId: {visitor_id}")
        print(f"Generated requestId: {request_id}")
        print()
        
        # Send fingerprint request
        fingerprint_response = send_fingerprint_request(visitor_id, request_id, survey_uuid)
        
        if fingerprint_response and fingerprint_response.status_code == 200:
            print("\n✓ Fingerprint request successful!")
            
            # Send spin request
            found_flag = send_spin_request(visitor_id, request_id, survey_uuid)
            
            if found_flag:
                print("\n✓ Spin request returned something interesting!")
                break
            else:
                print("\n✓ Spin request completed (result: no_flag)")
        else:
            print("\n✗ Fingerprint request failed or returned non-200 status")

if __name__ == "__main__":
    main()
