import sys
import os
import json

# Ensure local packages can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'python_packages'))

import urllib.request
import urllib.parse

BACKEND_URL = "http://127.0.0.1:5000"

def make_request(path, method="GET", data=None, is_json=True):
    url = f"{BACKEND_URL}{path}"
    headers = {}
    req_data = None
    
    if data is not None:
        if is_json:
            req_data = json.dumps(data).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        else:
            req_data = data
            
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            res_data = response.read().decode('utf-8')
            try:
                return json.loads(res_data), response.status
            except:
                return res_data, response.status
    except urllib.error.HTTPError as e:
        res_data = e.read().decode('utf-8')
        try:
            return json.loads(res_data), e.code
        except:
            return res_data, e.code
    except Exception as e:
        return str(e), 500

def test_flow():
    print("🚀 Starting integration tests...")
    
    # 0. Reset state to NONE / ACTIVE first
    print("\n--- Test 0: Reset State to ACTIVE ---")
    res_reset, status_reset = make_request("/vault/simulate", method="POST", data={"threat_level": "NONE"})
    print(f"Reset Status Code: {status_reset}")
    print(f"Reset Response: {res_reset}")
    
    # 1. Check status (ACTIVE)
    print("\n--- Test 1: Get Status (ACTIVE state) ---")
    res, status = make_request("/vault/status")
    print(f"Status Code: {status}")
    print(f"State: {res.get('state')}")
    print(f"Number of public records: {len(res.get('public_records', []))}")
    assert res.get('state') == 'ACTIVE', f"Expected ACTIVE, got {res.get('state')}"
    assert isinstance(res.get('public_records'), list), "Expected list of records under ACTIVE state"
    
    # 2. Upload new data
    print("\n--- Test 2: Upload new records ---")
    new_data = [
        {"student_id": "1001", "name": "Alice Johnson", "ssn": "123-45-6789", "grade": "A+", "status": "Active"},
        {"student_id": "9999", "name": "Test Student", "ssn": "000-00-0000", "grade": "F", "status": "Suspended"}
    ]
    res_up, status_up = make_request("/vault/upload", method="POST", data=new_data)
    print(f"Upload Status Code: {status_up}")
    print(f"Upload Response: {res_up}")
    assert status_up == 200
    
    # 3. Check status again (records updated)
    res_new, status_new = make_request("/vault/status")
    print(f"New Status Code: {status_new}")
    print(f"Number of public records: {len(res_new.get('public_records', []))}")
    assert any(r.get('student_id') == '9999' for r in res_new.get('public_records', [])), "Uploaded student 9999 not found"
    
    # 4. Simulate threat (MEDIUM)
    print("\n--- Test 3: Simulate Threat (MEDIUM) ---")
    res_sim, status_sim = make_request("/vault/simulate", method="POST", data={"threat_level": "MEDIUM"})
    print(f"Simulate Status Code: {status_sim}")
    print(f"Simulate Response: {res_sim}")
    
    # 5. Check status (PROTECTED - should return ciphertext string)
    print("\n--- Test 4: Get Status (PROTECTED state) ---")
    res_prot, status_prot = make_request("/vault/status")
    print(f"Protected Status Code: {status_prot}")
    print(f"State: {res_prot.get('state')}")
    print("Public Records preview:")
    print(res_prot.get('public_records')[:250] + "...")
    assert res_prot.get('state') == 'PROTECTED'
    assert isinstance(res_prot.get('public_records'), str), "Expected ciphertext warning string"
    assert "Unauthorized access detected." in res_prot.get('public_records')
    assert "Access Restricted due to Intrusion Detection." in res_prot.get('public_records')
    
    # 6. Revert threat simulation (consensus flow)
    print("\n--- Test 5: Revert Threat (Initiate Recovery & Consensus) ---")
    # Initiate recovery
    res_rec, status_rec = make_request("/vault/recover", method="POST", data={"admin_id": "Super Admin", "recovery_mode": "RECOVERY MODE"})
    print(f"Recover Status Code: {status_rec}")
    
    # Sign off Admin A
    res_a, status_a = make_request("/vault/approve", method="POST", data={"admin_id": "Admin A"})
    print(f"Admin A Status Code: {status_a}")
    
    # Sign off Admin B
    res_b, status_b = make_request("/vault/approve", method="POST", data={"admin_id": "Admin B"})
    print(f"Admin B Status Code: {status_b}")
    print(f"Admin B Response: {res_b}")
    assert res_b.get('recovered') is True
    
    # 7. Check status (ACTIVE again)
    res_act, status_act = make_request("/vault/status")
    print(f"Final Status Code: {status_act}")
    print(f"Final State: {res_act.get('state')}")
    assert res_act.get('state') == 'ACTIVE'
    
    print("\n🎉 All integration tests passed successfully!")

if __name__ == "__main__":
    test_flow()
