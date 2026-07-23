import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import app


def test_simulate_unauthorized_access_returns_encrypted_payload():
    client = app.test_client()
    resp = client.post('/simulate-unauthorized-access', json={
        'attacker_username': 'attacker',
        'target_username': 'victim',
        'target_filename': 'Bank.pdf'
    })

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload['status'] == 'blocked'
    assert payload['message'] == 'Unauthorized access detected'
    assert payload['encrypted_file'] == 'Bank.pdf.enc'
    assert payload['encrypted_content']
    assert 'gAAAAA' in payload['encrypted_content'] or 'ciphertext' in payload['encrypted_content'].lower()
