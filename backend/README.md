**Intrusion_system backend: victim/attacker simulation & protection CLI**

Quick overview
- `victim_server.py` — serves the on-disk encrypted sensitive file over TCP (default 127.0.0.1:9000).
- `attacker_client.py` — connects to the victim server and saves received bytes to `data/exfiltrated_by_attacker.enc`.
- `select_protect.py` — CLI to mark files as sensitive: copies the original to `data/vault_backup/*.orig` and writes an encrypted blob to `data/sensitive_files/<name>`.

Typical workflow (Windows PowerShell)
1. Protect files you consider important (example: a local plaintext file):

```powershell
python backend/select_protect.py path\to\student_records.csv
```

2. Start the victim server (serves the encrypted copy on disk):

```powershell
python backend/victim_server.py
```

3. From attacker machine (or locally), fetch the file:

```powershell
python backend/attacker_client.py 192.168.1.20
```

If your victim uses a different port or you want to save to a custom path:

```powershell
python backend/attacker_client.py 192.168.1.20 --port 9000 --output backend/data/exfiltrated_by_attacker.enc
```

4. Verify exfiltrated data is encrypted:

 - The exfiltrated file at `backend/data/exfiltrated_by_attacker.enc` should contain ciphertext, not plaintext.
 - If the file begins with `gAAAAA...`, it is a Fernet encrypted blob.

Notes
- The project stores the encryption key at `backend/data/vault_key.key` when `cryptography` is available. The attacker does not receive the key during the transfer.
- This simulation intentionally serves the encrypted on-disk copy to model a scenario where an attacker can exfiltrate files but not the decryption key.
- If you want an automated test that asserts the attacker got ciphertext (not plaintext), I can add a pytest that starts the server, runs the client, and inspects the saved bytes.
