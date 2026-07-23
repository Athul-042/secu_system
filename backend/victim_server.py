import argparse
import socket
import threading
import os
import time

HOST = "0.0.0.0"
PORT = 9000

ROOT = os.path.dirname(__file__)
DATA_DIR = os.path.join(ROOT, 'data')
SENSITIVE_FILE = os.path.join(DATA_DIR, 'sensitive_files', 'student_records.csv')


def handle_client(conn, addr):
    print(f"[victim] Connection from {addr}")
    try:
        # Serve raw on-disk content of the sensitive file (encrypted blob)
        if not os.path.exists(SENSITIVE_FILE):
            conn.sendall(b"")
            return
        with open(SENSITIVE_FILE, 'rb') as f:
            data = f.read()
        # Simulate partial exfiltration: send in chunks
        chunk_size = 4096
        for i in range(0, len(data), chunk_size):
            conn.sendall(data[i:i+chunk_size])
            time.sleep(0.01)
        print(f"[victim] Sent {len(data)} bytes to {addr}")
    except Exception as e:
        print(f"[victim] Error handling client: {e}")
    finally:
        conn.close()


def run_server(host=HOST, port=PORT):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    print(f"[victim] Serving encrypted vault file on {host}:{port}")
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("[victim] Shutting down server")
    finally:
        srv.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Start victim server to serve encrypted sensitive data.')
    parser.add_argument('--host', default=HOST, help='Host to bind the victim server to')
    parser.add_argument('--port', default=PORT, type=int, help='Port to bind the victim server to')
    args = parser.parse_args(argv)
    run_server(host=args.host, port=args.port)


if __name__ == '__main__':
    main()
