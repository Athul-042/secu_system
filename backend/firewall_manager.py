import subprocess
import threading
import time

# Safelist: IPs that should NEVER be blocked
WHITELIST = [
    "127.0.0.1",        # Localhost
    "0.0.0.0",          # All interfaces
    "255.255.255.255",  # Broadcast
    "192.168.1.1",      # Common Router IP (Adjust if needed)
    "10.0.0.1",         # Common Router IP
    "8.8.8.8",          # Google DNS
    "8.8.4.4",          # Google DNS
    "1.1.1.1",          # Cloudflare DNS
]

# Track blocked IPs to avoid redundant rules
blocked_ips = set()
lock = threading.Lock()

def is_safe(ip):
    if ip in WHITELIST:
        return True
    # Don't block local network traffic universally, but for this demo/test we might want to block a specific attacker
    # For safety, let's say we don't block anything starting with 192.168. (unless user wants to test with another pc)
    # For now, simplistic check:
    return False

def block_ip(ip):
    if is_safe(ip):
        print(f"⚠️ IPS: Skipped blocking safe IP {ip}")
        return False

    with lock:
        if ip in blocked_ips:
            return True # Already blocked

        print(f"🛡️ IPS: Blocking Malicious IP {ip} in Windows Firewall...")
        
        try:
            # Block Inbound
            subprocess.run(
                f'netsh advfirewall firewall add rule name="IDS_BLOCK_{ip}" dir=in action=block remoteip={ip}', 
                shell=True, check=True, stdout=subprocess.DEVNULL
            )
            # Block Outbound (Optional, but good for stopping exfiltration)
            subprocess.run(
                f'netsh advfirewall firewall add rule name="IDS_BLOCK_{ip}" dir=out action=block remoteip={ip}', 
                shell=True, check=True, stdout=subprocess.DEVNULL
            )
            
            blocked_ips.add(ip)
            print(f"✅ IPS: Validated Block Rule for {ip}")
            return True
        except Exception as e:
            print(f"❌ IPS Error blocking {ip}: {e}")
            return False

def unblock_ip(ip):
    with lock:
        if ip not in blocked_ips:
            return

        print(f"🔓 IPS: Unblocking IP {ip}...")
        try:
            # Delete rules (Matches by name pattern)
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="IDS_BLOCK_{ip}"', 
                shell=True, check=True, stdout=subprocess.DEVNULL
            )
            blocked_ips.remove(ip)
        except Exception as e:
            print(f"❌ IPS Error unblocking {ip}: {e}")

# Auto-unblocker (Optional cleanup)
def cleanup_all():
    print("🧹 IPS: Cleaning up all IDS firewall rules...")
    # This is a bit risky to implement blindly, user should rely on manual unblock or restart for now
    # But for a robust system, wetrack created rules.
    pass
