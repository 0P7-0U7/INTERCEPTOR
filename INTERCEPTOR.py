import sys
import socket
import csv
import os
import time
import threading
from datetime import datetime
from scapy.all import *
from scapy.config import conf
from mac_vendor_lookup import MacLookup

# ==========================================
# COMMAND-LINE ARGUMENTS
# ==========================================
if len(sys.argv) == 2 and sys.argv[1].lower() in ["update", "--update-only"]:
    print("[*] Running in UPDATE ONLY mode...")
    print("[*] Fetching latest IEEE database from the internet...")
    try:
        MacLookup().update_vendors()
        print("[+] Database updated successfully! You can now go offline.")
    except Exception as e:
        print(f"[-] Update failed. Are you connected to the internet? Error: {e}")
    sys.exit(0)

if len(sys.argv) < 7 or len(sys.argv) > 8:
    print("Usage: sudo python3 esp_target_lock.py <mac|linux|update> <TARGET_MAC|ALL> <INTERFACE> <CHANNEL> <DEST_HOSTNAME_OR_IP> <DEST_PORT> [OPTIONAL_LOG.csv]")
    sys.exit(1)

OS_TYPE = sys.argv[1].lower()
TARGET_MAC = sys.argv[2]
INTERFACE = sys.argv[3]
CHANNEL = sys.argv[4]
RAW_DEST = sys.argv[5]

try:
    OSC_DEST_PORT = int(sys.argv[6])
except ValueError:
    print("[-] Error: Port must be a number.")
    sys.exit(1)

LOG_FILE = sys.argv[7] if len(sys.argv) == 8 else None

# ==========================================
# SMART HOSTNAME RESOLUTION
# ==========================================
def resolve_destination(dest):
    try:
        socket.gethostbyname(dest)
        return dest
    except socket.gaierror:
        if "." not in dest:
            fallback = f"{dest}.local"
            try:
                socket.gethostbyname(fallback)
                return fallback
            except socket.gaierror:
                pass
    return dest

OSC_DEST_IP = resolve_destination(RAW_DEST)

# ==========================================
# DATABASE INITIALIZATION
# ==========================================
mac_db = MacLookup()
print("[*] Verifying MAC vendor database...")
try:
    mac_db.update_vendors()
    print("[+] Database updated successfully!\n")
except Exception:
    print("[-] No internet. Using local database cache.\n")

known_esps = set()

def is_espressif(mac_address):
    if not mac_address or mac_address.lower() == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        if "espressif" in mac_db.lookup(mac_address).lower():
            return True
    except Exception:
        pass
    return False

# ==========================================
# CROSS-PLATFORM HARDWARE AUTOMATION
# ==========================================
def linux_channel_hopper(iface):
    channels = [1, 6, 11]
    while True:
        for ch in channels:
            os.system(f"iw dev {iface} set channel {ch} > /dev/null 2>&1")
            time.sleep(0.5)

if OS_TYPE == "mac":
    conf.use_pcap = True
    print(f"[*] macOS Detected: Targeting interface {INTERFACE}")
    print(f"[!] IMPORTANT: Ensure macOS Sniffer is locked to Channel {CHANNEL}!\n")
    
elif OS_TYPE == "linux":
    print(f"[*] Linux Detected: Forcing {INTERFACE} offline to enable monitor mode...")
    try:
        os.system(f"ip link set {INTERFACE} down")
        os.system(f"iw dev {INTERFACE} set type monitor")
        os.system(f"ip link set {INTERFACE} up")
        
        if CHANNEL == "0":
            print("[*] SCAN MODE ACTIVATED: Hopping channels...")
            hopper = threading.Thread(target=linux_channel_hopper, args=(INTERFACE,), daemon=True)
            hopper.start()
        else:
            os.system(f"iw dev {INTERFACE} set channel {CHANNEL}")
            time.sleep(1)
            print(f"[+] Successfully locked to Channel {CHANNEL}!\n")
    except Exception as e:
        print(f"[-] Failed to configure Linux hardware: {e}")
        sys.exit(1)
else:
    print("[-] Unknown OS type. Please specify 'mac' or 'linux'.")
    sys.exit(1)

# ==========================================
# SETUP CSV LOGGER & UDP SOCKET
# ==========================================
if LOG_FILE:
    file_exists = os.path.isfile(LOG_FILE)
    try:
        with open(LOG_FILE, mode='a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['Timestamp', 'Source_MAC', 'Dest_MAC', 'Data_Type', 'Text_Payload', 'Hex_Payload'])
        print(f"[*] Logging enabled: {LOG_FILE}\n")
    except Exception:
        pass

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def parse_payload(raw_payload):
    bundle_idx = raw_payload.find(b'#bundle\x00')
    if bundle_idx != -1: return "OSC_BUNDLE", raw_payload[bundle_idx:]
    osc_idx = raw_payload.find(b'/')
    if osc_idx != -1:
        sliced = raw_payload[osc_idx:]
        if b'\x00' in sliced and b',' in sliced: return "OSC_MESSAGE", sliced
    return "RAW_DATA", raw_payload

def packet_handler(pkt):
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 13:
        src_mac = pkt.addr2 
        dst_mac = pkt.addr1 
        
        if TARGET_MAC.upper() != "ALL" and src_mac != TARGET_MAC.lower() and dst_mac != TARGET_MAC.lower():
            return
                
        # Device Discovery Logic
        if src_mac and is_espressif(src_mac):
            if src_mac not in known_esps:
                known_esps.add(src_mac)
                print(f"\n[★] NEW ESP32 DETECTED: {src_mac}")
                
        if dst_mac and dst_mac.lower() != "ff:ff:ff:ff:ff:ff" and is_espressif(dst_mac):
            if dst_mac not in known_esps:
                known_esps.add(dst_mac)
                print(f"\n[★] NEW ESP32 DETECTED: {dst_mac}")

        if is_espressif(src_mac) or is_espressif(dst_mac):
            if pkt.haslayer(Raw):
                raw_payload = pkt.getlayer(Raw).load
                data_type, clean_bytes = parse_payload(raw_payload)
                
                print(f"\n[+] Traffic: {src_mac} -> {dst_mac}")
                
                if data_type in ["OSC_MESSAGE", "OSC_BUNDLE"]:
                    try:
                        udp_sock.sendto(clean_bytes, (OSC_DEST_IP, OSC_DEST_PORT))
                        print(f"    [>] Routed {data_type} to {OSC_DEST_IP}:{OSC_DEST_PORT}")
                    except Exception:
                        pass
                else:
                    print(f"    [>] Ignored {data_type}")
                
                if LOG_FILE:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    try:
                        with open(LOG_FILE, mode='a', newline='') as f:
                            csv.writer(f).writerow([timestamp, src_mac, dst_mac, data_type, ''.join(chr(b) if 32 <= b <= 126 else '.' for b in clean_bytes), clean_bytes.hex()])
                    except Exception:
                        pass

if __name__ == "__main__":
    print(f"[*] Starting ESP-NOW Router on {INTERFACE}")
    print(f"[*] Forwarding OSC to: {OSC_DEST_IP} on port {OSC_DEST_PORT}")
    print("[*] Waiting for data... (Press Ctrl+C to stop)\n")
    
    try:
        sniff_kwargs = {"iface": INTERFACE, "prn": packet_handler, "store": 0}
        if OS_TYPE == "mac": sniff_kwargs["monitor"] = True
        sniff(**sniff_kwargs)
        
    except KeyboardInterrupt:
        # Graceful exit sequence
        print("\n\n[*] Stopping Sniffer...")
        
        # --- LINUX HARDWARE CLEANUP ---
        if OS_TYPE == "linux":
            print(f"[*] Restoring {INTERFACE} to normal Wi-Fi (managed) mode...")
            try:
                os.system(f"ip link set {INTERFACE} down")
                os.system(f"iw dev {INTERFACE} set type managed")
                os.system(f"ip link set {INTERFACE} up")
                print("[+] Hardware restored.")
            except Exception as e:
                print(f"[-] Could not fully restore hardware: {e}")
        # ------------------------------
        
        print("==========================================")
        print(f"[*] SESSION SUMMARY: {len(known_esps)} ESP32s Detected")
        print("==========================================")
        for mac in sorted(known_esps):
            print(f"    - {mac}")
        print("==========================================\n")
        sys.exit(0)
        
    except PermissionError:
        print("\n[-] ERROR: Run with sudo!")
        sys.exit(1)