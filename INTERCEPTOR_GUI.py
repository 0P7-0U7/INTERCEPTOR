import sys
import socket
import csv
import os
import time
import threading
from datetime import datetime
import customtkinter as ctk

try:
    from scapy.all import *
    from scapy.config import conf
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Suppress scapy warnings
except ImportError:
    print("Please install scapy: pip3 install scapy")
    sys.exit(1)

try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None
    print("Warning: mac_vendor_lookup not installed. Vendor resolution disabled.")

# ==========================================
# CUSTOMTKINTER THEME SETUP (BRUTALIST / DARK)
# ==========================================
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# Custom Colors
BG_COLOR = "#0f0f0f"
FG_COLOR = "#ffffff"
ACCENT_COLOR = "#333333"
TEXT_COLOR = "#dddddd"
FONT_MAIN = ("Inter", 12)
FONT_MONO = ("JetBrains Mono", 11)
FONT_HEADER = ("Inter", 16, "bold")

class InterceptorGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("INTERCEPTOR | OPT-OUT")
        self.geometry("1000x750")
        self.configure(fg_color=BG_COLOR)
        
        # --- Internal State ---
        self.is_sniffing = False
        self.sniff_thread = None
        self.mac_db = None
        self.known_esps = set()
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        self.OSC_DEST_IP = "127.0.0.1"
        self.OSC_DEST_PORT = 8000
        self.LOG_FILE = ""
        
        self._init_database()
        self._build_ui()
        
    def _init_database(self):
        if MacLookup:
            try:
                self.mac_db = MacLookup()
            except Exception:
                self.mac_db = None
                
    def _build_ui(self):
        # Grid Configuration
        self.grid_columnconfigure(0, weight=0, minsize=300) # Left Control Panel
        self.grid_columnconfigure(1, weight=1) # Right Monitor Panel
        self.grid_rowconfigure(0, weight=1)

        # --- LEFT PANEL (CONTROLS) ---
        self.panel_left = ctk.CTkFrame(self, fg_color=BG_COLOR, corner_radius=0, border_width=1, border_color=ACCENT_COLOR)
        self.panel_left.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Header
        header = ctk.CTkLabel(self.panel_left, text="INTERCEPTOR GUI", font=("Inter", 24, "bold"), text_color=FG_COLOR)
        header.pack(pady=(20, 5), padx=20, anchor="w")
        subheader = ctk.CTkLabel(self.panel_left, text="ESP-NOW to OSC Router", font=FONT_MAIN, text_color="gray")
        subheader.pack(pady=(0, 20), padx=20, anchor="w")

        # Bottom Controls Container (Fixed)
        bottom_frame = ctk.CTkFrame(self.panel_left, fg_color="transparent")
        bottom_frame.pack(side="bottom", fill="x", padx=10, pady=(10, 20))

        # Footer Link
        import webbrowser
        def open_github():
            webbrowser.open("https://github.com/0P7-0U7", new=2)
            
        footer_btn = ctk.CTkButton(bottom_frame, text="OPT-OUT / BRUSSELS 2026", font=("Inter", 10, "bold"),
                                   fg_color="transparent", text_color="gray", hover_color=ACCENT_COLOR,
                                   command=open_github, anchor="center")
        footer_btn.pack(side="bottom", fill="x", pady=(10, 0))
        
        # Start / Stop Button
        self.toggle_btn = ctk.CTkButton(bottom_frame, text="START", font=("Inter", 16, "bold"), 
                                        fg_color=FG_COLOR, text_color=BG_COLOR, hover_color="gray", 
                                        command=self.toggle_sniffing, height=50)
        self.toggle_btn.pack(side="bottom", fill="x")

        # Inputs Container (Scrollable) - Packed LAST so it takes remaining space
        params_frame = ctk.CTkScrollableFrame(self.panel_left, fg_color="transparent")
        params_frame.pack(side="top", fill="both", expand=True, padx=10, pady=5)

        def create_input(parent, label_text, default_val):
            lbl = ctk.CTkLabel(parent, text=label_text.upper(), font=FONT_MAIN, text_color=FG_COLOR)
            lbl.pack(anchor="w", pady=(10, 0), padx=10)
            entry = ctk.CTkEntry(parent, font=FONT_MONO, fg_color=ACCENT_COLOR, border_width=0, text_color=TEXT_COLOR)
            entry.insert(0, default_val)
            entry.pack(fill="x", pady=5, padx=10)
            return entry


        # OS Selection
        os_lbl = ctk.CTkLabel(params_frame, text="OS TYPE", font=FONT_MAIN, text_color=FG_COLOR)
        os_lbl.pack(anchor="w", pady=(10, 0), padx=10)
        self.os_var = ctk.StringVar(value="mac")
        self.os_menu = ctk.CTkOptionMenu(params_frame, values=["mac", "linux"], variable=self.os_var, 
                                         font=FONT_MONO, fg_color=ACCENT_COLOR, button_color=ACCENT_COLOR)
        self.os_menu.pack(fill="x", pady=5, padx=10)

        self.iface_entry = create_input(params_frame, "Interface (e.g. en0, wlan1)", "en0")
        self.target_entry = create_input(params_frame, "Target MAC (or ALL)", "ALL")
        self.channel_entry = create_input(params_frame, "Wi-Fi Channel (0 for Linux Scan)", "1")
        self.dest_entry = create_input(params_frame, "Destination Host/IP", "127.0.0.1")
        self.port_entry = create_input(params_frame, "Destination UDP Port", "8000")
        
        # Checkboxes
        self.wrap_raw_var = ctk.BooleanVar(value=False)
        self.wrap_cb = ctk.CTkCheckBox(params_frame, text="Wrap Raw Text (--wrap-raw)", variable=self.wrap_raw_var, 
                                       font=FONT_MAIN, fg_color=FG_COLOR, hover_color="gray")
        self.wrap_cb.pack(pady=(20, 10), padx=10, anchor="w")

        self.log_csv_var = ctk.BooleanVar(value=False)
        self.log_csv_cb = ctk.CTkCheckBox(params_frame, text="Enable CSV Logging", variable=self.log_csv_var, 
                                          font=FONT_MAIN, fg_color=FG_COLOR, hover_color="gray")
        self.log_csv_cb.pack(pady=(10, 5), padx=10, anchor="w")
        
        self.log_entry = ctk.CTkEntry(params_frame, font=FONT_MONO, fg_color=ACCENT_COLOR, border_width=0, text_color=TEXT_COLOR)
        self.log_entry.insert(0, "session.csv")
        self.log_entry.pack(fill="x", pady=(5, 20), padx=10)

        # --- RIGHT PANEL (LIVE MONITOR) ---
        self.panel_right = ctk.CTkFrame(self, fg_color=BG_COLOR, corner_radius=0, border_width=1, border_color=ACCENT_COLOR)
        self.panel_right.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=10)
        
        # Output Log Box
        self.log_box = ctk.CTkTextbox(self.panel_right, font=FONT_MONO, fg_color="transparent", text_color=TEXT_COLOR, wrap="word")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.log("[*] INTERCEPTOR GUI Initialized.")
        if self.mac_db:
             self.log("[+] MAC Vendor Database Loaded.")
        else:
             self.log("[-] MAC Vendor Database Missing. Proceeding without vendor resolution.")

    def log(self, message):
        """Thread-safe way to update the text box"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}\n"
        self.log_box.insert("end", formatted)
        self.log_box.see("end")

    def toggle_sniffing(self):
        if self.is_sniffing:
            self.stop_sniffing()
        else:
            self.start_sniffing()

    def start_sniffing(self):
        # Gather inputs
        os_type = self.os_var.get()
        iface = self.iface_entry.get().strip()
        channel = self.channel_entry.get().strip()
        raw_dest = self.dest_entry.get().strip()
        
        try:
            self.OSC_DEST_PORT = int(self.port_entry.get().strip())
        except ValueError:
            self.log("[-] ERROR: Port must be an integer.")
            return

        self.OSC_DEST_IP = self.resolve_destination(raw_dest)
        
        if self.log_csv_var.get():
            self.LOG_FILE = self.log_entry.get().strip()
        else:
            self.LOG_FILE = ""

        if self.LOG_FILE:
            file_exists = os.path.isfile(self.LOG_FILE)
            try:
                with open(self.LOG_FILE, mode='a', newline='') as f:
                    writer = csv.writer(f)
                    if not file_exists:
                        writer.writerow(['Timestamp', 'Source_MAC', 'Dest_MAC', 'Data_Type', 'Text_Payload', 'Hex_Payload'])
                self.log(f"[*] Appending metrics to CSV: {self.LOG_FILE}")
            except Exception as e:
                self.log(f"[-] CSV Error: {e}")
                self.LOG_FILE = ""
        
        self.is_sniffing = True
        self.toggle_btn.configure(text="STOP", fg_color="red", text_color="white", hover_color="darkred")
        self.log(f"\n[*] Starting Sniffer on {iface}...")
        self.log(f"[*] Forwarding to {self.OSC_DEST_IP}:{self.OSC_DEST_PORT}")
        
        # Hardware Setup
        if os_type == "mac":
            conf.use_pcap = True
            self.log(f"[!] macOS Warning: Ensure sniffer is locked to Channel {channel} via Wireless Diagnostics!")
        elif os_type == "linux":
            self.log(f"[*] Linux: Forcing {iface} into monitor mode...")
            try:
                os.system(f"ip link set {iface} down")
                os.system(f"iw dev {iface} set type monitor")
                os.system(f"ip link set {iface} up")
                if channel == "0":
                    self.log("[*] SCAN MODE ACTIVATED: Hopping channels in background...")
                    hopper = threading.Thread(target=self.linux_channel_hopper, args=(iface,), daemon=True)
                    hopper.start()
                else:
                    os.system(f"iw dev {iface} set channel {channel}")
                    time.sleep(1)
                    self.log(f"[+] Locked to Channel {channel}")
            except Exception as e:
                self.log(f"[-] Failed to configure Linux hardware: {e}")
                self.stop_sniffing()
                return

        # Start Sniffing Thread
        self.sniff_thread = threading.Thread(target=self.sniff_loop, args=(os_type, iface), daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self):
        if not self.is_sniffing: return
        self.is_sniffing = False
        self.toggle_btn.configure(text="START", fg_color=FG_COLOR, text_color=BG_COLOR, hover_color="gray")
        self.log("\n[*] Halting Sniffer...")
        
        if self.os_var.get() == "linux":
            iface = self.iface_entry.get().strip()
            self.log(f"[*] Linux: Restoring {iface} to managed mode...")
            try:
                os.system(f"ip link set {iface} down")
                os.system(f"iw dev {iface} set type managed")
                os.system(f"ip link set {iface} up")
            except Exception as e:
                 self.log(f"[-] Hardware restore failed: {e}")
                 
        self.log("================ SESSION SUMMARY ================")
        self.log(f"Unique ESP32s Discovered: {len(self.known_esps)}")
        for mac in self.known_esps:
            self.log(f"  -> {mac}")
        self.log("=================================================")

    def linux_channel_hopper(self, iface):
        channels = [1, 6, 11]
        while self.is_sniffing:
            for ch in channels:
                if not self.is_sniffing: break
                os.system(f"iw dev {iface} set channel {ch} > /dev/null 2>&1")
                time.sleep(0.5)

    def resolve_destination(self, dest):
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

    def is_espressif(self, mac_address):
        if not mac_address or mac_address.lower() == "ff:ff:ff:ff:ff:ff":
             return False
        if not self.mac_db:
             # Weak heuristic if DB is missing (common ESP prefixes)
             prefixes = ["24:0a:c4", "24:62:ab", "30:ae:a4", "3c:71:bf", "40:22:d8", "7c:df:a1", "84:cc:a8", "a0:20:a6", "c8:f0:9e", "d8:a0:1d"]
             return any(mac_address.lower().startswith(p) for p in prefixes)
        try:
            if "espressif" in self.mac_db.lookup(mac_address).lower():
                return True
        except Exception:
            pass
        return False

    def parse_payload(self, raw_payload):
        bundle_idx = raw_payload.find(b'#bundle\x00')
        if bundle_idx != -1: return "OSC_BUNDLE", raw_payload[bundle_idx:]
        
        idx = raw_payload.find(b'/')
        while idx != -1:
            comma_idx = raw_payload.find(b',', idx)
            if comma_idx != -1:
                null_between = raw_payload.find(b'\x00', idx, comma_idx)
                if null_between != -1:
                    padding_valid = True
                    for i in range(null_between, comma_idx):
                        if raw_payload[i] != 0: padding_valid = False; break
                    if padding_valid: return "OSC_MESSAGE", raw_payload[idx:]
            idx = raw_payload.find(b'/', idx + 1)
        return "UNKNOWN_FORMAT", raw_payload

    def process_osc(self, osc_payload):
        address_end = osc_payload.find(b'\x00')
        if address_end == -1: return

        address = osc_payload[:address_end].decode('utf-8', errors='ignore')
        type_tag_idx = osc_payload.find(b',', address_end)
        
        if type_tag_idx != -1:
            type_end = osc_payload.find(b'\x00', type_tag_idx)
            if type_end != -1:
                type_tags = osc_payload[type_tag_idx:type_end].decode('utf-8', errors='ignore')
                self.log(f"    [OK] Forwarded OSC: {address} [{type_tags}]")
                return

        self.log(f"    [?] Forwarded Blind OSC (No type tag): {address}")

    def pad_osc(self, data: bytes) -> bytes:
        pad_len = 4 - (len(data) % 4)
        return data + (b'\x00' * pad_len)

    def packet_handler(self, pkt):
        if not self.is_sniffing: 
            return # Tell scapy to stop

        target_mac = self.target_entry.get().strip().lower()
        
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 13: 
                src_mac = str(pkt.addr2).lower()
                dst_mac = str(pkt.addr1).lower()

                if target_mac != "all" and src_mac != target_mac: return
                if not self.is_espressif(src_mac): return

                if src_mac not in self.known_esps:
                    self.known_esps.add(src_mac)
                    self.log(f"[+] NEW ESP32 Discovered: {src_mac}")

                raw_data = bytes(pkt[Dot11].payload)
                if len(raw_data) < 24: return
                
                vendor_oui = raw_data[1:4]
                if vendor_oui == b'\x18\xfe\x34': # Espressif OUI check
                    clean_bytes = raw_data[4:] 
                    data_type, parsed_payload = self.parse_payload(clean_bytes)

                    if data_type in ["OSC_MESSAGE", "OSC_BUNDLE"]:
                        self.udp_sock.sendto(parsed_payload, (self.OSC_DEST_IP, self.OSC_DEST_PORT))
                        if data_type == "OSC_MESSAGE": self.process_osc(parsed_payload)
                        else: self.log("    [OK] Forwarded OSC Bundle")
                    
                    elif data_type == "UNKNOWN_FORMAT":
                        if self.wrap_raw_var.get():
                            address = self.pad_osc(b'/rawdata\x00')
                            types = self.pad_osc(b',s\x00')
                            str_payload = bytes(''.join(chr(b) if 32 <= b <= 126 else '?' for b in clean_bytes), 'utf-8')
                            str_padded = self.pad_osc(str_payload + b'\x00')
                            wrapped_osc = address + types + str_padded
                            self.udp_sock.sendto(wrapped_osc, (self.OSC_DEST_IP, self.OSC_DEST_PORT))
                            self.log(f"    [RAW] Wrapped & Forwarded: {str_payload.decode('utf-8', errors='ignore')}")
                        else:
                            pass # Just ignore if not wrapping

                    if self.LOG_FILE:
                        timestamp_csv = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                        try:
                            with open(self.LOG_FILE, mode='a', newline='') as f:
                                ascii_payload = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in clean_bytes)
                                csv.writer(f).writerow([timestamp_csv, src_mac, dst_mac, data_type, ascii_payload, clean_bytes.hex()])
                        except Exception:
                            pass

    def sniff_loop(self, os_type, iface):
        try:
            sniff_kwargs = {"iface": iface, "prn": self.packet_handler, "store": 0, "stop_filter": lambda p: not self.is_sniffing}
            if os_type == "mac": sniff_kwargs["monitor"] = True
            sniff(**sniff_kwargs)
        except Exception as e:
            self.log(f"[-] Sniffing Error: {e}")
            self.stop_sniffing()

if __name__ == "__main__":
    app = InterceptorGUI()
    app.mainloop()
