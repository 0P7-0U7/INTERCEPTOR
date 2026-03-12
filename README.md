
<p align="right">
  <a href="https://buymeacoffee.com/optoutbrussels">
    <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me a Coffee">
  </a>
</p>

## Ethical License (CNPL v4)
INTERCEPTOR is released under the **Cooperative Non-Violent Public License**. 

This means you are free to use it for art, education, and civilian research. However:
- **NO Military Use:** Use by military organizations or for weapons development is strictly prohibited.
- **NO Surveillance:** Use for state-sponsored surveillance is prohibited.
- **Cooperative Only:** Commercial use is reserved for worker-owned cooperatives.


<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/LOGO_DARK.png">
  <source media="(prefers-color-scheme: light)" srcset="images/LOGO_LIGHT.png">
  <img alt="INTERCEPTOR by OPT-OUT" src="images/LOGO_LIGHT.png" width="100%">
</picture>

# INTERCEPTOR by OPT-OUT
**ESP-NOW to OSC Smart Router**

A lightweight, zero-hardware Python bridge that turns your computer's native Wi-Fi card into a direct ESP-NOW receiver.

Instead of requiring a dedicated "Receiver ESP32" plugged into your computer via USB, this script sniffs raw 2.4GHz radio waves, identifies packets coming from Espressif chips, perfectly slices out **OSC (Open Sound Control)** payloads, and forwards them instantly over UDP to your visual or audio software (Resolume, TouchDesigner, Max/MSP, etc.).

### Core Capabilities
* **Zero-Hardware Receiver:** Intercepts ESP-NOW traffic directly out of the air using standard Wi-Fi hardware in Monitor Mode.
* **Smart OSC Routing:** Automatically detects valid OSC Messages (`/`) and OSC Bundles (`#bundle`), strips the proprietary Espressif radio headers, and fires the clean bytes to your target port.
* **Auto-Wrapping (`--wrap-raw`):** If an ESP32 sends plain text instead of OSC, the script can automatically pad and wrap it into a valid OSC message (`/rawdata <string>`) so your receiving software doesn't crash.
* **Live Hardware Discovery:** Maintains an active memory bank of all ESP32s in the room, printing a clean Session Summary of unique MAC addresses when you exit.
* **Smart Hostname Resolution:** Targets machines using local hostnames (e.g., `visuals-macpro`). The script automatically handles mDNS resolution.

---

## Installation

**ESP32 Hardware Compatibility:**
- **Zero-Hardware Receiver:** INTERCEPTOR is a pure Python script that utilizes your computer's native Wi-Fi card in Monitor Mode to sniff ESP-NOW traffic directly from the air. It requires **no ESP32 hardware** to function as a receiver, and is universally compatible with reading packets originating from any Espressif chip (ESP32, ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6).

1. Ensure you have **Python 3** installed.
2. Install the required network analysis and GUI libraries:
```bash
pip install scapy mac-vendor-lookup customtkinter
```
3. **Root Privileges:** Because this script interacts directly with raw network hardware, it *must* be run using `sudo`. Note: When launching the GUI version on Linux via sudo, you may need to preserve environmental variables (`sudo -E python3 INTERCEPTOR_GUI.py`) for X11/Wayland display access.

---

## Execution Workflows

### The Graphical Interface (New!)
To launch the dark-themed dashboard, run the GUI variant. It provides input fields aligned to the standard parameters and real-time scrolling packet monitoring:
```bash
sudo python3 INTERCEPTOR_GUI.py
```

### The CLI Headless Version
For automated or headless environments, the underlying system logic can be triggered sequentially:
`sudo python3 INTERCEPTOR.py <OS> <TARGET_MAC|ALL> <INTERFACE> <CHANNEL> <DEST_IP_OR_HOST> <DEST_PORT> [LOG.csv] [--wrap-raw]`

### Example: macOS Target Mode
Because Apple heavily restricts background hardware control, the script uses `libpcap` to read raw radio waves, but you must manually lock the frequency using the Wireless Diagnostics Sniffer window first.
```bash
sudo python3 INTERCEPTOR.py mac ALL en0 1 visuals-macpro 8000
```

### Example: Linux Auto-Scan Mode
Linux allows Python to fully control the hardware. Passing `0` for the channel invokes Scan Mode, physically sweeping channels to find ESP traffic.
```bash
sudo python3 INTERCEPTOR.py linux ALL wlan1 0 visuals-macpro 8000 --wrap-raw
```

---

### Full Documentation
For full architectural explanations, platform-specific logic, and argument breakdowns, please open the included **`docs/index.html`** file in your browser.
OR JUST GO TO <a href="https://0p7-0u7.github.io/INTERCEPTOR/" target="_blank">INTERCEPTOR PAGE</a>
