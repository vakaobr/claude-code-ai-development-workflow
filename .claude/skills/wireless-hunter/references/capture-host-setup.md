# Wireless Capture-Host Setup Checklist

Support material for `wireless-hunter`. The agent cannot do 802.11
monitor mode / injection on macOS (RTL8812AU is unsupported there, worse
on Apple Silicon). It drives a **Linux capture host** instead. This doc
is a runnable checklist for two hosts:

- **A) VM + USB passthrough** — primary, supported setup.
- **B) Raspberry Pi 4/5** — portable alternative (recommended for
  workshops); the road is paved here so you can switch later with no
  methodology change.

Reference adapter: **Alfa AWUS036ACH (Realtek RTL8812AU)**. Driver:
`aircrack-ng/rtl8812au` (DKMS).

> Run nothing against networks you are not authorized for. The rogue-AP /
> attendee-capture steps require `red_team_ops.wireless: approved` and
> `wireless_workshop_consent` in `.claude/security-scope.yaml`.

---

## A) Kali VM + USB passthrough (primary)

### A0. Host choice (read first)
- [ ] **Intel Mac / PC + VMware Workstation/Fusion or VirtualBox** →
      reliable USB-Wi-Fi passthrough. **Recommended.**
- [ ] **Apple Silicon Mac (UTM/QEMU)** → USB-Wi-Fi monitor-mode
      passthrough is unreliable. If you're on Apple Silicon, prefer the
      **Pi path (B)**. Don't fight QEMU for this.

### A1. Build the VM
- [ ] Download Kali Linux (or Ubuntu) VM image; allocate ≥2 vCPU / 4 GB
      RAM / 30 GB disk.
- [ ] Boot, update: `sudo apt update && sudo apt full-upgrade -y`
- [ ] Install headers + tooling:
      `sudo apt install -y bc dkms git build-essential linux-headers-$(uname -r) \
       aircrack-ng kismet hostapd dnsmasq tshark hcxdumptool hcxtools bettercap`

### A2. Pass the adapter through to the guest
- [ ] Plug the AWUS036ACH into the host.
- [ ] **VMware**: VM Settings → USB Controller → enable USB 3.x; when the
      adapter appears, "Connect to virtual machine". Or VM menu →
      Removable Devices → Realtek 8812AU → Connect.
- [ ] **VirtualBox**: Settings → USB → enable xHCI, add a USB filter for
      the Realtek adapter (install the Extension Pack first).
- [ ] In the guest, confirm the device is visible: `lsusb | grep -i realtek`

### A3. Install the RTL8812AU driver (DKMS)
- [ ] ```
      sudo apt install -y realtek-rtl88xxau-dkms   # Kali shortcut, OR build from source:
      git clone https://github.com/aircrack-ng/rtl8812au
      cd rtl8812au && sudo make dkms_install
      ```
- [ ] Reboot the guest. Confirm interface: `ip link` / `iw dev` (expect
      `wlan0` or similar).

### A4. Verify monitor mode + injection (DO NOT SKIP)
- [ ] Kill interfering processes: `sudo airmon-ng check kill`
- [ ] Enable monitor mode: `sudo airmon-ng start wlan0` → note the new
      `wlan0mon` interface; confirm with `iw dev` (type `monitor`).
- [ ] **Injection test:** `sudo aireplay-ng --test wlan0mon`
      → must report "Injection is working!". If it doesn't, STOP and fix
      the driver/passthrough before trusting any capture.
- [ ] Channel hop sanity: `sudo airodump-ng wlan0mon` shows nearby APs.

### A5. Restore when done
- [ ] `sudo airmon-ng stop wlan0mon` → back to managed mode.

---

## B) Raspberry Pi 4/5 (portable / workshop)

No passthrough layer = fewer failure modes. The agent drives the Pi over
SSH; methodology is identical to (A) from A3 onward.

### B1. Image + base
- [ ] Flash **Kali Linux ARM (RaspberryPi 4/400/5)** or Raspberry Pi OS
      (64-bit) to a fast microSD/USB-SSD.
- [ ] First boot: set a strong password, `sudo apt update && full-upgrade`.
- [ ] Enable + harden SSH (key auth) so the agent can reach it on the
      workshop LAN.
- [ ] Install the same tool set as A1.

### B2. Adapter + driver
- [ ] Attach the AWUS036ACH directly to a USB-3 (blue) port. On the Pi 5,
      prefer the USB-3 ports; ensure a 5V/5A (Pi 5) / 5V/3A (Pi 4) PSU —
      Wi-Fi injection draws power, brownouts cause dropouts.
- [ ] Install `rtl8812au` DKMS (as A3). Reboot.

### B3. Verify (same as A4)
- [ ] `sudo airmon-ng check kill && sudo airmon-ng start wlan0`
- [ ] `sudo aireplay-ng --test wlan0mon` → "Injection is working!"

> Keep the Pi's onboard Wi-Fi (`wlan0` built-in) for management/SSH and
> use the **Alfa** as the monitor/AP interface, or vice-versa — just don't
> put your SSH link on the interface you flip into monitor mode.

---

## Workshop rogue-AP demo bring-up (consent-gated)

Only with `red_team_ops.wireless: approved` + `wireless_workshop_consent`
+ attendee signage. This is the "free wifi" awareness demo.

- [ ] Pick the AP interface (the Alfa); keep your uplink on a different
      interface (built-in Wi-Fi / ethernet / tethered).
- [ ] `hostapd` open SSID (e.g. "Free Airport WiFi") + `dnsmasq` for
      DHCP/DNS. (Or `bettercap` to orchestrate.)
- [ ] Optional captive portal → benign awareness page (and, for the
      credential-awareness demo, a fake login that records only the FACT
      of submission — NEVER the real password).
- [ ] The teachable capture (run on the AP uplink):
      ```
      sudo tshark -i <uplink> -Y "dns.flags.response==0" -T fields -e dns.qry.name      # plaintext DNS
      sudo tshark -i <uplink> -Y "tls.handshake.extensions_server_name" \
           -T fields -e tls.handshake.extensions_server_name                            # TLS SNI (hostnames)
      sudo tshark -i <uplink> -Y "http.request" -T fields -e http.host -e http.request.uri  # cleartext HTTP
      sudo airodump-ng wlan0mon                                                          # probe requests (preferred SSIDs)
      ```
- [ ] Present: "without a VPN / encrypted DNS, this is what an open network
      sees." Set expectations — HTTPS bodies are NOT visible; DNS, SNI,
      probe requests, and cleartext HTTP are.
- [ ] **Teardown:** stop hostapd/dnsmasq, `airmon-ng stop`, purge captured
      attendee traffic beyond the anonymized teaching examples (per
      consent). Log the teardown.

---

## Quick troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No `wlan` interface in guest | passthrough not connected / driver missing | re-attach USB to VM; `lsusb`; install rtl8812au DKMS |
| Monitor mode sets but `--test` fails | wrong driver / power | rebuild aircrack-ng rtl8812au; better PSU/port (Pi) |
| Interface vanishes under load | USB power brownout | powered USB hub; Pi 5 → 5V/5A PSU |
| Apple Silicon UTM: flaky/no injection | QEMU USB-Wi-Fi limitation | use the Pi path or an Intel VM host |
| Capture empty | SSH/management on the monitor iface | separate management vs monitor/AP interfaces |

## References
- aircrack-ng: https://www.aircrack-ng.org/
- rtl8812au driver: https://github.com/aircrack-ng/rtl8812au
- Kali on Raspberry Pi: https://www.kali.org/docs/arm/raspberry-pi/
- hostapd / dnsmasq / bettercap docs
