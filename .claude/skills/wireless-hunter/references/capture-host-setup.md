# Wireless Capture-Host Setup Checklist

Support material for `wireless-hunter`. macOS itself can't do 802.11
monitor mode / injection, so the skill drives a **Linux capture host**.
This doc is a runnable checklist for two hosts:

- **A) VM + USB passthrough** — works on Apple Silicon (Fusion CAN pass
  the adapter through); the real variable is whether the adapter's driver
  builds for the guest kernel (see below).
- **B) Raspberry Pi 4/5** — portable, most-reliable for workshops; the
  road is paved here so you can switch with no methodology change.

> **What's actually hard (corrected):** USB passthrough is NOT the
> blocker — VMware Fusion passes the adapter into the Linux guest fine
> (Virtual Machine menu → USB & Bluetooth → Connect). The blocker is the
> **out-of-tree Wi-Fi driver vs the guest kernel**. Verified 2026-06-28
> on Kali arm64: the packaged `realtek-rtl88xxau-dkms` (RTL8812AU) has a
> `BUILD_EXCLUSIVE` guard that **refuses to build on kernel 6.19** — so
> monitor mode is unavailable until a 6.19-compatible driver lands,
> regardless of passthrough. Pick an adapter whose driver is in the
> **mainline kernel** to avoid this entirely.

> Run nothing against networks you are not authorized for. The rogue-AP /
> attendee-capture steps require `red_team_ops.wireless: approved` and
> `wireless_workshop_consent` in `.claude/security-scope.yaml`.

---

## Adapter selection (read before buying)

Monitor mode + injection depends on the **chipset + driver**. Prefer
chipsets whose driver is **in the mainline Linux kernel** — they work out
of the box on any recent kernel (incl. 6.19) and over VM passthrough,
with no DKMS chase.

| Adapter | Chipset | Driver | Bands | Verdict |
|---|---|---|---|---|
| **Alfa AWUS036ACM** | MediaTek MT7612U | `mt76x2u` (mainline) | 2.4 + 5 GHz | **Recommended** — dual-band AND mainline; no driver chasing |
| Alfa AWUS036NHA | Atheros AR9271 | `ath9k_htc` (mainline) | 2.4 GHz only | Rock-solid "just works"; pick if 2.4 GHz is enough |
| Alfa AWUS036ACHM | MediaTek MT7610U | `mt76x0u` (mainline) | 2.4 + 5 GHz (1×1) | Good mainline dual-band, lower throughput |
| Alfa AWUS036ACH / AC | Realtek RTL8812AU | `rtl88xxau` (out-of-tree DKMS) | 2.4 + 5 GHz | Capable but **driver lags new kernels** (the 6.19 problem above) |
| Alfa AWUS036NH | Ralink RT3070 | `rt2800usb` (mainline) | 2.4 GHz only | Classic, mainline, reliable |

**Bottom line:** for a dual-band adapter that works in the VM today and on
the Pi later with zero driver pain, get the **Alfa AWUS036ACM (MT7612U)**
rather than the AWUS036ACH (RTL8812AU) you were considering. The ACH is
fine on a Pi with a matched kernel, but the ACM avoids the out-of-tree
driver entirely. If you only need 2.4 GHz, the AWUS036NHA (AR9271) is the
most bulletproof.

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
- [ ] Plug the adapter into the Mac.
- [ ] **VMware Fusion**: Settings → USB & Bluetooth → enable USB 3.x; then
      VM running → **Virtual Machine menu → USB & Bluetooth → Connect
      [adapter]**. (HID `config` tweaks are only for keyboard/mouse — not
      needed for Wi-Fi.)
- [ ] In the guest, confirm it's visible: `lsusb` (look for MediaTek /
      Atheros / Realtek depending on your adapter).

### A3. Driver
- [ ] **Mainline-driver adapter (MT7612U / AR9271 / MT7610U / RT3070) —
      RECOMMENDED:** nothing to install. The driver is in-kernel; plug in,
      `iw dev` should already show the interface. Skip to A4.
- [ ] **Only for Realtek RTL8812AU (AWUS036ACH):** out-of-tree DKMS —
      ```
      sudo apt install -y realtek-rtl88xxau-dkms linux-headers-$(uname -r)
      sudo dkms autoinstall && sudo modprobe 88XXau
      ```
      ⚠ On Kali kernel **6.19** this driver is `BUILD_EXCLUSIVE` and will
      NOT build (verified 2026-06-28). Workarounds: use a mainline-driver
      adapter (best), boot an older kernel the driver supports, or wait for
      an updated package. This is the single reason to prefer MT7612U.
- [ ] Confirm interface: `iw dev` (expect `wlan0`/`wlx...`).

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
- [ ] Attach the adapter directly to a USB-3 (blue) port. On the Pi 5,
      prefer the USB-3 ports; ensure a 5V/5A (Pi 5) / 5V/3A (Pi 4) PSU —
      Wi-Fi injection draws power, brownouts cause dropouts.
- [ ] Mainline-driver adapter (MT7612U/AR9271): nothing to install. Only
      RTL8812AU needs the DKMS step from A3 (and a kernel it supports).

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
