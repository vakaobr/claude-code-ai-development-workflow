---
name: wireless-hunter
description: "Authorized Wi-Fi assessment and security-awareness demos run from a LINUX capture host (a VM with USB passthrough is the primary supported setup; a Raspberry Pi 4/5 is the documented portable alternative) with a monitor-mode adapter such as the Alfa AWUS036ACH (RTL8812AU). Covers passive survey (airodump-ng/kismet), WPA(2/3) handshake/PMKID capture for offline cracking (handed to cracking-hunter), rogue-AP / evil-twin and captive-portal awareness demos (hostapd + dnsmasq), and post-association traffic analysis (tshark) to show attendees what leaks on an open network (plaintext DNS, TLS SNI, probe requests, cleartext HTTP). Requires .claude/security-scope.yaml red_team_ops.wireless: approved + workshop/consent fields. Needs RF hardware + physical proximity; cannot run on macOS directly. Grounded in redteam-ops."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(iw:*), Bash(iwconfig:*), Bash(airmon-ng:*), Bash(airodump-ng:*),
  Bash(aireplay-ng:*), Bash(aircrack-ng:*), Bash(kismet:*),
  Bash(hcxdumptool:*), Bash(hcxpcapngtool:*), Bash(wifite:*),
  Bash(hostapd:*), Bash(hostapd-mana:*), Bash(dnsmasq:*), Bash(bettercap:*),
  Bash(tshark:*), Bash(tcpdump:*), Bash(capinfos:*),
  Bash(sha256sum:*), Bash(jq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: wireless
  authorization_required: true
  tier: T2
  profile: wireless
  source_methodology: "redteam-ops (aircrack-ng/hostapd/kismet docs)"
  service_affecting: true
  red_team_ops: true
  requires_hardware: true
  composed_from: [redteam-ops, cracking-hunter]
---

# Wireless Hunter

## Goal

Run authorized Wi-Fi assessments and, importantly for your workshops,
security-awareness demonstrations that show people — concretely — what
leaks when they join an unknown open network. Capabilities: passive RF
survey, WPA2/WPA3 handshake/PMKID capture for offline cracking (handed to
`cracking-hunter`), rogue-AP / evil-twin + captive-portal demos, and
post-association traffic analysis that surfaces the honest risk story
(plaintext DNS, TLS SNI hostnames, device probe requests, cleartext HTTP)
— and therefore why VPN + encrypted DNS matter.

> **This skill needs RF hardware and physical proximity and cannot run on
> macOS directly.** It drives a **Linux capture host**. See Capture-Host
> Setup below.

## When to Use

- An authorized Wi-Fi assessment or a consented security-awareness
  workshop is in scope: `red_team_ops.wireless: approved` (+ workshop
  consent fields for any rogue-AP/attendee-capture demo).
- You have a monitor-mode/injection adapter (e.g. Alfa AWUS036ACH,
  RTL8812AU) attached to the Linux capture host.

## When NOT to Use

- From macOS directly — RTL8812AU monitor mode/injection is unsupported
  on macOS (esp. Apple Silicon). Use the Linux capture host.
- Against networks/SSIDs not in scope, or capturing real attendees'
  traffic without explicit workshop consent and signage.
- WPA passphrase cracking itself — capture here, hand the handshake/PMKID
  to `cracking-hunter` (offline).
- Bluetooth/Zigbee/SDR or other RF — out of this skill's 802.11 scope.

## Capture-Host Setup (read before running)

**Primary (supported now): VM + USB passthrough.**
- Linux guest (Kali/Ubuntu) in the VM; pass the USB Wi-Fi adapter through
  to the guest (VMware/VirtualBox USB passthrough on Intel hosts is most
  reliable; on Apple Silicon, USB Wi-Fi monitor-mode passthrough via
  UTM/QEMU is unreliable — prefer an Intel host or the Pi path).
- Install the RTL8812AU driver in the guest
  (`aircrack-ng/rtl8812au` DKMS). Verify monitor mode:
  `iw dev`, then `airmon-ng start wlan0` → confirm a `*mon` interface.

**Documented alternative (portable, recommended for workshops): Raspberry
Pi 4/5.**
- Kali/Raspberry Pi OS on the Pi; attach the adapter directly (no
  passthrough layer). Same driver + `airmon-ng` verification. The Pi is
  the most reliable + portable workshop rig; the agent drives it over SSH.
- Keep the methodology identical across VM and Pi — only the host differs.

Always confirm the adapter reports monitor mode + injection
(`aireplay-ng --test`) before relying on capture results.

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. If missing/placeholder, halt.
2. Confirm `red_team_ops.wireless: approved` and the target SSIDs/BSSIDs
   or workshop are in `red_team_ops.wireless_targets`.
3. **Rogue-AP / attendee capture requires consent**: confirm
   `red_team_ops.wireless_workshop_consent` (signed) and that attendees
   are informed (signage/briefing). This skill is `service_affecting:
   true` — deauth/evil-twin disrupt RF; get per-invocation confirmation.
4. Pick a non-conflicting channel and bounded TX power; never jam or
   deauth networks outside scope.
5. Append a `running` row to the Skills Run Log.

## Inputs

- `{issue}`, `{host}` (VM or Pi capture host + interface), `{targets}`
- `{mode}`: survey | handshake | workshop-demo
- `{consent_ref}`: required for workshop-demo

## Methodology

### Phase 1: Survey (passive)
1. **Enumerate the RF environment.**
   Do: `airmon-ng start {iface}`; `airodump-ng {mon}` (and/or `kismet`)
   to list APs, channels, encryption, clients, signal. Record the
   in-scope target set. Note rogue/mis-secured APs (open, WEP, WPS-on).

### Phase 2: Handshake / PMKID Capture (authorized targets)
2. **Capture for offline cracking.**
   Do: target the in-scope BSSID/channel with `airodump-ng -c {ch}
   --bssid {bssid} -w cap`; capture a WPA handshake (optionally a single,
   scoped `aireplay-ng` deauth to speed it — only against in-scope
   clients) or PMKID via `hcxdumptool`. Convert with `hcxpcapngtool`.
   Hand the result to `cracking-hunter` (offline) — do NOT crack here.

### Phase 3: Workshop Rogue-AP / Evil-Twin Demo (consent-gated)
3. **Stand up the demo AP.**
   Do: with consent + signage, `hostapd` (open "Free WiFi" SSID) +
   `dnsmasq` (DHCP/DNS) on the capture host; optional captive portal that
   shows an awareness page (and, for a credential-awareness demo, a benign
   fake login that records only the FACT of submission, never real
   creds). `bettercap` can drive this too.
4. **Show what leaks (the teachable moment).**
   Do: on the AP's uplink, `tshark` to surface, live: DNS queries
   (plaintext), TLS `Client Hello` SNI (hostnames visited), HTTP cleartext
   requests, and device probe requests (preferred-network names) seen in
   the survey. Present these to attendees as "this is visible without
   your VPN/encrypted DNS." Capture screenshots for the report.

### Phase 4: Wrap & Teardown
5. **Stop and clean up.**
   Do: tear down the rogue AP, stop monitor mode (`airmon-ng stop`),
   restore managed mode. Purge any captured attendee traffic beyond the
   anonymized teaching examples; keep only what consent allows.

## Output Format

Findings/report append to `.claude/planning/{issue}/07a_SECURITY_AUDIT.md`
(or a workshop report) per `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:
- **CWE**: CWE-319 (cleartext transmission), CWE-326/CWE-327 (weak Wi-Fi
  crypto — WEP/WPA-TKIP/WPS), CWE-294 (auth bypass by capture-replay).
- **ATT&CK**: T1011 (exfil over other medium), T1557 (AiTM), T1040
  (network sniffing); rogue AP = T1557-style.
- **Evidence**: survey table (SSID/enc/channel/clients), handshake/PMKID
  capture file hash (handed to cracking-hunter), and for the workshop:
  anonymized leak examples (DNS/SNI/HTTP) + screenshots. No real attendee
  credentials, ever.
- **Remediation framing**: WPA3-SAE / 802.1X, disable WEP/WPS/TKIP, client
  guidance (always-on VPN, encrypted DNS/DoH, disable auto-join, forget
  open networks), rogue-AP detection (WIDS).
- Updates `STATUS.md` and the Skills Run Log.

## Quality Check (Self-Review)

- [ ] `wireless` gate verified; rogue-AP/attendee demo had signed consent + signage
- [ ] Ran from the Linux capture host (VM passthrough or Pi), monitor+injection confirmed
- [ ] Deauth/evil-twin limited to in-scope targets; no out-of-scope jamming
- [ ] Handshakes/PMKID handed to cracking-hunter (no in-skill cracking)
- [ ] No real attendee credentials stored; captures purged per consent at teardown
- [ ] Adapter restored to managed mode; demo AP torn down
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **macOS dead-end**: RTL8812AU won't do monitor mode on macOS — always
  use the Linux host. Apple-Silicon USB passthrough is flaky; prefer Pi
  or an Intel VM host.
- **Driver/monitor failures**: wrong/missing RTL8812AU DKMS driver →
  no monitor mode or no injection. Verify with `aireplay-ng --test`
  before trusting results.
- **Regulatory/Tx power + channels**: respect local RF regulations; don't
  exceed legal TX power or use disallowed channels.
- **HTTPS reality for the demo**: most traffic is TLS — you will NOT show
  page contents. The honest, still-compelling story is DNS + SNI +
  probe-requests + cleartext HTTP. Set attendee expectations accordingly.
- **Collateral disruption**: broad deauth harms bystander networks and
  may be illegal. Scope tightly; this is why the skill is service-affecting.

## References

- aircrack-ng: https://www.aircrack-ng.org/ — Kismet: https://www.kismetwireless.net/
- hostapd / dnsmasq; hcxdumptool/hcxtools; bettercap: https://www.bettercap.org/
- Alfa AWUS036ACH (RTL8812AU) + aircrack-ng/rtl8812au driver
- MITRE ATT&CK: T1557, T1040, T1011

## Source Methodology

Grounded in `redteam-ops` (section 4) and `cracking-hunter` (offline
handoff), authored from aircrack-ng / hostapd / kismet documentation.
Tool shortlist cross-checked against awesome-pentest (CC-BY-4.0).
Conversion date: 2026-06-28.
