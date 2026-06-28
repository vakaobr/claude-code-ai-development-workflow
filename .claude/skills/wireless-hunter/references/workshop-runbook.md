# Security-Awareness Wi-Fi Workshop — Runbook

Turnkey companion to `capture-host-setup.md`. This is the attendee-facing
talk track plus the slide-worthy "what leaked / what didn't" summary for
the "free wifi" awareness demo run by `wireless-hunter`.

> Run only with `red_team_ops.wireless: approved` and
> `wireless_workshop_consent` set, and with attendees informed (signage +
> verbal briefing). The point is to teach, not to embarrass — keep
> everything aggregated and anonymous.

> **Captive portal ≠ evilginx (important).** The "free wifi" splash /
> awareness page in this workshop is a plain **captive portal** you build
> yourself: `hostapd` (the open AP) + `dnsmasq` (DHCP/DNS) + a tiny web
> server (`python3 -m http.server`, nginx, or `bettercap`'s `http-ui`)
> serving **your own HTML/CSS** — so yes, the look & feel is 100%
> yours (brand it as "Airport WiFi", a hotel portal, etc.).
> **evilginx is a different tool for a different job**: it's a
> reverse-proxy man-in-the-middle that *mirrors a real site* (e.g. a real
> M365 login) to capture session cookies / MFA tokens — you do NOT design
> its look (it proxies the genuine page); you configure it via *phishlets*
> (YAML) + lures. Use evilginx (via `social-engineering-hunter`, separately
> consented) only to PROVE MFA-phishing risk — not for the captive-portal
> splash. For this awareness demo, keep the portal benign: it records the
> *fact* of a submission for the teachable moment, never real credentials.

---

## 0. Pre-flight (the day before / morning of)

- [ ] Capture host ready and verified (see `capture-host-setup.md`):
      monitor mode + `aireplay-ng --test` pass. On Apple Silicon, use the
      Raspberry Pi — not a VM.
- [ ] Two interfaces: one for the rogue AP (Alfa), one for uplink
      (tether/ethernet). Never put management/SSH on the AP interface.
- [ ] Consent slide + physical signage printed ("This network is part of
      a live security demo; traffic may be displayed in aggregate").
- [ ] A throwaway demo device you control (phone/laptop) to drive the
      visible examples, so you never depend on a real attendee's data.
- [ ] Decide the SSID (e.g. "Conference_Free_WiFi", "Airport_Guest").
- [ ] tshark filters pre-loaded (below). Dry-run once end to end.

---

## 1. Talk track (≈15-20 min)

**Hook (1 min).** "Show of hands: who has joined an open Wi-Fi at an
airport, café, or hotel? Today we ARE that network. Connect to
`<SSID>` — with your consent — and let's see what it can see."

**Connect (2 min).** Attendees join the open SSID. On screen, show the
association events / probe requests appearing (`airodump-ng`). Narrate:
"Your device just told everyone nearby every network name it remembers —
that alone can map where you live, work, and travel."

**The reveal — DNS (3 min).** Visit a few sites on YOUR demo device.
Show plaintext DNS queries scrolling. "Even though the sites are HTTPS,
the *names* of everything you look up are in clear text unless you use
encrypted DNS. Your bank, your health provider, your dating app — the
network sees the lookups."

**The reveal — SNI (3 min).** Show the TLS Client Hello SNI field.
"When your encrypted connection starts, the destination hostname is
still visible here. Encryption protects the *contents*, not always the
*who you're talking to*."

**The reveal — cleartext HTTP (2 min).** Hit any plain-HTTP endpoint
(or a device doing captive-portal checks / app telemetry over HTTP).
Show full URLs/headers. "Anything not HTTPS — some apps, some IoT, some
old sites — is fully readable."

**The captive-portal moment (3 min, optional, gated).** Show the benign
fake login. "A network can also just *ask* you to log in, and many people
will type a password into a page they didn't verify. We record only that
a submission happened — never your actual password."

**The turn — what protected you (3 min).** Re-run one lookup over a VPN
+ encrypted DNS. Show the difference: now it's one tunnel to one
endpoint; DNS and SNI go dark. "This is the fix, and it's free or cheap."

**Close (1 min).** Hand out the takeaways card (section 3). "You don't
have to fear public Wi-Fi — you have to prepare for it."

---

## 2. The "what leaked vs what didn't" summary (slide)

| Visible to the open network | NOT visible (with HTTPS) |
|---|---|
| **DNS queries** (sites you look up) — unless encrypted DNS | Page contents / messages over HTTPS |
| **TLS SNI** (destination hostnames) — unless ECH | Passwords sent over HTTPS forms |
| **Probe requests** (your remembered network names) | HTTPS request/response bodies |
| **Cleartext HTTP** (full URLs, headers, data) | Anything inside a VPN tunnel |
| Device identifiers (MAC unless randomized), traffic volume/timing | — |
| Anything you type into a **captive portal** page | — |

Honest framing for the slide: "Modern HTTPS hides the *contents*. The
open network still learns a lot about *who* and *what* you connect to —
and everything for non-HTTPS traffic."

---

## 3. Attendee takeaways (handout / final slide)

1. **Use a VPN** on untrusted networks — it collapses all of the above
   into one encrypted tunnel.
2. **Turn on encrypted DNS** (DoH/DoT) — hides your lookups even without
   a VPN. (iOS/Android/browsers support it; or a profile.)
3. **Disable auto-join** for open networks and **"forget" old ones** —
   stops silent reconnection and quiets your probe requests.
4. **Never enter credentials on a captive-portal page** — open a known
   site yourself; verify the padlock and domain.
5. **Prefer your phone's hotspot** over open Wi-Fi when handling anything
   sensitive.
6. **Keep devices updated** — randomized MAC, ECH, and modern TLS reduce
   what leaks.

---

## 4. tshark quick-reference (operator screen)

```bash
# Plaintext DNS queries
sudo tshark -i <uplink> -Y "dns.flags.response==0" -T fields -e dns.qry.name

# TLS SNI (destination hostnames)
sudo tshark -i <uplink> -Y "tls.handshake.extensions_server_name" \
     -T fields -e tls.handshake.extensions_server_name

# Cleartext HTTP (host + path)
sudo tshark -i <uplink> -Y "http.request" -T fields -e http.host -e http.request.uri

# Probe requests (remembered SSIDs) — on the monitor interface
sudo airodump-ng wlan0mon
```

Display tip: pipe to `| sort -u` or a large-font terminal so the room can
read it. Keep your own demo device generating the traffic.

---

## 5. Ethics / cleanup (every time)

- [ ] Only the consented SSID/area; tear the AP down at the end.
- [ ] Purge captured attendee traffic beyond the anonymized teaching
      examples (per consent). No real credentials stored, ever.
- [ ] Restore adapter to managed mode (`airmon-ng stop`).
- [ ] Note the run in the engagement/workshop record.

## References
- Capture-host setup: `capture-host-setup.md`
- Skill: `../SKILL.md` (`wireless-hunter`)
- DoH/DoT, ECH, MAC randomization vendor docs for the takeaways slide
