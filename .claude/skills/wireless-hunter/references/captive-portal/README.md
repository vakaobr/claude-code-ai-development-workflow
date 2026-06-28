# Workshop Captive Portal

A brandable "free wifi" captive portal for `wireless-hunter` awareness
workshops, with **Continue with Google / Microsoft / GitHub** buttons.

**Safe by default:** buttons go to an awareness "gotcha" page (`aware.html`).
The portal NEVER sees or stores credentials - it only logs the *fact* a
button was clicked (`submissions.log`: timestamp, client IP, provider) so
you can show click-rates. The live adversary-in-the-middle (evilginx) part
is opt-in, consent-gated, and uses a test account.

## Files
- `index.html` / `style.css` - the splash (rebrand freely: SSID, logo, copy).
- `aware.html` - the lesson page (AiTM, why MFA fails, use passkeys).
- `portal.py` - tiny stdlib web server (no deps); handles OS captive
  probes, `/go?provider=`, logging, and the safe-vs-live redirect.
- `hostapd.conf` / `dnsmasq.conf` - open AP + captive DNS templates.

## Run the portal only (quick test / on the AP host)
```bash
sudo PORT=80 python3 portal.py     # serves on :80 ; logs to ./submissions.log
# visit http://<host>/  -> click a button -> lands on /aware (safe mode)
```

## Full rogue-AP bring-up (consent + signage required)
```bash
sudo ip addr add 10.0.0.1/24 dev wlan1 && sudo ip link set wlan1 up
sudo hostapd ./hostapd.conf &           # open "CityCafe Guest WiFi"
sudo dnsmasq -C ./dnsmasq.conf -d &     # DHCP + DNS-to-portal
sudo PORT=80 python3 portal.py          # the splash
# (optional) give clients internet via your uplink:
#   sudo sysctl -w net.ipv4.ip_forward=1
#   sudo iptables -t nat -A POSTROUTING -o <uplink> -j MASQUERADE
```
Gate: `red_team_ops.wireless: approved` + `wireless_workshop_consent`.
Tear down: kill hostapd/dnsmasq/portal, flush iptables, `airmon-ng stop`.

## Enabling the LIVE evilginx demo (advanced, high-rigor)
This is what proves social-login can be phished end-to-end, MFA included.
Do this ONLY under `social-engineering-hunter` gates: `se_consent_ref`,
`se_evilginx: approved`, and against a **seeded TEST account you control**
 - never an attendee's real account.

What evilginx needs (it is NOT a captive portal - it's a reverse proxy
that mirrors the REAL provider page; you don't design its look, you load a
*phishlet*):
1. A **domain you own** + DNS A record → the evilginx host.
2. A **valid TLS cert** (evilginx does Let's Encrypt automatically).
3. A loaded **phishlet** for the provider (`phishlets enable google …`),
   then a **lure**: `lures create google` → `lures get-url <id>`.
4. Put those lure URLs into the portal and flip live mode:
   ```bash
   sudo LIVE_AITM=true \
        LURE_GOOGLE="https://<your-evilginx-domain>/<lure>" \
        LURE_MICROSOFT="https://<your-evilginx-domain>/<lure>" \
        LURE_GITHUB="https://<your-evilginx-domain>/<lure>" \
        PORT=80 python3 portal.py
   ```
   Now a button → evilginx → the real provider; evilginx captures the
   session/MFA token to demonstrate the bypass.

### Reality + ethics check
- **Providers fight this.** Google/Microsoft/GitHub deploy anti-AiTM
  measures; phishlets break often and may show warnings. Treat a live demo
  as best-effort and rehearse it.
- **Passkeys/FIDO2 defeat it** - that's the headline lesson. If the test
  account uses a passkey, evilginx CANNOT replay it. Demo that contrast.
- **Test account only.** Destroy captured tokens immediately after proof
  (per `social-engineering-hunter`). Never proxy attendees' real logins.
- For most workshops the **safe mode is enough** - clicking through to the
  `/aware` page already lands the point without touching real providers.
