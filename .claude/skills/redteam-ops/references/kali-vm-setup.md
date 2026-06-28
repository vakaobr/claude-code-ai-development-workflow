# Kali Linux Operator VM — Reproducible Setup (Apple Silicon / VMware Fusion)

The Linux box the executable red-team-ops AND DFIR hunters run from. Built
and verified 2026-06-28 on an Apple M3 Pro (arm64), macOS 26, VMware
Fusion 26. Rebuild from this in ~30-40 min (mostly the GUI install +
compiles).

> Software tooling only. Wireless monitor mode is a separate concern —
> see `../../wireless-hunter/references/capture-host-setup.md` (driver/
> kernel caveat) and prefer a mainline-driver adapter.

---

## 1. Host prep (macOS)
- Need ~40 GB free. (We reclaimed it via `docker system prune -a` +
  `docker volume prune` — 37 GB.)
- VMware Fusion 13+/26 (free personal use; manual Broadcom-account
  download — no Homebrew cask anymore).

## 2. Get + verify the ISO
```bash
cd ~/Downloads
curl -fL -o kali-linux-2026.2-installer-arm64.iso \
  https://kali.download/base-images/kali-2026.2/kali-linux-2026.2-installer-arm64.iso
# verify against the official SHA256SUMS (base-images dir)
shasum -a 256 kali-linux-2026.2-installer-arm64.iso
# expected (2026.2): b9a08050ee522fbee7cac703b1bc48178f79eb974c962d4ed9dc1ccfdfa77fb6
```
Kali ships **no prebuilt arm64 VM image** — only the installer ISO. So it's
an ISO install either way.

## 3. Create the VM (scripted with Fusion's vmcli)
```bash
export PATH="/Applications/VMware Fusion.app/Contents/Public:/Applications/VMware Fusion.app/Contents/Library:$PATH"
VMDIR="$HOME/Virtual Machines"; mkdir -p "$VMDIR"; cd "$VMDIR"
vmcli VM Create -n "Kali-2026.2-arm64" -d "$VMDIR" -c arm-debian12-64
# vmcli's skeleton is minimal (512 MB, no disk attached) — fix it:
rm -f Kali-2026.2-arm64.vmdk
vmware-vdiskmanager -c -s 40GB -a nvme -t 0 "Kali-2026.2-arm64.vmdk"
```
Then write the `.vmx` (key lines — full file in git history of this repo):
```
guestOS = "arm-debian12-64"
firmware = "efi"
numvcpus = "4"
memsize = "6144"
nvme0.present = "TRUE"
nvme0:0.present = "TRUE"
nvme0:0.fileName = "Kali-2026.2-arm64.vmdk"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "/Users/<you>/Downloads/kali-linux-2026.2-installer-arm64.iso"
sata0:0.startConnected = "TRUE"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "vmxnet3"
usb_xhci.present = "TRUE"
```
Power on: `vmrun -T fusion start "$VMDIR/Kali-2026.2-arm64.vmx" gui`

## 4. Install Kali (GUI — can't be scripted)
Graphical install → user + password → **Guided, entire disk** (the 40 GB
nvme) → default software selection (XFCE + Kali default) → GRUB to
`/dev/nvme0n1` → reboot → **disconnect the CD** (VM menu → Removable
Devices) so it boots from disk.

## 5. Enable SSH + passwordless sudo (in the VM)
```bash
sudo systemctl enable --now ssh
# add your pubkey to ~/.ssh/authorized_keys, then (optional, lab convenience):
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/$USER
sudo chmod 0440 /etc/sudoers.d/$USER && sudo visudo -c
```
Get the guest IP from the host: `vmrun -T fusion getGuestIPAddress "<vmx>" -wait`

## 6. Toolset (run over SSH; user-level unless noted)
Already in Kali's default metapackage: nmap, netexec, hashcat, john,
radare2, gdb, binwalk, yara, aircrack-ng, tshark, sleuthkit (mmls/fls),
searchsploit, ghidra, gophish, pipx, git, 7z.

```bash
# apt (needs sudo): plaso + build deps for the source/cargo installs
sudo apt-get update
sudo apt-get install -y plaso cargo golang-go git

# plaso on Kali ships as plaso-* — add the .py names the skills expect
mkdir -p ~/.local/bin
ln -sf /usr/bin/plaso-log2timeline ~/.local/bin/log2timeline.py
ln -sf /usr/bin/plaso-psort        ~/.local/bin/psort.py
ln -sf /usr/bin/plaso-pinfo        ~/.local/bin/pinfo.py

# Python tools (pipx, user-level)
pipx ensurepath
pipx install volatility3        # -> vol, volshell
pipx install flare-capa         # capa (RE)
pipx install flare-floss        # floss (RE)

# rustscan (no prebuilt binary anymore -> compile)
cargo install rustscan          # -> ~/.cargo/bin/rustscan
ln -sf ~/.cargo/bin/rustscan ~/.local/bin/rustscan

# chainsaw (aarch64 binary + rules)
cd /tmp && curl -fsSL -o cs.zip \
  "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.16.0/chainsaw_all_platforms%2Brules.zip"
mkdir -p ~/tools/chainsaw && unzip -q cs.zip -d /tmp/cs
cp "$(find /tmp/cs -name 'chainsaw_aarch64-unknown-linux-gnu')" ~/tools/chainsaw/chainsaw
chmod +x ~/tools/chainsaw/chainsaw
for d in rules mappings sigma; do cp -r "$(find /tmp/cs -type d -name $d|head -1)" ~/tools/chainsaw/; done
ln -sf ~/tools/chainsaw/chainsaw ~/.local/bin/chainsaw

# hayabusa (lin aarch64 + rules)
curl -fsSL -o hb.zip \
  "https://github.com/Yamato-Security/hayabusa/releases/download/v3.9.0/hayabusa-3.9.0-lin-aarch64-gnu.zip"
mkdir -p ~/tools/hayabusa && unzip -q hb.zip -d ~/tools/hayabusa
hb=$(find ~/tools/hayabusa -name 'hayabusa*-lin-aarch64-gnu'); chmod +x "$hb"
ln -sf "$hb" ~/.local/bin/hayabusa

# evilginx (no arm64 binary upstream -> Go source build)
git clone --depth 1 -b v3.3.0 https://github.com/kgretzky/evilginx2 ~/tools/evilginx-src
cd ~/tools/evilginx-src && make
ln -sf ~/tools/evilginx-src/build/evilginx ~/.local/bin/evilginx
```

## 7. Verify
```bash
for t in rustscan vol chainsaw hayabusa evilginx gophish log2timeline.py psort.py \
         capa floss nmap netexec hashcat radare2 gdb ghidra binwalk yara aircrack-ng \
         tshark mmls fls searchsploit; do
  printf '%-16s %s\n' "$t" "$(command -v $t || echo MISSING)"; done
```
All present = the VM can run every executable red-team-ops + DFIR hunter.

## Notes
- `~/.local/bin` is on PATH via `pipx ensurepath` (login shells). Use
  `ssh user@vm 'bash -lc "..."'` for non-interactive runs that need it.
- Wireless (`aircrack-ng` is installed) needs a monitor-mode adapter +
  a kernel-compatible driver — see the capture-host doc; on arm64 + Kali
  6.19 the RTL8812AU DKMS won't build, so use a mainline-driver adapter
  (MT7612U) or the Pi.
- Snapshot the VM after step 7 so you can roll back between engagements.
