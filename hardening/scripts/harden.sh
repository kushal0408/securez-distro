#!/bin/bash
#
# SecureZ+ OS — System Hardening Script
# harden.sh — Applied during ISO build and on first boot
#
# This script applies all hardening configurations.
#

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "  ${CYAN}[HARDEN]${NC} $1"; }
ok()  { echo -e "  ${GREEN}  ✅ $1${NC}"; }
warn(){ echo -e "  ${YELLOW}  ⚠  $1${NC}"; }

log "Applying SecureZ+ hardening..."

# ── 1. Sysctl Kernel Hardening ──────────────────────────────
log "Applying kernel sysctl hardening..."
cp /usr/share/securez/99-securez.conf /etc/sysctl.d/
sysctl --system > /dev/null 2>&1
ok "Kernel parameters hardened"

# ── 2. AppArmor Profiles ────────────────────────────────────
log "Loading AppArmor profiles..."
if command -v apparmor_parser &> /dev/null; then
    cp /usr/share/securez/apparmor/* /etc/apparmor.d/ 2>/dev/null || true
    systemctl enable apparmor
    apparmor_parser -r /etc/apparmor.d/usr.bin.szshell 2>/dev/null || true
    ok "AppArmor profiles loaded"
else
    warn "AppArmor not installed"
fi

# ── 3. Firewall ─────────────────────────────────────────────
log "Installing firewall rules..."
mkdir -p /etc/securez
cp /usr/share/securez/securez-firewall.nft /etc/securez/
ok "Firewall rules installed (activate via first-boot wizard)"

# ── 4. Disable Unnecessary Services ─────────────────────────
log "Disabling unnecessary services..."

DISABLE_SERVICES=(
    "cups"              # Printing (enable if needed)
    "avahi-daemon"      # mDNS (attack surface)
    "bluetooth"         # Bluetooth (enable if needed)
    "ModemManager"      # Modem management
    "whoopsie"          # Ubuntu error reporting (telemetry)
    "apport"            # Crash reporting (telemetry)
    "ubuntu-report"     # Ubuntu census (telemetry)
)

for svc in "${DISABLE_SERVICES[@]}"; do
    if systemctl is-enabled "$svc" 2>/dev/null | grep -q "enabled"; then
        systemctl disable "$svc" 2>/dev/null || true
        systemctl stop "$svc" 2>/dev/null || true
    fi
done
ok "Unnecessary services disabled"

# ── 5. Remove Telemetry Packages ────────────────────────────
log "Removing telemetry packages..."
REMOVE_PKGS=(
    "ubuntu-report"
    "popularity-contest"
    "whoopsie"
    "apport"
)

for pkg in "${REMOVE_PKGS[@]}"; do
    dpkg -l | grep -q "^ii  $pkg" && apt-get remove -y "$pkg" > /dev/null 2>&1 || true
done
ok "Telemetry packages removed"

# ── 6. Remove Snap ──────────────────────────────────────────
log "Removing snap (telemetry-heavy package manager)..."
if command -v snap &> /dev/null; then
    snap list 2>/dev/null | awk 'NR>1 {print $1}' | while read -r pkg; do
        snap remove --purge "$pkg" 2>/dev/null || true
    done
    apt-get remove -y snapd 2>/dev/null || true
    apt-mark hold snapd 2>/dev/null || true
    ok "Snap removed and held"
else
    ok "Snap not present"
fi

# ── 7. Secure File Permissions ──────────────────────────────
log "Hardening file permissions..."

chmod 0700 /root
chmod 0600 /etc/securez/* 2>/dev/null || true
chmod 0700 /etc/securez
chmod 0644 /etc/sysctl.d/99-securez.conf

# Restrict cron
chmod 0700 /etc/cron.d 2>/dev/null || true
chmod 0700 /etc/cron.daily 2>/dev/null || true
chmod 0700 /etc/cron.hourly 2>/dev/null || true

ok "File permissions hardened"

# ── 8. SSH Hardening (if installed) ─────────────────────────
if [ -f /etc/ssh/sshd_config ]; then
    log "Hardening SSH..."

    # Create hardened SSH config drop-in
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/99-securez.conf << 'SSHEOF'
# SecureZ+ SSH Hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
Protocol 2
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
SSHEOF

    ok "SSH hardened (root login disabled, password auth disabled)"
else
    ok "SSH not installed (good — smaller attack surface)"
fi

# ── 9. Set Up CrypticEngine Directories ─────────────────────
log "Setting up CrypticEngine directories..."
mkdir -p /etc/securez
mkdir -p /var/lib/securez
mkdir -p /mnt/securez-vault
mkdir -p /tmp/securez-sessions
chmod 0700 /etc/securez /var/lib/securez /mnt/securez-vault /tmp/securez-sessions
ok "CrypticEngine directories created"

# ── 10. Enable Security Services ────────────────────────────
log "Enabling security services..."
systemctl enable crypticd.service 2>/dev/null || true
systemctl enable securez-firstboot.service 2>/dev/null || true
ok "Security services enabled"

# ── Done ────────────────────────────────────────────────────
echo ""
log "✅ SecureZ+ hardening complete!"
echo ""
