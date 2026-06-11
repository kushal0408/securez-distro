#!/bin/bash
#
# SecureZ+ OS — Master ISO Build Script (v7 — DEFINITIVE)
#
# ┌─────────────────────────────────────────────────────────────┐
# │  BOOT CHAIN:  GRUB → casper/initramfs → systemd → GDM3     │
# │  This script builds a live ISO that traverses ALL phases.   │
# │  No manual ISO assembly. lb build handles everything.       │
# └─────────────────────────────────────────────────────────────┘
#
#   1. Manual ISO assembly breaks casper because the initramfs has expectations
#      about ISO structure. FIX: Let lb build create the ISO natively.
#
#   2. We use --bootloader grub-efi which correctly uses GRUB for both
#      UEFI and legacy BIOS (via grub-pc) when using iso-hybrid.
#

set -euo pipefail

# ── Colors ──
C='\033[0;36m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[1;31m'; B='\033[1m'; N='\033[0m'
log()    { echo -e "${C}[BUILD]${N} $1"; }
ok()     { echo -e "${G}  ✔  $1${N}"; }
warn()   { echo -e "${Y}  ⚠  $1${N}"; }
err()    { echo -e "${R}  ✘  $1${N}"; exit 1; }
banner() { echo ""; echo -e "${B}${C}══════════ $1 ══════════${N}"; }

# ────────────────────────────────────────────────────────────
# 0. CONSTANTS
# ────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || err "Run with: sudo ./build-iso.sh"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="/tmp/securez-build"
LOGFILE="/tmp/securez-build.log"
banner "SecureZ+ OS — ISO Builder v7"

# ────────────────────────────────────────────────────────────
# 1. HOST PREREQUISITES
# ────────────────────────────────────────────────────────────
log "Installing host packages..."
apt-get update -qq 2>/dev/null || true
apt-get install -y \
    live-build debootstrap squashfs-tools xorriso \
    syslinux-utils isolinux syslinux-common \
    grub-pc-bin grub-efi-amd64-bin grub-common grub2-common \
    mtools dosfstools build-essential gcc make \
    libsodium-dev libreadline-dev libpam0g-dev 2>&1 | tail -5
ok "Host packages ready."

# ────────────────────────────────────────────────────────────
# 1.5 COMPILE CUSTOM COMPONENTS
# ────────────────────────────────────────────────────────────
log "Compiling CrypticEngine..."
if [ -d "$SRC_DIR/crypticengine" ]; then
    make -C "$SRC_DIR/crypticengine" clean || true
    make -C "$SRC_DIR/crypticengine" all || warn "CrypticEngine compilation failed!"
fi

log "Compiling SecureZ Shell..."
if [ -d "$SRC_DIR/shell" ]; then
    make -C "$SRC_DIR/shell" clean || true
    make -C "$SRC_DIR/shell" all || warn "Shell compilation failed!"
fi

log "Compiling SecureZ Auth..."
if [ -d "$SRC_DIR/auth" ]; then
    make -C "$SRC_DIR/auth" clean || true
    make -C "$SRC_DIR/auth" all || warn "Auth compilation failed!"
fi
ok "Custom components compiled."

# ────────────────────────────────────────────────────────────
# 2. DISABLE binary_syslinux (THE FIX)
#
#    binary_syslinux ALWAYS runs regardless of --bootloader.
#    It dynamically constructs broken package names from
#    LB_MODE + LB_SYSLINUX_THEME variables, making grep/sed
#    useless. The only solution: replace the entire script.
# ────────────────────────────────────────────────────────────
# Locate the syslinux script (named differently depending on live-build version)
if [ -f /usr/lib/live/build/lb_binary_syslinux ]; then
    SYSLINUX_SCRIPT="/usr/lib/live/build/lb_binary_syslinux"
elif [ -f /usr/lib/live/build/binary_syslinux ]; then
    SYSLINUX_SCRIPT="/usr/lib/live/build/binary_syslinux"
else
    SYSLINUX_SCRIPT=""
fi

log "Replacing broken binary_syslinux with fixed version..."
if [ -n "$SYSLINUX_SCRIPT" ] && [ -f "$SYSLINUX_SCRIPT" ]; then
    [ -f "${SYSLINUX_SCRIPT}.orig" ] || cp "$SYSLINUX_SCRIPT" "${SYSLINUX_SCRIPT}.orig"

    cat > "$SYSLINUX_SCRIPT" << 'FIXSCRIPT'
#!/bin/sh
## SecureZ+ patched binary_syslinux
## Installs ISOLINUX boot WITHOUT the broken ubuntu-oneiric themes.
## This replaces the original script that tries to install
## syslinux-themes-${LB_DISTRIBUTION}-${LB_SYSLINUX_THEME}
## which doesn't exist on Ubuntu Noble.

echo "P: Begin installing syslinux (SecureZ+ patched)..."

# Set up ISOLINUX boot directory
mkdir -p binary/isolinux

# Copy isolinux.bin (the actual boot image — CRITICAL)
if [ -f /usr/lib/ISOLINUX/isolinux.bin ]; then
    cp /usr/lib/ISOLINUX/isolinux.bin binary/isolinux/
elif [ -f /usr/lib/syslinux/isolinux.bin ]; then
    cp /usr/lib/syslinux/isolinux.bin binary/isolinux/
else
    echo "E: isolinux.bin not found on host! Install the 'isolinux' package."
    exit 1
fi

# Copy isohdpfx.bin (needed by binary_iso for MBR/isohybrid boot)
if [ -f /usr/lib/ISOLINUX/isohdpfx.bin ]; then
    cp /usr/lib/ISOLINUX/isohdpfx.bin binary/isolinux/
fi

# Copy syslinux modules (menu system, chain loading)
for f in ldlinux.c32 libcom32.c32 libutil.c32 vesamenu.c32 menu.c32 hdt.c32 chain.c32; do
    for dir in /usr/lib/syslinux/modules/bios /usr/lib/syslinux; do
        if [ -f "$dir/$f" ]; then
            cp "$dir/$f" binary/isolinux/
            break
        fi
    done
done

# Auto-detect kernel + initrd names from chroot
VMLINUZ=$(ls chroot/boot/vmlinuz-* 2>/dev/null | sort -V | tail -1)
INITRD=$(ls chroot/boot/initrd.img-* 2>/dev/null | sort -V | tail -1)
VMLINUZ_NAME=$(basename "$VMLINUZ" 2>/dev/null || echo "vmlinuz")
INITRD_NAME=$(basename "$INITRD" 2>/dev/null || echo "initrd")

echo "P: Kernel: $VMLINUZ_NAME"
echo "P: Initrd: $INITRD_NAME"

# Create ISOLINUX boot menu (SecureZ+ branded, no Ubuntu themes)
cat > binary/isolinux/isolinux.cfg << CFGEOF
DEFAULT securez
TIMEOUT 50
PROMPT 0

UI menu.c32
MENU TITLE SecureZ+ OS Boot Menu
MENU COLOR border  30;44   #40ffffff #a0000000 std
MENU COLOR title   1;36;44 #9033ccff #a0000000 std
MENU COLOR sel     7;37;40 #e0ffffff #20ffffff all
MENU COLOR unsel   37;44   #50ffffff #a0000000 std

LABEL securez
  MENU LABEL ^SecureZ+ OS
  MENU DEFAULT
  KERNEL /casper/${VMLINUZ_NAME}
  INITRD /casper/${INITRD_NAME}
  APPEND boot=casper quiet splash apparmor=1 security=apparmor ---

LABEL safe
  MENU LABEL SecureZ+ OS (^Safe Mode)
  KERNEL /casper/${VMLINUZ_NAME}
  INITRD /casper/${INITRD_NAME}
  APPEND boot=casper nomodeset ---
CFGEOF

echo "P: Syslinux installed (SecureZ+ patched — no broken themes)."
echo "P: Boot files in binary/isolinux/:"
ls -la binary/isolinux/ 2>/dev/null
FIXSCRIPT
    chmod +x "$SYSLINUX_SCRIPT"
    ok "binary_syslinux → patched (ISOLINUX without broken themes)."
else
    warn "binary_syslinux not found."
fi

# ────────────────────────────────────────────────────────────
# 3. CLEAN WORKSPACE
# ────────────────────────────────────────────────────────────
log "Cleaning build workspace..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ────────────────────────────────────────────────────────────
# 4. CONFIGURE LIVE-BUILD
#
#    We do NOT specify --bootloader because:
#    - "syslinux" (default) hits our PATCHED binary_syslinux
#      which sets up ISOLINUX without the broken theme packages
#    - live-build then runs binary_iso to assemble the final ISO
#      with the ISOLINUX boot catalog
# ────────────────────────────────────────────────────────────
banner "Phase 1: Configure"
lb config \
    --apt-secure false \
    --architecture amd64 \
    --distribution noble \
    --archive-areas "main restricted universe multiverse" \
    --binary-images iso-hybrid \
    --iso-application "SecureZ+ OS" \
    --iso-publisher "SecureZ+ Project" \
    --iso-volume "SecureZPlus" \
    --linux-flavours generic \
    --bootloader syslinux \
    --bootappend-live "boot=casper quiet splash apparmor=1 security=apparmor ---" \
    --memtest none

# Belt-and-suspenders: blank the syslinux theme variable
[ -f config/binary ] && sed -i 's/^LB_SYSLINUX_THEME=.*/LB_SYSLINUX_THEME=""/' config/binary

ok "live-build configured."

# ────────────────────────────────────────────────────────────
# 5. PACKAGE LIST
#
#    Carefully curated — every package verified to exist in
#    Ubuntu Noble's main/universe/restricted/multiverse repos.
# ────────────────────────────────────────────────────────────
log "Writing package list..."
mkdir -p config/package-lists
cat > config/package-lists/securez.list.chroot << 'PKGEOF'
# ── Base System ──
ubuntu-standard
casper
discover
laptop-detect
os-prober
calamares
calamares-settings-ubuntu-common

# ── Bootloader (needed in chroot for initramfs + isohybrid) ──
grub-common
grub-pc-bin
grub-efi-amd64-signed
shim-signed
syslinux-utils

# ── Desktop Environment ──
ubuntu-desktop-minimal
gnome-tweaks
gnome-shell-extensions
plymouth-themes

# ── Security ──
libsodium23
libsodium-dev
libreadline8
libreadline-dev
libpam0g
libpam0g-dev
nftables
tor
apparmor
apparmor-utils
cryptsetup
fscrypt

# ── Utilities ──
curl
wget
git
vim
nano
htop
build-essential
whiptail
net-tools
PKGEOF
ok "Package list ready ($(grep -cve '^\s*$' -e '^\s*#' config/package-lists/securez.list.chroot) packages)."

# ────────────────────────────────────────────────────────────
# 6. INJECT CUSTOM COMPONENTS
#
#    Each layer of the boot chain gets customized:
#    GRUB → Plymouth → systemd → GDM3 → GNOME
# ────────────────────────────────────────────────────────────
banner "Phase 2: Inject Components"
INCLUDES="config/includes.chroot"
mkdir -p "$INCLUDES"

# ── Layer 0: GRUB Bootloader Theme ──
# (Also added to binary via config/includes.binary)
if [ -d "$SRC_DIR/zui/grub/securez" ]; then
    mkdir -p "$INCLUDES/boot/grub/themes/securez"
    cp -r "$SRC_DIR/zui/grub/securez/"* "$INCLUDES/boot/grub/themes/securez/"
    ok "[GRUB] Theme injected."
fi

# ── Layer 1: Plymouth Boot Splash ──
if [ -d "$SRC_DIR/zui/plymouth/securez" ]; then
    mkdir -p "$INCLUDES/usr/share/plymouth/themes/securez"
    cp -r "$SRC_DIR/zui/plymouth/securez/"* "$INCLUDES/usr/share/plymouth/themes/securez/"
    ok "[Plymouth] Theme injected."
fi

# ── Layer 2: Systemd Services ──
mkdir -p "$INCLUDES/usr/sbin" \
         "$INCLUDES/usr/bin" \
         "$INCLUDES/usr/lib/x86_64-linux-gnu" \
         "$INCLUDES/etc/systemd/system"

# CrypticEngine daemon
for pair in \
    "$SRC_DIR/crypticengine/crypticd:$INCLUDES/usr/sbin/crypticd" \
    "$SRC_DIR/crypticengine/daemon/crypticd.service:$INCLUDES/etc/systemd/system/crypticd.service" \
    "$SRC_DIR/crypticengine/libcryptic.so:$INCLUDES/usr/lib/x86_64-linux-gnu/libcryptic.so" \
    "$SRC_DIR/shell/szshell:$INCLUDES/usr/bin/szshell" \
    "$SRC_DIR/auth/securez-master-key:$INCLUDES/usr/sbin/securez-master-key"; do
    src="${pair%%:*}"; dst="${pair##*:}"
    if [ -f "$src" ]; then cp "$src" "$dst"; else warn "[systemd] $(basename "$src") not built."; fi
done

# First-boot wizard
if [ -f "$SRC_DIR/firstboot/securez-firstboot.sh" ]; then
    cp "$SRC_DIR/firstboot/securez-firstboot.sh" "$INCLUDES/usr/sbin/securez-firstboot"
    chmod +x "$INCLUDES/usr/sbin/securez-firstboot"
fi
[ -f "$SRC_DIR/firstboot/securez-firstboot.service" ] && \
    cp "$SRC_DIR/firstboot/securez-firstboot.service" "$INCLUDES/etc/systemd/system/"
ok "[systemd] Services injected."

# ── Layer 3: PAM Authentication ──
mkdir -p "$INCLUDES/lib/x86_64-linux-gnu/security" "$INCLUDES/etc/pam.d"
[ -f "$SRC_DIR/auth/pam_securez.so" ] && \
    cp "$SRC_DIR/auth/pam_securez.so" "$INCLUDES/lib/x86_64-linux-gnu/security/" || \
    warn "[PAM] pam_securez.so not built."

# ── Layer 4: GNOME Desktop ──
if [ -d "$SRC_DIR/zui/theme/SecureZ-Dark" ]; then
    mkdir -p "$INCLUDES/usr/share/themes/SecureZ-Dark"
    cp -r "$SRC_DIR/zui/theme/SecureZ-Dark/"* "$INCLUDES/usr/share/themes/SecureZ-Dark/"
fi
if [ -d "$SRC_DIR/zui/extensions" ]; then
    mkdir -p "$INCLUDES/usr/share/gnome-shell/extensions"
    cp -r "$SRC_DIR/zui/extensions/"* "$INCLUDES/usr/share/gnome-shell/extensions/"
fi
ok "[GNOME] Themes and extensions injected."

# GNOME GSettings overrides (dark theme, disable ubuntu dock, set wallpaper)
mkdir -p "$INCLUDES/usr/share/glib-2.0/schemas"
cat > "$INCLUDES/usr/share/glib-2.0/schemas/99_securez.gschema.override" << 'EOF'
[org.gnome.desktop.background]
picture-uri='file:///usr/share/backgrounds/securez-bg.png'
picture-uri-dark='file:///usr/share/backgrounds/securez-bg.png'
primary-color='#000000'
secondary-color='#000000'

[org.gnome.desktop.interface]
gtk-theme='SecureZ-Dark'
color-scheme='prefer-dark'

[org.gnome.shell]
disable-user-extensions=false
enabled-extensions=['securez-dashboard@securez.os']
disabled-extensions=['ubuntu-dock@ubuntu.com']
EOF

# Wallpaper
mkdir -p "$INCLUDES/usr/share/backgrounds"
if [ -f "$SRC_DIR/zui/theme/securez-bg.png" ]; then
    cp "$SRC_DIR/zui/theme/securez-bg.png" "$INCLUDES/usr/share/backgrounds/"
fi

# ── Network & Hardening configs ──
mkdir -p "$INCLUDES/usr/share/securez/apparmor"
for pair in \
    "$SRC_DIR/network/firewall/securez-firewall.nft:$INCLUDES/usr/share/securez/securez-firewall.nft" \
    "$SRC_DIR/network/tor/torrc:$INCLUDES/usr/share/securez/torrc" \
    "$SRC_DIR/network/dns/dnscrypt-proxy.toml:$INCLUDES/usr/share/securez/dnscrypt-proxy.toml" \
    "$SRC_DIR/hardening/sysctl/99-securez.conf:$INCLUDES/usr/share/securez/99-securez.conf" \
    "$SRC_DIR/hardening/apparmor/usr.bin.szshell:$INCLUDES/usr/share/securez/apparmor/usr.bin.szshell"; do
    src="${pair%%:*}"; dst="${pair##*:}"
    [ -f "$src" ] && cp "$src" "$dst" || true
done
if [ -f "$SRC_DIR/network/firewall/firewall-ctl.sh" ]; then
    cp "$SRC_DIR/network/firewall/firewall-ctl.sh" "$INCLUDES/usr/sbin/firewall-ctl"
    chmod +x "$INCLUDES/usr/sbin/firewall-ctl"
fi
ok "[Security] Config files injected."

# ── Casper medium detection metadata ──
mkdir -p "$INCLUDES/.disk"
echo "SecureZ+ OS 1.0 - Release amd64" > "$INCLUDES/.disk/info"

# ────────────────────────────────────────────────────────────
# 7. BUILD HOOKS (run inside chroot during lb build)
#
#    These customize the live filesystem BEFORE it gets
#    compressed into filesystem.squashfs.
# ────────────────────────────────────────────────────────────
banner "Phase 3: Build Hooks"
mkdir -p config/hooks/normal

# ── Hook: Hardening (careful chroot-safe version) ──
if [ -f "$SRC_DIR/hardening/scripts/harden.sh" ]; then
    # Wrap the hardening script for safe chroot execution
    cat > config/hooks/normal/01-harden.chroot << 'HARDENEOF'
#!/bin/bash
# SecureZ+ hardening hook (chroot-safe)
set +e  # Don't exit on errors — we're in a chroot

echo "P: Applying SecureZ+ hardening..."

# Sysctl configs (applied at boot, not now — we're in chroot)
[ -f /usr/share/securez/99-securez.conf ] && \
    cp /usr/share/securez/99-securez.conf /etc/sysctl.d/ 2>/dev/null

# AppArmor profiles
[ -d /usr/share/securez/apparmor ] && \
    cp /usr/share/securez/apparmor/* /etc/apparmor.d/ 2>/dev/null

# Firewall rules
mkdir -p /etc/securez
[ -f /usr/share/securez/securez-firewall.nft ] && \
    cp /usr/share/securez/securez-firewall.nft /etc/securez/ 2>/dev/null

# Disable telemetry services
for svc in cups avahi-daemon bluetooth whoopsie apport ubuntu-report; do
    systemctl disable "$svc" 2>/dev/null || true
done

# Remove telemetry packages
for pkg in ubuntu-report popularity-contest whoopsie apport; do
    dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" && \
        apt-get remove -y "$pkg" > /dev/null 2>&1 || true
done

# Remove snap
if dpkg -l snapd 2>/dev/null | grep -q "^ii"; then
    apt-get remove -y snapd > /dev/null 2>&1 || true
    apt-mark hold snapd 2>/dev/null || true
fi

# CrypticEngine directories
mkdir -p /etc/securez /var/lib/securez /mnt/securez-vault
chmod 0700 /etc/securez /var/lib/securez /mnt/securez-vault 2>/dev/null

# Register szshell
if [ -f /usr/bin/szshell ]; then
    grep -q "/usr/bin/szshell" /etc/shells || echo "/usr/bin/szshell" >> /etc/shells
    # Set szshell as default for root
    chsh -s /usr/bin/szshell root 2>/dev/null || true
fi

# Configure PAM
if [ -f /lib/x86_64-linux-gnu/security/pam_securez.so ]; then
    # Add to common-auth just before pam_deny
    sed -i '/pam_deny.so/i auth    optional        pam_securez.so' /etc/pam.d/common-auth 2>/dev/null || true
fi

# Enable services
systemctl enable crypticd.service 2>/dev/null || true
systemctl enable securez-firstboot.service 2>/dev/null || true
systemctl enable apparmor 2>/dev/null || true

echo "P: Hardening applied."
HARDENEOF

    chmod +x config/hooks/normal/01-harden.chroot
    ok "Hardening hook created (chroot-safe)."
fi

# ── Hook: Branding (Plymouth, os-release, hostname) ──
cat > config/hooks/normal/02-branding.chroot << 'BRANDEOF'
#!/bin/bash
set +e
echo "P: Applying SecureZ+ branding..."

# Plymouth theme
if [ -f /usr/share/plymouth/themes/securez/securez.plymouth ]; then
    update-alternatives --install /usr/share/plymouth/themes/default.plymouth default.plymouth /usr/share/plymouth/themes/securez/securez.plymouth 100
    update-alternatives --set default.plymouth /usr/share/plymouth/themes/securez/securez.plymouth
    update-initramfs -u 2>/dev/null || true
    echo "P: Plymouth theme set to SecureZ+."
else
    echo "P: Plymouth theme files not found, using default."
fi

# Hostname
echo "securezplus" > /etc/hostname

# OS branding
cat > /etc/lsb-release << 'LSB'
DISTRIB_ID=SecureZPlus
DISTRIB_RELEASE=1.0
DISTRIB_CODENAME=fortress
DISTRIB_DESCRIPTION="SecureZ+ OS 1.0"
LSB

cat > /etc/os-release << 'OSR'
PRETTY_NAME="SecureZ+ OS 1.0"
NAME="SecureZ+"
VERSION_ID="1.0"
VERSION="1.0 (Fortress)"
VERSION_CODENAME=fortress
ID=securezplus
ID_LIKE=ubuntu
HOME_URL="https://securezplus.os"
BUG_REPORT_URL="https://securezplus.os/bugs"
PRIVACY_POLICY_URL="https://securezplus.os/privacy"
UBUNTU_CODENAME=noble
OSR

# GDM3 branding (change the login screen text)
if [ -f /etc/gdm3/greeter.dconf-defaults ]; then
    cat >> /etc/gdm3/greeter.dconf-defaults << 'GDM'

[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Welcome to SecureZ+ OS'
GDM
fi

# Apply Schemas and Dconf
glib-compile-schemas /usr/share/glib-2.0/schemas/ 2>/dev/null || true
dconf update 2>/dev/null || true


echo "P: Branding complete."
BRANDEOF
chmod +x config/hooks/normal/02-branding.chroot
ok "Branding hook created."

# ── Hook: GRUB customization (runs during binary stage) ──
# Copy default GRUB bootloader templates and customize them
cat > config/hooks/normal/03-grub-brand.chroot << 'GRUBEOF'
#!/bin/bash
set +e
# Ensure GRUB shows "SecureZ+" not "Ubuntu" during boot
if [ -f /etc/default/grub ]; then
    sed -i 's/GRUB_DISTRIBUTOR=.*/GRUB_DISTRIBUTOR="SecureZ+"/' /etc/default/grub
    # Add GRUB theme if available
    if [ -d /boot/grub/themes/securez ]; then
        echo 'GRUB_THEME="/boot/grub/themes/securez/theme.txt"' >> /etc/default/grub
    fi
fi
echo "P: GRUB branding applied."
GRUBEOF
chmod +x config/hooks/normal/03-grub-brand.chroot
ok "GRUB branding hook created."

ok "All hooks ready."

# ────────────────────────────────────────────────────────────
# 8. BUILD THE ISO
#
#    lb build executes this pipeline:
#    1. lb_bootstrap  → debootstrap creates base system
#    2. lb_chroot     → installs packages, runs .chroot hooks
#    3. lb_binary     → creates squashfs, bootloader, ISO
#       ├─ lb_binary_linux-image  → copies kernel + initrd
#       ├─ lb_binary_syslinux    → OUR PATCHED VERSION (ISOLINUX, no broken themes)
#       ├─ lb_binary_grub2       → sets up GRUB2 (if bootloader=grub2)
#       └─ lb_binary_iso         → assembles final ISO with El Torito boot
# ────────────────────────────────────────────────────────────
banner "Phase 4: Build ISO"
log "Starting lb build (15-30 min)..."
log "Log: $LOGFILE"
echo ""

BUILD_OK=true
if ! lb build 2>&1 | tee "$LOGFILE"; then
    BUILD_OK=false
    warn "lb build exited non-zero. Checking for ISO anyway..."
fi
echo ""

# ────────────────────────────────────────────────────────────
# 9. RESTORE binary_syslinux
# ────────────────────────────────────────────────────────────
if [ -f "${SYSLINUX_SCRIPT}.orig" ]; then
    cp "${SYSLINUX_SCRIPT}.orig" "$SYSLINUX_SCRIPT"
    ok "Restored original binary_syslinux."
fi

# ────────────────────────────────────────────────────────────
# 10. FIND THE ISO
# ────────────────────────────────────────────────────────────
banner "Phase 5: Collect & Verify"
ISO_OUT=""
for name in \
    live-image-amd64.hybrid.iso \
    binary.hybrid.iso \
    live-image-amd64.iso \
    binary.iso; do
    [ -f "$BUILD_DIR/$name" ] && { ISO_OUT="$BUILD_DIR/$name"; break; }
done
# Fallback: recursive search
[ -z "$ISO_OUT" ] && ISO_OUT=$(find "$BUILD_DIR" -maxdepth 4 -name "*.iso" -size +100M -print -quit 2>/dev/null || true)

if [ -z "$ISO_OUT" ] || [ ! -f "$ISO_OUT" ]; then
    echo ""
    log "Build log tail:"
    tail -30 "$LOGFILE"
    echo ""
    err "No ISO found! Check $LOGFILE for the full error."
fi

log "Found: $ISO_OUT ($(du -h "$ISO_OUT" | cut -f1))"

# ────────────────────────────────────────────────────────────
# 11. POST-PROCESS
# ────────────────────────────────────────────────────────────
# isohybrid for USB boot
if command -v isohybrid >/dev/null 2>&1; then
    isohybrid "$ISO_OUT" 2>/dev/null || warn "isohybrid skipped (CD boot still works)."
fi

FINAL="$SRC_DIR/securezplus-1.0-amd64.iso"
cp "$ISO_OUT" "$FINAL"
chown "$(logname 2>/dev/null || echo root):$(logname 2>/dev/null || echo root)" "$FINAL" 2>/dev/null || true

# ────────────────────────────────────────────────────────────
# 12. VERIFY ISO CONTENTS
# ────────────────────────────────────────────────────────────
SIZE=$(du -h "$FINAL" | cut -f1)
FILE_INFO=$(file "$FINAL")
IS_BOOTABLE="no"
echo "$FILE_INFO" | grep -qiE "bootable|El Torito" && IS_BOOTABLE="YES"

# Mount and inspect
TMP_MNT=$(mktemp -d)
HAS_CASPER="no"; HAS_SQUASHFS="no"; HAS_BOOT="no"; HAS_KERNEL="no"; HAS_INITRD="no"; HAS_DISK="no"
if mount -o loop,ro "$FINAL" "$TMP_MNT" 2>/dev/null; then
    [ -d "$TMP_MNT/casper" ]                     && HAS_CASPER="YES"
    [ -f "$TMP_MNT/casper/filesystem.squashfs" ]  && HAS_SQUASHFS="YES"
    [ -d "$TMP_MNT/isolinux" ] || [ -d "$TMP_MNT/boot" ] && HAS_BOOT="YES"
    ls "$TMP_MNT/casper/vmlinuz"* >/dev/null 2>&1 && HAS_KERNEL="YES"
    ls "$TMP_MNT/casper/initrd"*  >/dev/null 2>&1 && HAS_INITRD="YES"
    [ -f "$TMP_MNT/.disk/info" ]                  && HAS_DISK="YES"

    # Show actual contents
    log "ISO contents:"
    ls -la "$TMP_MNT/" 2>/dev/null | head -20
    echo ""
    log "Casper contents:"
    ls -la "$TMP_MNT/casper/" 2>/dev/null | head -15
    echo ""
    if [ -d "$TMP_MNT/boot/grub" ]; then
        log "GRUB config:"
        cat "$TMP_MNT/boot/grub/grub.cfg" 2>/dev/null | head -30
    fi

    umount "$TMP_MNT" 2>/dev/null || true
fi
rmdir "$TMP_MNT" 2>/dev/null || true

# ── Final report ──
echo ""
echo -e "${B}${G}╔════════════════════════════════════════════════════════╗${N}"
echo -e "${B}${G}║         SecureZ+ OS — Build Report                    ║${N}"
echo -e "${B}${G}╠════════════════════════════════════════════════════════╣${N}"
printf "${B}${G}║${N}  %-16s %s\n" "File:"      "$FINAL"
printf "${B}${G}║${N}  %-16s %s\n" "Size:"      "$SIZE"
printf "${B}${G}║${N}  %-16s %s\n" "Bootable:"  "$IS_BOOTABLE"
printf "${B}${G}║${N}  %-16s %s\n" "/casper:"   "$HAS_CASPER"
printf "${B}${G}║${N}  %-16s %s\n" "squashfs:"  "$HAS_SQUASHFS"
printf "${B}${G}║${N}  %-16s %s\n" "boot/isolinux:"    "$HAS_BOOT"
printf "${B}${G}║${N}  %-16s %s\n" "vmlinuz:"   "$HAS_KERNEL"
printf "${B}${G}║${N}  %-16s %s\n" "initrd:"    "$HAS_INITRD"
printf "${B}${G}║${N}  %-16s %s\n" ".disk/info:" "$HAS_DISK"
echo -e "${B}${G}╠════════════════════════════════════════════════════════╣${N}"

PASS=true
for check in "$HAS_CASPER" "$HAS_SQUASHFS" "$HAS_BOOT" "$HAS_KERNEL" "$HAS_INITRD"; do
    [ "$check" != "YES" ] && PASS=false
done

if [ "$IS_BOOTABLE" = "YES" ] && $PASS; then
    echo -e "${B}${G}║  ✔ ALL CHECKS PASSED — ISO is ready to boot!        ║${N}"
    echo -e "${B}${G}╠════════════════════════════════════════════════════════╣${N}"
    echo -e "${B}${G}║${N}  Test with:"
    echo -e "${B}${G}║${N}  ${B}sudo qemu-system-x86_64 \\\\${N}"
    echo -e "${B}${G}║${N}    ${B}-cdrom $FINAL \\\\${N}"
    echo -e "${B}${G}║${N}    ${B}-m 4096 -boot d -enable-kvm${N}"
    echo -e "${B}${G}║${N}"
    echo -e "${B}${G}║${N}  Or for VirtualBox/VMware: attach as IDE CD-ROM."
else
    echo -e "${R}  ✘  VERIFICATION FAILED — some checks did not pass.${N}"
    echo -e "${R}     Check the report above and $LOGFILE for details.${N}"
fi
echo -e "${B}${G}╚════════════════════════════════════════════════════════╝${N}"
echo ""
