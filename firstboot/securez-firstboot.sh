#!/bin/bash
#
# SecureZ+ OS — First Boot Wizard (Whiptail TUI)
# securez-firstboot.sh
#

set -euo pipefail

SECUREZ_DIR="/etc/securez"
export NEWT_COLORS='
    root=,black
    border=cyan,black
    window=cyan,black
    shadow=,black
    title=cyan,black
    button=black,cyan
    actbutton=black,cyan
    compactbutton=black,cyan
    checkbox=cyan,black
    actcheckbox=black,cyan
    entry=white,black
    label=white,black
    listbox=white,black
    actlistbox=black,cyan
    sellistbox=black,cyan
    actsellistbox=black,cyan
'

# ── 1. Welcome Screen ────────────────────────────────────────

whiptail --title " 🛡️ SecureZ+ OS " --msgbox "Welcome to SecureZ+ OS.\n\nSecurity starts now. This wizard will guide you through configuring your Master Key and Firewall.\n\nThe system will not boot to the desktop until this is complete." 12 60

# ── 2. Master Key Setup ──────────────────────────────────────

while true; do
    MASTER_KEY=$(whiptail --title " Master Key Setup " --passwordbox "Your Master Key is the root of all security in SecureZ+.\nIt protects your login, hidden vaults, and encrypted files.\n\nWARNING: If you lose this key, data is UNRECOVERABLE.\n\nEnter a new Master Key (min 16 chars):" 14 65 3>&1 1>&2 2>&3)
    
    if [ ${#MASTER_KEY} -lt 16 ]; then
        whiptail --title " Error " --msgbox "Master Key must be at least 16 characters long!" 8 50
        continue
    fi

    CONFIRM_KEY=$(whiptail --title " Master Key Setup " --passwordbox "Please confirm your Master Key:" 10 50 3>&1 1>&2 2>&3)

    if [ "$MASTER_KEY" != "$CONFIRM_KEY" ]; then
        whiptail --title " Error " --msgbox "Keys do not match. Please try again." 8 50
        continue
    fi

    break
done

mkdir -p "$SECUREZ_DIR"
whiptail --title " Processing " --infobox "Hashing Master Key with Argon2id... Please wait." 8 50
echo "$MASTER_KEY" | /usr/sbin/securez-master-key --setup >/dev/null 2>&1
whiptail --title " Success " --msgbox "Master Key successfully configured!" 8 50

# ── 3. Firewall Setup ────────────────────────────────────────

if whiptail --title " Firewall Setup " --yesno "SecureZ+ uses a Default-Deny firewall.\n\nThis means ALL inbound connections are blocked by default. You can open specific ports later if needed.\n\nEnable the Firewall now? (Highly Recommended)" 12 60; then
    if [ -f "/etc/securez/securez-firewall.nft" ]; then
        nft -f /etc/securez/securez-firewall.nft
        systemctl enable nftables >/dev/null 2>&1
    else
        cp /usr/share/securez/securez-firewall.nft /etc/securez/
        nft -f /etc/securez/securez-firewall.nft
        systemctl enable nftables >/dev/null 2>&1
    fi
    whiptail --title " Firewall " --msgbox "Default-Deny Firewall is now ACTIVE." 8 50
else
    whiptail --title " Warning " --msgbox "Firewall NOT enabled. System is less secure." 8 50
fi

# ── 4. User Account ──────────────────────────────────────────

USERNAME=$(whiptail --title " User Account " --inputbox "Enter a username for your daily-driver account:" 10 50 3>&1 1>&2 2>&3)

if ! id "$USERNAME" &>/dev/null; then
    groupadd securez 2>/dev/null || true
    useradd -m -s /usr/bin/szshell -G sudo,securez "$USERNAME"
    while true; do
        USER_PASS=$(whiptail --title " User Password " --passwordbox "Enter a login password for $USERNAME:\n(This is separate from your Master Key)" 10 50 3>&1 1>&2 2>&3)
        USER_CONF=$(whiptail --title " User Password " --passwordbox "Confirm login password:" 10 50 3>&1 1>&2 2>&3)
        
        if [ "$USER_PASS" == "$USER_CONF" ]; then
            echo "$USERNAME:$USER_PASS" | chpasswd
            whiptail --title " Success " --msgbox "User $USERNAME created successfully." 8 50
            break
        else
            whiptail --title " Error " --msgbox "Passwords do not match." 8 50
        fi
    done
fi

# ── 5. Optional Features ─────────────────────────────────────

FEATURES=$(whiptail --title " Advanced Security Options " --checklist \
"Select optional privacy features to enable:" 15 60 4 \
"DNS" "Enable Encrypted DNS (dnscrypt-proxy)" ON \
"TOR" "Enable Tor Transparent Proxy" OFF \
"DAEMON" "Enable CrypticEngine Security Daemon" ON \
"INTEGRITY" "Initialize File Integrity Database" ON 3>&1 1>&2 2>&3)

if echo "$FEATURES" | grep -q "DNS"; then
    systemctl enable dnscrypt-proxy >/dev/null 2>&1 || true
    systemctl start dnscrypt-proxy >/dev/null 2>&1 || true
fi

if echo "$FEATURES" | grep -q "TOR"; then
    systemctl enable tor >/dev/null 2>&1 || true
    systemctl start tor >/dev/null 2>&1 || true
fi

if echo "$FEATURES" | grep -q "DAEMON"; then
    systemctl enable crypticd >/dev/null 2>&1 || true
    systemctl start crypticd >/dev/null 2>&1 || true
fi

if echo "$FEATURES" | grep -q "INTEGRITY"; then
    whiptail --title " Processing " --infobox "Building Integrity Database... Please wait." 8 50
    /usr/sbin/securez-integrity --init >/dev/null 2>&1 || true
fi

# ── 6. Finish ────────────────────────────────────────────────

whiptail --title " Setup Complete " --msgbox "SecureZ+ setup is complete!\n\nYour system is now locked down and ready.\nThe computer will now reboot into the SecureZ+ Desktop." 10 60

touch /etc/securez/.setup-complete
systemctl disable securez-firstboot.service >/dev/null 2>&1 || true
reboot
