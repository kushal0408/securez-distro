#!/bin/bash
#
# SecureZ+ ISO Diagnostic Tool
# Run this AFTER build-iso.sh to deeply inspect the ISO
#

ISO="${1:-$(dirname "$0")/securezplus-1.0-amd64.iso}"

if [ ! -f "$ISO" ]; then
    echo "Usage: sudo ./diagnose-iso.sh [path-to-iso]"
    echo "ISO not found at: $ISO"
    exit 1
fi

echo "═══════════════════════════════════════════"
echo "  SecureZ+ ISO Diagnostic"
echo "═══════════════════════════════════════════"
echo ""

# 1. File type
echo "── 1. File identification ──"
file "$ISO"
echo ""

# 2. Size
echo "── 2. Size ──"
ls -lh "$ISO" | awk '{print $5, $NF}'
echo ""

# 3. Mount and inspect
MNT=$(mktemp -d)
echo "── 3. ISO Contents ──"
if mount -o loop,ro "$ISO" "$MNT" 2>/dev/null; then
    echo "Root:"
    ls -la "$MNT/"
    echo ""

    if [ -d "$MNT/casper" ]; then
        echo "Casper directory: ✔ EXISTS"
        echo "Contents:"
        ls -lh "$MNT/casper/"
        echo ""

        if [ -f "$MNT/casper/filesystem.squashfs" ]; then
            echo "filesystem.squashfs: ✔ EXISTS ($(du -h "$MNT/casper/filesystem.squashfs" | cut -f1))"
        else
            echo "filesystem.squashfs: ✘ MISSING — THIS IS THE PROBLEM"
        fi

        echo ""
        echo "Kernel files:"
        ls "$MNT/casper/vmlinuz"* 2>/dev/null || echo "  ✘ No vmlinuz found!"
        ls "$MNT/casper/initrd"*  2>/dev/null || echo "  ✘ No initrd found!"
    else
        echo "Casper directory: ✘ MISSING — THIS IS THE PROBLEM"
    fi

    echo ""
    if [ -d "$MNT/boot/grub" ]; then
        echo "GRUB directory: ✔ EXISTS"
        echo ""
        echo "grub.cfg contents:"
        echo "────────────────────"
        cat "$MNT/boot/grub/grub.cfg" 2>/dev/null
        echo "────────────────────"
    else
        echo "GRUB directory: ✘ MISSING"
        echo "Checking for other bootloaders:"
        ls "$MNT/isolinux/" 2>/dev/null && echo "  Found: ISOLINUX" || true
        ls "$MNT/syslinux/" 2>/dev/null && echo "  Found: SYSLINUX" || true
    fi

    echo ""
    if [ -f "$MNT/.disk/info" ]; then
        echo ".disk/info: ✔ EXISTS → $(cat "$MNT/.disk/info")"
    else
        echo ".disk/info: ✘ MISSING — casper needs this!"
    fi

    # Check for casper-uuid
    if [ -f "$MNT/.disk/casper-uuid-generic" ]; then
        echo "casper-uuid: ✔ $(cat "$MNT/.disk/casper-uuid-generic")"
    else
        echo "casper-uuid: not present (usually OK)"
    fi

    echo ""
    echo "── 4. Initrd Module Check ──"
    # Extract initrd and check for critical modules
    INITRD=$(ls "$MNT/casper/initrd"* 2>/dev/null | head -1)
    if [ -n "$INITRD" ]; then
        TMPDIR=$(mktemp -d)
        cd "$TMPDIR"
        # initrd might be gzip, lz4, zstd, or concatenated cpio
        unmkinitramfs "$INITRD" "$TMPDIR/initrd-contents" 2>/dev/null || \
            (zcat "$INITRD" 2>/dev/null || lz4 -d "$INITRD" 2>/dev/null || zstd -d "$INITRD" 2>/dev/null) | \
            cpio -id 2>/dev/null

        echo "Checking for critical modules in initrd:"
        # Look in all extracted directories
        for mod in sr_mod cdrom isofs iso9660 loop squashfs overlay; do
            if find "$TMPDIR" -name "${mod}.ko*" 2>/dev/null | grep -q .; then
                echo "  ✔ $mod"
            else
                echo "  ✘ $mod — MISSING, will prevent boot!"
            fi
        done

        # Check for casper scripts
        echo ""
        echo "Checking for casper in initrd:"
        if find "$TMPDIR" -path "*/scripts/casper" 2>/dev/null | grep -q .; then
            echo "  ✔ casper scripts present"
        else
            echo "  ✘ casper scripts MISSING — live boot impossible!"
        fi

        cd /
        rm -rf "$TMPDIR"
    fi

    umount "$MNT" 2>/dev/null
else
    echo "✘ Failed to mount ISO!"
fi
rmdir "$MNT" 2>/dev/null

echo ""
echo "═══════════════════════════════════════════"
echo "  If the ISO drops to (initramfs) shell:"
echo ""
echo "  Run these commands to diagnose:"
echo "    blkid            # See all block devices"
echo "    ls /dev/sr*      # Check CD-ROM devices"
echo "    mount /dev/sr0 /cdrom  # Try mounting CD-ROM"
echo "    ls /cdrom/casper/      # Check casper files"
echo "    cat /proc/modules | grep sr  # Check sr_mod loaded"
echo "═══════════════════════════════════════════"
