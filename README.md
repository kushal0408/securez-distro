# SecureZ+ OS

Production-ready security-focused Linux distribution.

## Build
```bash
sudo ./build-iso.sh
```

## Test
```bash
qemu-system-x86_64 -cdrom securezplus-1.0-amd64.iso -m 2048
```

## Features
- 🔐 Cryptic Engine (Custom C Daemon)
- 🛡️ Security Hardening & AppArmor integration
- 💻 SecureZ+ Shell interface
- 🎨 Complete Boot and UI Branding

See `docs/` for details.
