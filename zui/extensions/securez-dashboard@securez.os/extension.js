/**
 * SecureZ+ OS — Security Dashboard Extension
 * extension.js — GNOME Shell panel indicator
 *
 * Shows a shield icon in the top panel with real-time security status.
 * Clicking shows a dropdown with firewall, Tor, VPN, DNS, and
 * CrypticEngine status.
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import St from 'gi://St';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';

const REFRESH_INTERVAL = 10; // seconds

export default class SecureZDashboard extends Extension {
    enable() {
        this._indicator = new PanelMenu.Button(0.0, 'SecureZ+ Security', false);

        // Shield icon in the panel
        this._icon = new St.Icon({
            icon_name: 'security-high-symbolic',
            style_class: 'system-status-icon',
        });
        this._indicator.add_child(this._icon);

        // Status label next to icon
        this._label = new St.Label({
            text: '🛡️',
            y_align: imports.gi.Clutter.ActorAlign.CENTER,
            style: 'font-size: 11px; margin-left: 4px;',
        });
        this._indicator.add_child(this._label);

        // Build the dropdown menu
        this._buildMenu();

        // Add to panel
        Main.panel.addToStatusArea('securez-dashboard', this._indicator, 0, 'right');

        // Start periodic refresh
        this._refreshTimer = GLib.timeout_add_seconds(
            GLib.PRIORITY_DEFAULT, REFRESH_INTERVAL,
            () => { this._refresh(); return GLib.SOURCE_CONTINUE; }
        );

        // Initial refresh
        this._refresh();
    }

    disable() {
        if (this._refreshTimer) {
            GLib.source_remove(this._refreshTimer);
            this._refreshTimer = null;
        }

        if (this._indicator) {
            this._indicator.destroy();
            this._indicator = null;
        }
    }

    _buildMenu() {
        const menu = this._indicator.menu;

        // Title
        const titleItem = new PopupMenu.PopupMenuItem('🛡️ SecureZ+ Security', {
            reactive: false,
            style_class: 'popup-menu-item',
        });
        titleItem.label.style = 'font-weight: bold; font-size: 13px; color: #00ffd5;';
        menu.addMenuItem(titleItem);

        menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        // Status items
        this._firewallItem = new PopupMenu.PopupMenuItem('Firewall: checking...');
        this._torItem = new PopupMenu.PopupMenuItem('Tor: checking...');
        this._vpnItem = new PopupMenu.PopupMenuItem('VPN: checking...');
        this._dnsItem = new PopupMenu.PopupMenuItem('Encrypted DNS: checking...');
        this._crypticItem = new PopupMenu.PopupMenuItem('CrypticEngine: checking...');
        this._luksItem = new PopupMenu.PopupMenuItem('Disk Encryption: checking...');

        menu.addMenuItem(this._firewallItem);
        menu.addMenuItem(this._torItem);
        menu.addMenuItem(this._vpnItem);
        menu.addMenuItem(this._dnsItem);
        menu.addMenuItem(this._crypticItem);
        menu.addMenuItem(this._luksItem);

        menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        // Quick actions
        const toggleTor = new PopupMenu.PopupMenuItem('🔄 Toggle Tor');
        toggleTor.connect('activate', () => this._toggleService('tor'));
        menu.addMenuItem(toggleTor);

        const toggleFw = new PopupMenu.PopupMenuItem('🔥 Reload Firewall');
        toggleFw.connect('activate', () => this._runCommand(
            'pkexec nft -f /etc/securez/securez-firewall.nft'
        ));
        menu.addMenuItem(toggleFw);

        menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        const openTerminal = new PopupMenu.PopupMenuItem('🖥️ Open SecureZ Shell');
        openTerminal.connect('activate', () => {
            this._runCommand('gnome-terminal -- szshell');
        });
        menu.addMenuItem(openTerminal);
    }

    _refresh() {
        this._checkService('nftables', this._firewallItem, 'Firewall', '🛡️');
        this._checkService('tor', this._torItem, 'Tor Proxy', '🧅');
        this._checkVPN();
        this._checkService('dnscrypt-proxy', this._dnsItem, 'Encrypted DNS', '🔒');
        this._checkSocket('/run/crypticd.sock', this._crypticItem, 'CrypticEngine', '⚙️');
        this._checkLUKS();
        this._updateIcon();
    }

    _checkService(service, menuItem, label, emoji) {
        try {
            const proc = Gio.Subprocess.new(
                ['systemctl', 'is-active', '--quiet', service],
                Gio.SubprocessFlags.NONE
            );
            proc.wait_async(null, (proc, result) => {
                try {
                    proc.wait_finish(result);
                    const active = proc.get_successful();
                    menuItem.label.text = `${emoji} ${label}: ${active ? '● Active' : '○ Inactive'}`;
                    menuItem.label.style = active
                        ? 'color: #00ffd5;'
                        : 'color: #888888;';
                } catch(e) {
                    menuItem.label.text = `${emoji} ${label}: ? Unknown`;
                }
            });
        } catch(e) {
            menuItem.label.text = `${emoji} ${label}: ? Error`;
        }
    }

    _checkSocket(path, menuItem, label, emoji) {
        const file = Gio.File.new_for_path(path);
        const active = file.query_exists(null);
        menuItem.label.text = `${emoji} ${label}: ${active ? '● Running' : '○ Stopped'}`;
        menuItem.label.style = active ? 'color: #00ffd5;' : 'color: #ff4444;';
    }

    _checkVPN() {
        const wg = Gio.File.new_for_path('/sys/class/net/wg0').query_exists(null);
        const tun = Gio.File.new_for_path('/sys/class/net/tun0').query_exists(null);
        const active = wg || tun;
        this._vpnItem.label.text = `🔐 VPN: ${active ? '● Connected' : '○ Disconnected'}`;
        this._vpnItem.label.style = active ? 'color: #00ffd5;' : 'color: #888888;';
    }

    _checkLUKS() {
        try {
            const proc = Gio.Subprocess.new(
                ['bash', '-c', 'lsblk -o TYPE 2>/dev/null | grep -q crypt'],
                Gio.SubprocessFlags.NONE
            );
            proc.wait_async(null, (proc, result) => {
                try {
                    proc.wait_finish(result);
                    const encrypted = proc.get_successful();
                    this._luksItem.label.text = `💾 Disk Encryption: ${encrypted ? '● Encrypted' : '○ Not detected'}`;
                    this._luksItem.label.style = encrypted ? 'color: #00ffd5;' : 'color: #ffcc00;';
                } catch(e) {}
            });
        } catch(e) {}
    }

    _updateIcon() {
        // The panel icon color could reflect overall security health
        // For now, keep the shield icon stable
    }

    _toggleService(service) {
        try {
            Gio.Subprocess.new(
                ['pkexec', 'bash', '-c',
                 `if systemctl is-active --quiet ${service}; then systemctl stop ${service}; else systemctl start ${service}; fi`],
                Gio.SubprocessFlags.NONE
            );
            GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 2, () => {
                this._refresh();
                return GLib.SOURCE_REMOVE;
            });
        } catch(e) {
            Main.notify('SecureZ+', `Failed to toggle ${service}`);
        }
    }

    _runCommand(cmd) {
        try {
            GLib.spawn_command_line_async(cmd);
        } catch(e) {
            Main.notify('SecureZ+', `Failed: ${cmd}`);
        }
    }
}
