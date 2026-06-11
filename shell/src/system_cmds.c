/*
 * SecureZ+ OS — SecureZ Shell
 * system_cmds.c — System info and security status commands
 *
 * Copyright (c) 2025 SecureZ+ Project
 * License: GPL v3
 */

#include "commands.h"
#include "shell.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

/* ── status — Security overview ──────────────────────────────── */

int cmd_status(int argc, char **argv, ShellState *state)
{
    (void)argc; (void)argv; (void)state;

    printf("\n  \033[1;36m🛡️  SecureZ+ Security Status\033[0m\n\n");

    /* Firewall */
    int fw = system("nft list ruleset > /dev/null 2>&1") == 0;
    printf("  %-24s %s\n", "Firewall (nftables):",
           fw ? "\033[32m● ACTIVE\033[0m" : "\033[31m○ INACTIVE\033[0m");

    /* Tor */
    int tor = system("systemctl is-active tor > /dev/null 2>&1") == 0;
    printf("  %-24s %s\n", "Tor Proxy:",
           tor ? "\033[32m● ACTIVE\033[0m" : "\033[33m○ inactive\033[0m");

    /* VPN */
    int vpn = (access("/sys/class/net/wg0", 0) == 0 ||
               access("/sys/class/net/tun0", 0) == 0);
    printf("  %-24s %s\n", "VPN:",
           vpn ? "\033[32m● CONNECTED\033[0m" : "\033[33m○ disconnected\033[0m");

    /* DNS encryption */
    int dns = system("systemctl is-active dnscrypt-proxy > /dev/null 2>&1") == 0;
    printf("  %-24s %s\n", "Encrypted DNS:",
           dns ? "\033[32m● ACTIVE\033[0m" : "\033[31m○ INACTIVE\033[0m");

    /* CrypticEngine daemon */
    int ce = (access("/run/crypticd.sock", 0) == 0);
    printf("  %-24s %s\n", "CrypticEngine Daemon:",
           ce ? "\033[32m● RUNNING\033[0m" : "\033[31m○ STOPPED\033[0m");

    /* AppArmor */
    int aa = system("aa-enabled > /dev/null 2>&1") == 0;
    printf("  %-24s %s\n", "AppArmor:",
           aa ? "\033[32m● ENFORCING\033[0m" : "\033[33m○ disabled\033[0m");

    /* LUKS */
    int luks = system("lsblk -o TYPE | grep -q crypt 2>/dev/null") == 0;
    printf("  %-24s %s\n", "Disk Encryption (LUKS):",
           luks ? "\033[32m● ENCRYPTED\033[0m" : "\033[33m○ not detected\033[0m");

    /* ptrace_scope */
    FILE *f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    int ptrace = 0;
    if (f) { fscanf(f, "%d", &ptrace); fclose(f); }
    const char *ptrace_str;
    switch (ptrace) {
        case 0:  ptrace_str = "\033[31m○ UNRESTRICTED (0)\033[0m"; break;
        case 1:  ptrace_str = "\033[33m◑ parent-only (1)\033[0m"; break;
        case 2:  ptrace_str = "\033[32m● admin-only (2)\033[0m"; break;
        case 3:  ptrace_str = "\033[32m● DISABLED (3)\033[0m"; break;
        default: ptrace_str = "\033[33m? unknown\033[0m"; break;
    }
    printf("  %-24s %s\n", "Ptrace Protection:", ptrace_str);

    /* Secure memory stats */
    printf("\n  \033[2m─── Memory ───\033[0m\n");
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        printf("  %-24s %lu MB / %lu MB\n", "RAM Used:",
               (si.totalram - si.freeram) / (1024 * 1024),
               si.totalram / (1024 * 1024));
    }

    printf("\n");
    return 0;
}

/* ── sysinfo — System information ────────────────────────────── */

int cmd_sysinfo(int argc, char **argv, ShellState *state)
{
    (void)argc; (void)argv; (void)state;

    struct utsname uts;
    uname(&uts);

    struct sysinfo si;
    sysinfo(&si);

    printf("\n");
    printf("  \033[1;36m╔════════════════════════════════════╗\033[0m\n");
    printf("  \033[1;36m║\033[0m  \033[1m🛡️  SecureZ+ OS v1.0 (Fortress)\033[0m  \033[1;36m║\033[0m\n");
    printf("  \033[1;36m╚════════════════════════════════════╝\033[0m\n\n");

    printf("  \033[1mSystem\033[0m\n");
    printf("  %-18s %s\n", "OS:",       "SecureZ+ 1.0 (Fortress)");
    printf("  %-18s %s %s\n", "Kernel:", uts.sysname, uts.release);
    printf("  %-18s %s\n", "Arch:",     uts.machine);
    printf("  %-18s %s\n", "Hostname:", uts.nodename);

    /* Uptime */
    long uptime = si.uptime;
    int days = uptime / 86400;
    int hours = (uptime % 86400) / 3600;
    int mins = (uptime % 3600) / 60;
    printf("  %-18s %dd %dh %dm\n", "Uptime:", days, hours, mins);

    /* Memory */
    printf("\n  \033[1mMemory\033[0m\n");
    printf("  %-18s %lu MB\n", "Total:", si.totalram / (1024 * 1024));
    printf("  %-18s %lu MB\n", "Used:",
           (si.totalram - si.freeram) / (1024 * 1024));
    printf("  %-18s %lu MB\n", "Free:", si.freeram / (1024 * 1024));
    printf("  %-18s %lu MB\n", "Swap:", si.totalswap / (1024 * 1024));

    /* CPUs */
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    printf("\n  \033[1mProcessor\033[0m\n");
    printf("  %-18s %ld cores\n", "CPUs:", nproc);

    /* Shell */
    printf("\n  \033[1mShell\033[0m\n");
    printf("  %-18s SecureZ Shell (szshell)\n", "Shell:");
    printf("  %-18s CrypticEngine v1.0\n", "Security Engine:");

    printf("\n");
    return 0;
}
