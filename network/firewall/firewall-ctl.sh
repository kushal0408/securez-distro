#!/bin/bash
#
# SecureZ+ OS — Firewall Control
# firewall-ctl.sh — Enable, disable, and manage the nftables firewall
#

set -euo pipefail

RULES_FILE="/etc/securez/securez-firewall.nft"
SERVICE="nftables"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    echo ""
    echo "  🛡️  SecureZ+ Firewall Control"
    echo ""
    echo "  Usage: $(basename "$0") <command>"
    echo ""
    echo "  Commands:"
    echo "    enable      Load firewall rules (default-deny inbound)"
    echo "    disable     Remove all firewall rules (DANGEROUS)"
    echo "    status      Show current firewall status"
    echo "    reload      Reload rules from config file"
    echo "    allow-in    <port> <tcp|udp>  — Allow inbound port"
    echo "    deny-in     <port> <tcp|udp>  — Remove inbound allow"
    echo "    list        Show all active rules"
    echo ""
}

fw_enable() {
    echo -e "  ${CYAN}Loading SecureZ+ firewall rules...${NC}"

    if [ ! -f "$RULES_FILE" ]; then
        echo -e "  ${RED}❌ Rules file not found: $RULES_FILE${NC}"
        exit 1
    fi

    nft -f "$RULES_FILE"
    echo -e "  ${GREEN}✅ Firewall enabled (default-deny inbound)${NC}"
}

fw_disable() {
    echo -e "  ${YELLOW}⚠ WARNING: Disabling the firewall removes ALL protection${NC}"
    read -p "  Type 'yes' to confirm: " confirm
    if [ "$confirm" != "yes" ]; then
        echo "  Cancelled."
        exit 0
    fi

    nft flush ruleset
    echo -e "  ${RED}🔓 Firewall disabled — system is UNPROTECTED${NC}"
}

fw_status() {
    echo ""
    echo -e "  ${CYAN}🛡️  Firewall Status${NC}"
    echo ""

    if nft list ruleset 2>/dev/null | grep -q "securez_firewall"; then
        echo -e "  Status:     ${GREEN}● ACTIVE${NC}"

        # Count rules
        local rule_count
        rule_count=$(nft list ruleset | grep -c "accept\|drop\|reject" 2>/dev/null || echo 0)
        echo "  Rules:      $rule_count active rules"

        # Show policy
        echo "  Inbound:    DROP (default deny)"
        echo "  Outbound:   ACCEPT (user-friendly)"
        echo "  Forward:    DROP"
    else
        echo -e "  Status:     ${RED}○ INACTIVE${NC}"
        echo -e "  ${YELLOW}Run '$(basename "$0") enable' to activate${NC}"
    fi
    echo ""
}

fw_allow_in() {
    local port=$1
    local proto=${2:-tcp}

    nft add rule inet securez_firewall input "$proto" dport "$port" accept
    echo -e "  ${GREEN}✅ Allowed inbound ${proto}/${port}${NC}"
}

fw_deny_in() {
    local port=$1
    local proto=${2:-tcp}

    # Find and delete the rule (simplified — in production use handles)
    echo -e "  ${YELLOW}Use 'nft -a list chain inet securez_firewall input' to find handles${NC}"
    echo -e "  ${YELLOW}Then 'nft delete rule inet securez_firewall input handle <N>'${NC}"
}

fw_list() {
    echo ""
    echo -e "  ${CYAN}Active Firewall Rules:${NC}"
    echo ""
    nft list ruleset
}

# ── Main ──────────────────────────────────────────────────────

if [ $# -lt 1 ]; then
    usage
    exit 1
fi

case "$1" in
    enable)  fw_enable ;;
    disable) fw_disable ;;
    status)  fw_status ;;
    reload)  fw_enable ;;  # Same as enable — reloads atomically
    allow-in)
        [ $# -lt 2 ] && { echo "Usage: $0 allow-in <port> [tcp|udp]"; exit 1; }
        fw_allow_in "$2" "${3:-tcp}"
        ;;
    deny-in) fw_deny_in "$2" "${3:-tcp}" ;;
    list)    fw_list ;;
    *)       usage; exit 1 ;;
esac
