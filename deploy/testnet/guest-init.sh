#!/bin/sh
set -eu

export PATH=/sbin:/usr/sbin:/bin:/usr/bin

echo "=== ZNS TESTNET GUEST INIT ==="

# ---------------------------------------------------------------------------
# Early userspace
# ---------------------------------------------------------------------------

mkdir -p /proc /sys /dev /run /var/lib/zebra /state /etc

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true

# SEV-SNP guest driver.
modprobe sev-guest 2>/dev/null || true

if [ ! -e /dev/sev-guest ]; then
    echo "FATAL: /dev/sev-guest is unavailable"
    exec sh
fi

# ---------------------------------------------------------------------------
# Persistent volumes
#
# ext4 UUIDs of the host images, so the mounts do not depend on QEMU
# disk order:
#   zns-test-state.img  -> /state
#   zebra-state.img     -> /var/lib/zebra
# ---------------------------------------------------------------------------

ZNS_UUID="0ece68d8-f963-4985-a751-84128c9ae1c4"
ZEBRA_UUID="589fd35e-42f5-460c-aa84-7458ac3f11a0"

echo "Resolving persistent volumes..."

ZNS_DEV="$(blkid -U "$ZNS_UUID")"
ZEBRA_DEV="$(blkid -U "$ZEBRA_UUID")"

if [ -z "$ZNS_DEV" ] || [ -z "$ZEBRA_DEV" ]; then
    echo "FATAL: could not resolve persistent volume UUIDs"
    exec sh
fi

echo "Mounting ZNS state from $ZNS_DEV..."
mount "$ZNS_DEV" /state

echo "Mounting Zebra state from $ZEBRA_DEV..."
mount "$ZEBRA_DEV" /var/lib/zebra

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

NIC=""

for iface in /sys/class/net/*; do
    name="${iface##*/}"

    if [ "$name" != "lo" ]; then
        NIC="$name"
        break
    fi
done

if [ -z "$NIC" ]; then
    echo "FATAL: no network interface found"
    exec sh
fi

echo "Using network interface: $NIC"

ip link set "$NIC" up

echo "Requesting DHCP lease..."
ipconfig -c dhcp -t 30 "$NIC"

NETCONF="/run/net-${NIC}.conf"

if [ ! -f "$NETCONF" ]; then
    echo "FATAL: DHCP succeeded but $NETCONF was not created"
    exec sh
fi

# ipconfig writes values including:
#   IPV4ADDR
#   IPV4GATEWAY
#   IPV4DNS0
#   IPV4DNS1
. "$NETCONF"

echo "Guest IPv4: ${IPV4ADDR:-unknown}"
echo "Gateway:    ${IPV4GATEWAY:-unknown}"

# Build resolv.conf from the DNS servers supplied by DHCP.
: > /etc/resolv.conf

for dns in "${IPV4DNS0:-}" "${IPV4DNS1:-}"; do
    if [ -n "$dns" ] && [ "$dns" != "0.0.0.0" ]; then
        echo "nameserver $dns" >> /etc/resolv.conf
    fi
done

if [ ! -s /etc/resolv.conf ]; then
    echo "FATAL: DHCP supplied no usable DNS servers"
    exec sh
fi

echo "DNS configuration:"
cat /etc/resolv.conf

# ---------------------------------------------------------------------------
# Zebra
# ---------------------------------------------------------------------------

echo "Starting Zebra..."
zebrad -c /etc/zebra/zebrad.toml start &
ZEBRA_PID=$!

echo "zebrad pid: $ZEBRA_PID"

# First prototype:
#   boot -> persistent volumes -> network -> Zebra
#
# TODO: Health gating and automatic testnet keygen launch.
wait "$ZEBRA_PID"

echo "Zebra exited."
exec sh
