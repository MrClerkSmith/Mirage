#!/bin/sh
# Mirage server: enable forwarding and NAT for the tunnel subnet.
#
# Usage:  ./server-nat.sh up          (or: down)
#
# Edit TUN/SUBNET/EXT below to match server.json and the real uplink.
set -eu

TUN=mirage-srv
SUBNET=10.7.0.0/24
EXT=eth0

up() {
	sysctl -w net.ipv4.ip_forward=1
	iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$EXT" -j MASQUERADE
	iptables -A FORWARD -i "$TUN" -j ACCEPT
	iptables -A FORWARD -o "$TUN" -j ACCEPT
	# The outer connection is TCP-over-TCP; clamp MSS so no packet has to be
	# fragmented or dropped inside the tunnel.
	iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	echo "NAT up for $SUBNET via $EXT"
}

down() {
	iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	iptables -D FORWARD -o "$TUN" -j ACCEPT
	iptables -D FORWARD -i "$TUN" -j ACCEPT
	iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$EXT" -j MASQUERADE
	echo "NAT down"
}

case "${1:-up}" in
	up) up ;;
	down) down ;;
	*) echo "usage: $0 up|down"; exit 1 ;;
esac
