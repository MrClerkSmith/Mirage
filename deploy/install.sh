#!/bin/sh
# Mirage one-shot installer for Linux servers.
#
# Detects the distribution, updates the system, installs Go, clones the
# repository, builds the binaries and installs the systemd service.
#
# Run as root:  curl -fsSL https://raw.githubusercontent.com/MrClerkSmith/Mirage/main/deploy/install.sh | sh
# or:           sh deploy/install.sh
set -eu

REPO_URL=https://github.com/MrClerkSmith/Mirage.git
SRC_DIR=/opt/mirage
CONFIG_DIR=/etc/mirage
BIN_DIR=/usr/local/bin
SERVICE_DIR=/etc/systemd/system
GO_VERSION=go1.23.4

# ---------- helpers ----------

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m==>\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

ask() {
	# ask "prompt" "default" -> sets ANSWER
	printf '%s [%s]: ' "$1" "$2"
	read ANSWER
	[ -n "$ANSWER" ] || ANSWER="$2"
}

# ---------- os detection ----------

detect_os() {
	OS=unknown
	PM=unknown
	if [ -f /etc/os-release ]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		case "$ID" in
			ubuntu|debian|raspbian|linuxmint|pop)
				OS=debian; PM=apt ;;
			fedora|rhel|rocky|almalinux|centos|amzn|ol)
				OS=rhel; PM=dnf ;;
			arch|manjaro|endeavouros)
				OS=arch; PM=pacman ;;
			alpine)
				OS=alpine; PM=apk ;;
		esac
	fi
	# Fall back to whatever package manager exists.
	if [ "$PM" = unknown ]; then
		for p in apt-get dnf yum pacman apk; do
			if command -v "$p" >/dev/null 2>&1; then PM="$p"; break; fi
		done
	fi
	[ "$PM" = unknown ] && die "unsupported distribution: cannot find a package manager"
	log "os: ${PRETTY_NAME:-$ID} ($ID), package manager: $PM"
}

update_system() {
	log "updating the system"
	case "$PM" in
		apt-get) apt-get update -y; apt-get upgrade -y ;;
		dnf)     dnf -y upgrade ;;
		yum)     yum -y update ;;
		pacman)  pacman -Syu --noconfirm ;;
		apk)     apk update; apk upgrade ;;
	esac
}

install_pkgs() {
	case "$PM" in
		apt-get) apt-get install -y "$@" ;;
		dnf)     dnf install -y "$@" ;;
		yum)     yum install -y "$@" ;;
		pacman)  pacman -S --noconfirm --needed "$@" ;;
		apk)     apk add "$@" ;;
	esac
}

# ---------- go ----------

go_usable() {
	command -v go >/dev/null 2>&1 || return 1
	v=$(go version | awk '{print $3}' | sed 's/^go//')
	major=${v%%.*}
	rest=${v#*.}
	minor=${rest%%.*}
	[ "$major" -gt 1 ] && return 0
	[ "$major" -eq 1 ] && [ "$minor" -ge 23 ] && return 0
	return 1
}

install_go() {
	if go_usable; then
		log "go $(go version | awk '{print $3}') already installed"
		return 0
	fi
	arch=amd64
	case "$(uname -m)" in
		x86_64|amd64)   arch=amd64 ;;
		aarch64|arm64)  arch=arm64 ;;
		armv7l)         arch=armv6l ;;
		*)              die "unsupported cpu architecture: $(uname -m)" ;;
	esac
	log "installing $GO_VERSION for linux-$arch"
	url="https://go.dev/dl/$GO_VERSION.linux-$arch.tar.gz"
	command -v curl >/dev/null 2>&1 || install_pkgs curl
	curl -fsSL "$url" -o /tmp/go.tar.gz || die "download failed: $url"
	rm -rf /usr/local/go
	tar -C /usr/local -xzf /tmp/go.tar.gz || die "cannot extract go"
	rm -f /tmp/go.tar.gz
	export PATH="$PATH:/usr/local/go/bin"
	cat >/etc/profile.d/mirage-go.sh <<EOF
export PATH="\$PATH:/usr/local/go/bin"
EOF
	log "go installed: $(go version | awk '{print $3}')"
}

# ---------- source and build ----------

fetch_source() {
	if [ -d "$SRC_DIR/.git" ]; then
		log "updating $SRC_DIR"
		# shellcheck disable=SC2164
		cd "$SRC_DIR"
		git pull --ff-only || warn "git pull failed, continuing with the local tree"
	else
		log "cloning $REPO_URL into $SRC_DIR"
		command -v git >/dev/null 2>&1 || install_pkgs git
		git clone --depth 1 "$REPO_URL" "$SRC_DIR" || die "clone failed"
		# shellcheck disable=SC2164
		cd "$SRC_DIR"
	fi
}

build() {
	log "building"
	# A writable module cache is needed when building as root from a read-only HOME.
	export GOMODCACHE="${GOMODCACHE:-$SRC_DIR/.gomodcache}"
	go build -buildvcs=false -o "$BIN_DIR/mirage" ./cmd/mirage
	go build -buildvcs=false -o "$BIN_DIR/mirage-admin" ./cmd/mirage-admin
	chmod +x "$BIN_DIR/mirage" "$BIN_DIR/mirage-admin"
	log "installed $BIN_DIR/mirage and $BIN_DIR/mirage-admin"
}

# ---------- service ----------

install_service() {
	mkdir -p "$CONFIG_DIR"
	cp -f deploy/server-nat.sh "$CONFIG_DIR/server-nat.sh"
	chmod +x "$CONFIG_DIR/server-nat.sh"
	cp -f deploy/mirage-server.service "$SERVICE_DIR/mirage-server.service"

	# Wintun is not needed on the server, but Go still fetches the module.
	systemctl daemon-reload
	systemctl enable mirage-server
	log "service installed and enabled (not started yet)"
}

first_run() {
	if [ -f "$CONFIG_DIR/server.json" ]; then
		log "$CONFIG_DIR/server.json exists, leaving it alone"
		return 0
	fi
	DOMAIN=""
	HOST=""
	echo
	echo "First-run setup. The tunnel speaks TLS 1.3 with SNI <domain>."
	ask "server domain (an A/AAAA record pointing at this host)" "example.com"
	DOMAIN="$ANSWER"
	ask "public host or IP clients connect to (empty = the domain)" "$DOMAIN"
	HOST="$ANSWER"

	log "generating keys and configs in $CONFIG_DIR"
	"$BIN_DIR/mirage" keygen -dir "$CONFIG_DIR" -domain "$DOMAIN" -server-addr "$HOST:443"
	chmod 600 "$CONFIG_DIR"/*.json "$CONFIG_DIR"/*.pem 2>/dev/null || true
	log "done. client template: $CONFIG_DIR/client.json"
}

open_firewall() {
	if command -v ufw >/dev/null 2>&1; then
		ufw allow 443/tcp
	elif command -v firewall-cmd >/dev/null 2>&1; then
		firewall-cmd --permanent --add-port=443/tcp
		firewall-cmd --reload
	else
		warn "no firewall manager found; make sure 443/tcp is reachable"
	fi
}

start_service() {
	echo
	ask "start the server now?" "y"
	case "$ANSWER" in
		y|Y|yes)
			systemctl restart mirage-server
			sleep 1
			systemctl --no-pager status mirage-server || true
			;;
		*)
			log "start it later with: systemctl start mirage-server"
			;;
	esac
}

main() {
	[ "$(id -u)" -eq 0 ] || die "run as root"
	command -v systemctl >/dev/null 2>&1 || die "systemd not found (this script targets Linux servers)"
	detect_os
	update_system
	install_pkgs git curl ca-certificates iptables
	install_go
	fetch_source
	build
	install_service
	first_run
	open_firewall
	start_service

	echo
	log "next steps:"
	echo "  manage clients and inbounds:  mirage-admin -c /etc/mirage/server.json"
	echo "  client configs land in:       /etc/mirage/clients/<id>.json"
	echo "  logs:                         journalctl -u mirage-server -f"

	print_client_config
}

print_client_config() {
	cfg="$CONFIG_DIR/client.json"
	[ -f "$cfg" ] || cfg="$CONFIG_DIR/clients/$(ls -1 "$CONFIG_DIR/clients" 2>/dev/null | head -n 1)"
	[ -f "$cfg" ] || return 0

	echo
	log "the client config (one line, safe to paste):"
	if command -v base64 >/dev/null 2>&1; then
		b64=$(base64 -w 0 "$cfg" 2>/dev/null || base64 "$cfg" | tr -d '\n')
		echo "$b64"
		echo
		log "on the client machine:"
		echo "  Linux/mac:  curl -fsSL https://raw.githubusercontent.com/MrClerkSmith/Mirage/main/deploy/install-client.sh | sudo sh"
		echo "  Windows:    powershell -c \"irm https://raw.githubusercontent.com/MrClerkSmith/Mirage/main/deploy/install-client.ps1 | iex\""
		echo
		echo "then paste the line above when the installer asks for the config."
	else
		echo "$cfg"
	fi
}

main "$@"
