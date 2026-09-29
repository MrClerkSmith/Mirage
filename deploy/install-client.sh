#!/bin/sh
# Mirage client installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/MrClerkSmith/Mirage/main/deploy/install-client.sh | sudo sh
#
# Asks for the client config at the end: either a path to a client.json or the
# one-line base64 config printed by the server installer. Non-interactive:
#
#   sh install-client.sh -b64 "eyJtb2RlIj..."
#   sh install-client.sh -c /home/me/Downloads/home.json
#   sh install-client.sh -foreground

set -eu

REPO_URL=https://github.com/MrClerkSmith/Mirage.git
SRC_DIR=/opt/mirage-client
CONFIG_DIR=/etc/mirage
SERVICE=mirage-client
BRANCH=main
GO_VERSION=go1.23.4

CONFIG_FILE=
CONFIG_B64=
FOREGROUND=0

while [ $# -gt 0 ]; do
	case "$1" in
		-c)       CONFIG_FILE="$2"; shift 2 ;;
		-b64)     CONFIG_B64="$2"; shift 2 ;;
		-foreground) FOREGROUND=1; shift ;;
		-branch)  BRANCH="$2"; shift 2 ;;
		*)        echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m==>\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (the service and the TUN interface need it)"

# ---------- config ----------

if [ -n "$CONFIG_FILE" ]; then
	[ -f "$CONFIG_FILE" ] || die "config file not found: $CONFIG_FILE"
	json=$(cat "$CONFIG_FILE")
elif [ -n "$CONFIG_B64" ]; then
	json=$(printf '%s' "$CONFIG_B64" | base64 -d) || die "bad base64 config"
else
	log "client config"
	echo "Paste the config from the server:"
	echo "  - a path to client.json, or"
	echo "  - the one-line base64 config the server installer printed"
	printf 'config: '
	read line
	if [ -f "$line" ]; then
		json=$(cat "$line")
	else
		json=$(printf '%s' "$line" | base64 -d 2>/dev/null) || die "that is neither a file nor valid base64"
	fi
fi
echo "$json" | grep -q '"server_addr"' || die "the config does not look like a Mirage client config"

# ---------- go ----------

go_ok() {
	command -v go >/dev/null 2>&1 || return 1
	v=$(go version | awk '{print $3}' | sed 's/^go//')
	major=${v%%.*}; rest=${v#*.}; minor=${rest%%.*}
	[ "$major" -gt 1 ] && return 0
	[ "$major" -eq 1 ] && [ "$minor" -ge 23 ] && return 0
	return 1
}

install_go() {
	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	arch=amd64
	case "$(uname -m)" in
		x86_64|amd64)  arch=amd64 ;;
		aarch64|arm64) arch=arm64 ;;
		armv7l)        arch=armv6l ;;
		*)             die "unsupported cpu architecture: $(uname -m)" ;;
	esac
	log "installing $GO_VERSION for $os-$arch"
	command -v curl >/dev/null 2>&1 || install_pkgs curl
	url="https://go.dev/dl/$GO_VERSION.$os-$arch.tar.gz"
	curl -fsSL "$url" -o /tmp/go.tar.gz || die "download failed: $url"
	rm -rf /usr/local/go
	tar -C /usr/local -xzf /tmp/go.tar.gz || die "cannot extract go"
	rm -f /tmp/go.tar.gz
	export PATH="$PATH:/usr/local/go/bin"
}

install_pkgs() {
	if command -v apt-get >/dev/null 2>&1; then apt-get install -y "$@"
	elif command -v dnf >/dev/null 2>&1; then dnf install -y "$@"
	elif command -v yum >/dev/null 2>&1; then yum install -y "$@"
	elif command -v pacman >/dev/null 2>&1; then pacman -S --noconfirm --needed "$@"
	elif command -v apk >/dev/null 2>&1; then apk add "$@"
	else die "cannot install $*: no package manager found"
	fi
}

if go_ok; then
	log "go $(go version | awk '{print $3}') already installed"
else
	command -v git >/dev/null 2>&1 || install_pkgs git
	install_go
fi

# ---------- source and build ----------

if [ -d "$SRC_DIR/.git" ]; then
	log "updating $SRC_DIR"
	cd "$SRC_DIR"
	git pull --ff-only || warn "git pull failed, continuing with the local tree"
else
	log "cloning $REPO_URL into $SRC_DIR"
	command -v git >/dev/null 2>&1 || install_pkgs git
	git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$SRC_DIR" || die "clone failed"
	cd "$SRC_DIR"
fi

log "building"
export GOMODCACHE="${GOMODCACHE:-$SRC_DIR/.gomodcache}"
go build -buildvcs=false -o mirage ./cmd/mirage
chmod +x mirage

# ---------- config file ----------

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
printf '%s\n' "$json" > "$CONFIG_DIR/client.json"
chmod 600 "$CONFIG_DIR/client.json"

# ---------- run ----------

if [ "$FOREGROUND" -eq 1 ]; then
	log "running in the foreground (ctrl-c to stop)"
	exec "$SRC_DIR/mirage" client -c "$CONFIG_DIR/client.json"
fi

if command -v systemctl >/dev/null 2>&1; then
	cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=Mirage VPN client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SRC_DIR/mirage client -c $CONFIG_DIR/client.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable "$SERVICE"
	systemctl restart "$SERVICE"
	log "installed and started: systemctl status $SERVICE"
else
	log "no systemd found; starting in the background"
	nohup "$SRC_DIR/mirage" client -c "$CONFIG_DIR/client.json" >> /var/log/mirage-client.log 2>&1 &
	log "logs: tail -f /var/log/mirage-client.log"
fi

echo
log "done. config: $CONFIG_DIR/client.json"
echo "trouble: rerun with -foreground to see the logs"
