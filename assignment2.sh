#!/usr/bin/env bash
set -euo pipefail

# ========== Configuration ==========
TARGET_IP="192.168.16.21/24"
GATEWAY_IP="192.168.16.2"
USERS=(dennis aubrey captain snibbles brownie scooter sandy perrier cindy tiger yoda)
ADMIN_USER="dennis"
ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm"

# ========== Utility functions ==========
log() { echo -e "\n\033[1;34m[INFO]\033[0m $*"; }
ok()  { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root. Try: sudo bash assignment2.sh"
    exit 1
  fi
}

pkg_install() {
  apt-get update -y
  apt-get install -y "$@"
}

ensure_service() {
  systemctl enable "$1"
  systemctl restart "$1"
}

ensure_user() {
  local user="$1"
  if ! id "$user" &>/dev/null; then
    useradd -m -s /bin/bash "$user"
    ok "Created user $user"
  fi
}

ensure_sudo() {
  local user="$1"
  usermod -aG sudo "$user" 2>/dev/null || true
}

ensure_ssh_keys() {
  local user="$1"
  local home_dir="/home/$user"
  mkdir -p "$home_dir/.ssh"
  chmod 700 "$home_dir/.ssh"
  chown "$user:$user" "$home_dir/.ssh"

  for type in rsa ed25519; do
    if [[ ! -f "$home_dir/.ssh/id_$type" ]]; then
      sudo -u "$user" ssh-keygen -t "$type" -N "" -f "$home_dir/.ssh/id_$type" >/dev/null
    fi
  done

  local auth="$home_dir/.ssh/authorized_keys"
  touch "$auth"
  chmod 600 "$auth"
  chown "$user:$user" "$auth"

  for key in "$home_dir/.ssh/id_rsa.pub" "$home_dir/.ssh/id_ed25519.pub"; do
    grep -Fq "$(cat "$key")" "$auth" || cat "$key" >> "$auth"
  done
}

# ========== Network Configuration ==========
configure_network() {
  if ip -o -4 addr show | grep -q "192\.168\.16\.21/24"; then ok "Network already configured; skipping"; return; fi
  local iface
  iface=$(ip -o -4 addr show | awk '$4 ~ /^192\.168\.16\./ {print $2; exit}')
  if [[ -z "$iface" ]]; then
    err "Could not detect interface on 192.168.16.x network"
    exit 1
  fi

  log "Configuring static IP on $iface..."
  netplan set "network.ethernets.${iface}.dhcp4=false"
  netplan set "network.ethernets.${iface}.addresses=[${TARGET_IP}]"
  netplan set "network.ethernets.${iface}.routes=[{to=0.0.0.0/0,via=${GATEWAY_IP}}]"
  netplan set "network.ethernets.${iface}.nameservers.addresses=[1.1.1.1,8.8.8.8]"
  netplan generate && netplan apply
  ok "Network configured successfully"
}

# ========== Host file ==========
fix_hosts() {
  sed -i '/server1/d' /etc/hosts
  echo "192.168.16.21 server1" >> /etc/hosts
  ok "/etc/hosts updated"
}

# ========== Software ==========
install_software() {
  log "Installing required packages..."
  pkg_install apache2 squid
  ensure_service apache2
  ensure_service squid
}

# ========== Users ==========
create_users() {
  for u in "${USERS[@]}"; do
    ensure_user "$u"
    ensure_ssh_keys "$u"
  done

  ensure_sudo "$ADMIN_USER"
  local auth="/home/${ADMIN_USER}/.ssh/authorized_keys"
  grep -Fq "$ADMIN_PUBKEY" "$auth" || echo "$ADMIN_PUBKEY" >> "$auth"
  ok "All users configured successfully"
}

# ========== Main ==========
main() {
  require_root
  configure_network
  fix_hosts
  install_software
  create_users
  ok "Assignment 2 configuration completed successfully."
}

main "$@"
