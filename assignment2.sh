#!/bin/bash
# Assignment 2 - System Modification Script

set -euo pipefail

log_info()  { echo "[INFO] $*"; }
log_ok()    { echo "[ OK ] $*"; }
log_error() { echo "[ERROR] $*" >&2; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 1
  fi
}

configure_network() {
  log_info "Checking network configuration for 192.168.16.21/24..."

  # Find interface currently on 192.168.16.0/24 (e.g. eth0)
  local iface
  iface=$(ip -o -4 addr show | awk '/192\.168\.16\./{print $2; exit}')
  if [[ -z "$iface" ]]; then
    log_error "Could not find an interface on 192.168.16.0/24."
    return 1
  fi

  # If already correct, skip
  if ip -4 addr show dev "$iface" | grep -q '192.168.16.21/24'; then
    log_ok "Network already configured on $iface; skipping."
  else
    cat > /etc/netplan/99-assign2.yaml <<EOF
network:
  version: 2
  ethernets:
    $iface:
      dhcp4: false
      addresses:
        - 192.168.16.21/24
      routes:
        - to: 0.0.0.0/0
          via: 192.168.16.2
      nameservers:
        addresses: [192.168.16.2, 1.1.1.1, 8.8.8.8]
EOF

    chmod 600 /etc/netplan/99-assign2.yaml

    netplan generate
    netplan apply
    sleep 2

    if ! ip -4 addr show dev "$iface" | grep -q '192.168.16.21/24'; then
      log_error "Failed to configure static IP on $iface."
      return 1
    fi
    log_ok "Static IP 192.168.16.21/24 configured on $iface."
  fi

  # /etc/hosts update for server1
  sed -i '/server1/d' /etc/hosts
  echo "192.168.16.21 server1" >> /etc/hosts
  log_ok "/etc/hosts updated with 192.168.16.21 server1."
}

configure_software() {
  log_info "Ensuring apache2 and squid are installed and running..."

  # Make sure apt metadata is current
  apt-get update -y

  # Install packages if missing
  if ! dpkg -s apache2 &>/dev/null; then
    apt-get install -y apache2
  fi
  if ! dpkg -s squid &>/dev/null; then
    apt-get install -y squid
  fi

  # Ensure services are enabled and running
  systemctl enable --now apache2
  systemctl enable --now squid

  systemctl is-active --quiet apache2 || log_error "apache2 is not active."
  systemctl is-active --quiet squid   || log_error "squid is not active."

  log_ok "apache2 and squid installed and running."
}

ensure_user() {
  local user="$1"

  if id "$user" &>/dev/null; then
    log_ok "User $user already exists."
  else
    useradd -m -s /bin/bash "$user"
    log_ok "Created user $user."
  fi

  # Ensure home and shell are correct
  local home shell
  home=$(getent passwd "$user" | cut -d: -f6)
  shell=$(getent passwd "$user" | cut -d: -f7)

  if [[ ! -d "$home" ]]; then
    mkdir -p "$home"
    chown "$user:$user" "$home"
    log_info "Created home directory $home for $user."
  fi

  if [[ "$shell" != "/bin/bash" ]]; then
    usermod -s /bin/bash "$user"
    log_info "Set /bin/bash as default shell for $user."
  fi
}

ensure_ssh_keys_for_user() {
  local user="$1"
  local home
  home=$(getent passwd "$user" | cut -d: -f6)

  su - "$user" -s /bin/bash <<'EOF'
set -e
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# RSA key
if [[ ! -f ~/.ssh/id_rsa ]]; then
  ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa >/dev/null 2>&1
fi

# ED25519 key
if [[ ! -f ~/.ssh/id_ed25519 ]]; then
  ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 >/dev/null 2>&1
fi

touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

for pub in ~/.ssh/id_rsa.pub ~/.ssh/id_ed25519.pub; do
  key=$(cat "$pub")
  grep -qxF "$key" ~/.ssh/authorized_keys || echo "$key" >> ~/.ssh/authorized_keys
done
EOF

  log_ok "SSH keys (RSA + ED25519) configured for $user."
}

configure_users() {
  log_info "Configuring required user accounts..."

  local users=(
    dennis
    aubrey
    captain
    snibbles
    brownie
    scooter
    sandy
    perrier
    cindy
    tiger
    yoda
  )

  for u in "${users[@]}"; do
    ensure_user "$u"
    ensure_ssh_keys_for_user "$u"
  done

  # Ensure dennis is in sudo
  if id dennis &>/dev/null; then
    usermod -aG sudo dennis || true
    log_ok "User dennis ensured as sudoer."

    # Add professor's ed25519 key to dennis
    local prof_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm"

    su - dennis -s /bin/bash <<EOF
set -e
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
grep -qxF "$prof_key" ~/.ssh/authorized_keys || echo "$prof_key" >> ~/.ssh/authorized_keys
EOF

    log_ok "Professor's SSH key added for dennis."
  else
    log_error "User dennis does not exist – this should not happen."
  fi

  log_ok "All user accounts configured."
}

main() {
  require_root
  configure_network
  configure_software
  configure_users
  log_ok "Assignment 2 configuration completed successfully."
}

main "$@"
