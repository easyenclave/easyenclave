#!/usr/bin/env bash
set -euo pipefail

if [ ! -s /tmp/ee-agent ]; then
  echo "Missing /tmp/ee-agent uploaded by packer file provisioner" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  gnupg \
  jq \
  lsb-release

install -m 0755 /tmp/ee-agent /usr/local/bin/ee-agent
rm -f /tmp/ee-agent

docker_codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
if [ -z "${docker_codename}" ]; then
  echo "Missing VERSION_CODENAME for Docker repo setup" >&2
  exit 1
fi
docker_arch="$(dpkg --print-architecture)"
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod 0644 /etc/apt/keyrings/docker.gpg
cat > /etc/apt/sources.list.d/docker.list <<DOCKERREPO
deb [arch=${docker_arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${docker_codename} stable
DOCKERREPO
apt-get update
apt-get install -y --no-install-recommends \
  containerd.io \
  docker-buildx-plugin \
  docker-ce \
  docker-ce-cli

install -d -m 0755 /usr/local/bin /home/tdx /etc/easyenclave /etc/apt/keyrings

cat > /etc/systemd/system/easyenclave-agent.service <<'SERVICEUNIT'
[Unit]
Description=EasyEnclave Agent Service
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/tdx
Environment=EE_AGENT_MODE=agent
Environment=EASYENCLAVE_CONFIG=/etc/easyenclave/agent.json
ExecStart=/usr/local/bin/ee-agent
Restart=on-failure
RestartSec=5
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
SERVICEUNIT

cat > /etc/systemd/system/easyenclave-control-plane.service <<'SERVICEUNIT'
[Unit]
Description=EasyEnclave Control Plane Service
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/tdx
Environment=EE_AGENT_MODE=control-plane
Environment=EASYENCLAVE_CONFIG=/etc/easyenclave/control-plane.json
ExecStart=/usr/local/bin/ee-agent
Restart=on-failure
RestartSec=5
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
SERVICEUNIT

cloudflare_codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
if [ -z "${cloudflare_codename}" ]; then
  echo "Missing VERSION_CODENAME for cloudflared repo setup" >&2
  exit 1
fi
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | gpg --dearmor -o /etc/apt/keyrings/cloudflare-main.gpg
chmod 0644 /etc/apt/keyrings/cloudflare-main.gpg
cat > /etc/apt/sources.list.d/cloudflared.list <<APTREPO
deb [signed-by=/etc/apt/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared ${cloudflare_codename} main
APTREPO
apt-get update
apt-get install -y --no-install-recommends cloudflared

systemctl daemon-reload
systemctl enable docker
systemctl enable easyenclave-agent.service
systemctl disable easyenclave-control-plane.service || true

apt-get clean
rm -rf /var/lib/apt/lists/*
