#!/bin/sh
# Customization script run inside the VM image via virt-customize
# Installs attestation tools and configures the environment
# NOTE: Uses POSIX shell for virt-customize compatibility

set -e

echo "[customize.sh] Starting customization..."

# Update package lists
apt-get update

# Install attestation dependencies
apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    jq \
    curl \
    wget \
    git \
    python3 \
    python3-requests

# Install libtdx-attest-dev for quote generation (optional)
# This may be from Intel's repository - not always available
echo "[customize.sh] Checking for libtdx-attest-dev..."
if apt-get install -y libtdx-attest-dev 2>/dev/null; then
    echo "[customize.sh] Installed libtdx-attest-dev from repository"
else
    echo "[customize.sh] libtdx-attest-dev not available (OK - using ConfigFS-TSM interface)"
fi

# Install Intel Trust Authority CLI (optional)
# Try multiple versions/URLs as the release structure may vary
echo "[customize.sh] Attempting to install Intel Trust Authority CLI..."

TRUSTAUTHORITY_INSTALLED=false
mkdir -p /tmp/trustauthority
cd /tmp/trustauthority

# Try different release URLs (POSIX shell compatible)
# Note: Newer releases use format trustauthority-cli-v{version}.tar.gz
for url in \
    "https://github.com/intel/trustauthority-client-for-go/releases/latest/download/trustauthority-cli-v1.10.1.tar.gz" \
    "https://github.com/intel/trustauthority-client-for-go/releases/download/v1.10.1/trustauthority-cli-v1.10.1.tar.gz" \
    "https://github.com/intel/trustauthority-client-for-go/releases/download/v1.9.0/trustauthority-cli-v1.9.0.tar.gz" \
    "https://github.com/intel/trustauthority-client-for-go/releases/latest/download/trustauthority-cli_Linux_x86_64.tar.gz"
do
    echo "[customize.sh] Trying: $url"
    if curl -fsSL -L -o trustauthority-cli.tar.gz "$url" 2>/dev/null; then
        # Try gzip first, then plain tar (some releases are tar despite .tar.gz extension)
        if tar -xzf trustauthority-cli.tar.gz 2>/dev/null || tar -xf trustauthority-cli.tar.gz 2>/dev/null; then
            # Find the binary (might be in subdirectory or root)
            CLI_BIN=$(find . -name "trustauthority-cli" -type f 2>/dev/null | head -1)
            if [ -n "$CLI_BIN" ] && [ -f "$CLI_BIN" ]; then
                install -m 755 "$CLI_BIN" /usr/local/bin/trustauthority-cli
                echo "[customize.sh] trustauthority-cli installed to /usr/local/bin/"
                TRUSTAUTHORITY_INSTALLED=true
                break
            fi
        fi
    fi
    rm -f trustauthority-cli.tar.gz trustauthority-cli trustauthority-cli.sig trustauthority-cli.cer 2>/dev/null || true
done

if [ "$TRUSTAUTHORITY_INSTALLED" = false ]; then
    echo "[customize.sh] trustauthority-cli not installed (OK - can use ConfigFS-TSM directly)"
fi

cd /
rm -rf /tmp/trustauthority

# Configure ConfigFS-TSM for TDX attestation
cat > /etc/systemd/system/tdx-tsm-setup.service << 'SERVICEUNIT'
[Unit]
Description=Setup ConfigFS-TSM for TDX attestation
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'modprobe configfs 2>/dev/null || true; mount -t configfs none /sys/kernel/config 2>/dev/null || true'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICEUNIT

systemctl enable tdx-tsm-setup.service

# Create docker-compose wrapper for attestation metadata
cat > /usr/local/bin/compose-with-attestation << 'COMPOSESCRIPT'
#!/bin/bash
# Run docker-compose and capture attestation metadata
# Usage: compose-with-attestation [compose args...]

set -e

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
ATTESTATION_DIR="${ATTESTATION_DIR:-/tmp/attestation}"

mkdir -p "$ATTESTATION_DIR"

# Compute hash of compose file
if [ -f "$COMPOSE_FILE" ]; then
    sha256sum "$COMPOSE_FILE" | awk '{print $1}' > "$ATTESTATION_DIR/compose_hash.txt"
    echo "Compose file hash: $(cat $ATTESTATION_DIR/compose_hash.txt)"
fi

# Run docker-compose pull and capture image digests
echo "Pulling images..."
docker compose -f "$COMPOSE_FILE" pull 2>&1 | tee "$ATTESTATION_DIR/pull_output.txt"

# Get image digests
docker compose -f "$COMPOSE_FILE" config --images | while read image; do
    digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$image" 2>/dev/null || echo "unknown")
    echo "$image: $digest"
done > "$ATTESTATION_DIR/image_digests.txt"

echo "Image digests captured to $ATTESTATION_DIR/image_digests.txt"

# Run docker-compose with remaining args
exec docker compose -f "$COMPOSE_FILE" "$@"
COMPOSESCRIPT
chmod +x /usr/local/bin/compose-with-attestation

# =============================================================================
# Configure Virtio-fs Mount
# =============================================================================
echo "[customize.sh] Configuring virtio-fs mount..."

# Create mount point for virtio-fs shared directory
mkdir -p /mnt/share

# Add fstab entry for 9P filesystem (virtiofs doesn't work with TDX due to IOMMU requirements)
# The mount tag "share" must match the target dir in the XML template
echo "share /mnt/share 9p trans=virtio,version=9p2000.L,nofail 0 0" >> /etc/fstab

# =============================================================================
# Install Launcher Service
# =============================================================================
echo "[customize.sh] Installing launcher service..."

# Create launcher directory
# Note: We use /opt/launcher since /home/ubuntu doesn't exist during virt-customize
# (ubuntu user is created by cloud-init on first boot)
mkdir -p /opt/launcher

# Copy launcher files (these are placed by virt-customize --copy-in)
# The files should be at /tmp/launcher/ after --copy-in launcher:/tmp/
if [ -d /tmp/launcher ]; then
    cp /tmp/launcher/launcher.py /opt/launcher/
    chmod +x /opt/launcher/launcher.py
    rm -rf /tmp/launcher
fi

# Create systemd service for file-based launcher
cat > /etc/systemd/system/tdx-launcher.service << 'LAUNCHERSERVICE'
[Unit]
Description=TDX VM File-based Launcher Service
After=local-fs.target docker.service
Wants=docker.service
# Don't require mount - launcher will wait for it
# RequiresMountsFor=/mnt/share

[Service]
Type=simple
User=root
WorkingDirectory=/opt/launcher
ExecStart=/usr/bin/python3 /opt/launcher/launcher.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
LAUNCHERSERVICE

# Enable launcher service to start on boot
systemctl enable tdx-launcher.service

# Create workload directory (no chown needed as launcher runs as root)
mkdir -p /home/tdx

# =============================================================================
# Cleanup
# =============================================================================
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "[customize.sh] Customization complete!"
echo "Installed:"
echo "  - Docker CE + docker-compose plugin"
echo "  - trustauthority-cli (if available)"
echo "  - libtdx-attest-dev (if available)"
echo "  - compose-with-attestation wrapper"
echo "  - TDX Launcher service (file-based via 9P)"
echo "  - 9P mount point at /mnt/share"
