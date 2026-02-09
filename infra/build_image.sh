#!/bin/bash
# DEPRECATED: Use infra/image/ (mkosi + dm-verity) instead.
# This script builds a mutable qcow2 image without rootfs integrity.
# The new mkosi-based build produces a dm-verity protected image where
# the rootfs is cryptographically bound to the attestation chain.
#
# New build: cd infra/image && nix develop --command make build
#
# This script is kept for backward compatibility but will be removed.
#
# Build custom TDX VM image with Docker and attestation tools
# Wraps Canonical's create-td-image.sh with customizations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Managed dependencies
DEPS_DIR="${DEPS_DIR:-$PROJECT_ROOT/deps}"
TDX_DIR="$DEPS_DIR/tdx"

# Configuration
IMAGE_NAME="${IMAGE_NAME:-tdx-runner}"
IMAGE_SIZE="${IMAGE_SIZE:-20G}"
UBUNTU_VERSION="${UBUNTU_VERSION:-noble}"  # 24.04 LTS
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/output}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_dependencies() {
    log_info "Checking dependencies..."

    local missing=()

    # Check for required tools
    command -v qemu-img &>/dev/null || missing+=("qemu-utils")
    command -v virt-customize &>/dev/null || missing+=("libguestfs-tools")
    command -v wget &>/dev/null || missing+=("wget")

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_info "Install with: sudo apt-get install ${missing[*]}"
        exit 1
    fi

    log_info "All dependencies available"
}

create_base_image() {
    log_info "Creating base TDX image..."

    mkdir -p "$OUTPUT_DIR"

    BASE_IMAGE="$OUTPUT_DIR/${IMAGE_NAME}-base.qcow2"

    # Check for existing Canonical TDX guest image first
    # Priority: our managed deps, then system locations
    CANONICAL_IMAGES=(
        "$TDX_DIR/guest-tools/image/tdx-guest-ubuntu-24.04-generic.qcow2"
        "/home/ubuntu/tdx/guest-tools/image/tdx-guest-ubuntu-24.04-generic.qcow2"
        "/opt/canonical-tdx/guest-tools/image/tdx-guest-ubuntu-24.04-generic.qcow2"
        "$HOME/tdx/guest-tools/image/tdx-guest-ubuntu-24.04-generic.qcow2"
    )

    for img in "${CANONICAL_IMAGES[@]}"; do
        if [ -f "$img" ]; then
            log_info "Found existing Canonical TDX image: $img"
            log_info "Copying as base image..."
            cp "$img" "$BASE_IMAGE"

            # Resize if needed
            CURRENT_SIZE=$(qemu-img info --output=json "$BASE_IMAGE" | jq -r '.["virtual-size"]')
            TARGET_SIZE_BYTES=$(numfmt --from=iec "$IMAGE_SIZE")
            if [ "$CURRENT_SIZE" -lt "$TARGET_SIZE_BYTES" ]; then
                log_info "Resizing image to $IMAGE_SIZE..."
                qemu-img resize "$BASE_IMAGE" "$IMAGE_SIZE"
            fi

            log_info "Base image created: $BASE_IMAGE"
            return 0
        fi
    done

    # No existing image found - download Ubuntu cloud image
    log_info "No existing TDX image found, downloading Ubuntu cloud image..."

    CLOUD_IMAGE_URL="https://cloud-images.ubuntu.com/${UBUNTU_VERSION}/current/${UBUNTU_VERSION}-server-cloudimg-amd64.img"
    CLOUD_IMAGE="$OUTPUT_DIR/ubuntu-cloud-${UBUNTU_VERSION}.img"

    if [ ! -f "$CLOUD_IMAGE" ]; then
        log_info "Downloading from: $CLOUD_IMAGE_URL"
        wget -q --show-progress -O "$CLOUD_IMAGE" "$CLOUD_IMAGE_URL" || {
            log_error "Failed to download cloud image"
            exit 1
        }
    else
        log_info "Using cached cloud image: $CLOUD_IMAGE"
    fi

    # Convert and resize
    log_info "Converting to qcow2 and resizing to $IMAGE_SIZE..."
    qemu-img convert -f qcow2 -O qcow2 "$CLOUD_IMAGE" "$BASE_IMAGE"
    qemu-img resize "$BASE_IMAGE" "$IMAGE_SIZE"

    # Sealed mode: lock passwords and disable SSH (cloud-init --debug can re-enable)
    log_info "Configuring base image for TDX use (sealed mode)..."
    sudo virt-customize -a "$BASE_IMAGE" \
        --run-command 'useradd -m -s /bin/bash -G sudo ubuntu || true' \
        --run-command 'echo "ubuntu ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/ubuntu' \
        --run-command 'passwd -l root' \
        --run-command 'passwd -l ubuntu' \
        --run-command 'systemctl disable ssh || true' \
        --firstboot-command 'growpart /dev/sda 1 && resize2fs /dev/sda1 || true' \
        || {
            log_error "Base image configuration failed"
            exit 1
        }

    log_info "Base image created: $BASE_IMAGE"
}

customize_image() {
    log_info "Customizing image with Docker and attestation tools..."

    BASE_IMAGE="$OUTPUT_DIR/${IMAGE_NAME}-base.qcow2"
    FINAL_IMAGE="$OUTPUT_DIR/${IMAGE_NAME}.qcow2"

    if [ ! -f "$BASE_IMAGE" ]; then
        log_error "Base image not found: $BASE_IMAGE"
        exit 1
    fi

    # Copy base to final
    cp "$BASE_IMAGE" "$FINAL_IMAGE"

    # Use virt-customize to add packages
    log_info "Installing packages via virt-customize..."

    sudo virt-customize -a "$FINAL_IMAGE" \
        --run-command 'apt-get update' \
        --run-command 'apt-get install -y ca-certificates curl gnupg lsb-release' \
        --run-command 'install -m 0755 -d /etc/apt/keyrings' \
        --run-command 'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg' \
        --run-command 'chmod a+r /etc/apt/keyrings/docker.gpg' \
        --run-command 'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list' \
        --run-command 'apt-get update' \
        --run-command 'apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin' \
        --run-command 'systemctl enable docker' \
        --run-command 'usermod -aG docker ubuntu || true' \
        --run-command 'usermod -aG docker tdx || true' \
        --copy-in "$SCRIPT_DIR/launcher:/tmp" \
        --run "$SCRIPT_DIR/customize.sh" \
        || {
            log_error "Image customization failed"
            exit 1
        }

    log_info "Final image created: $FINAL_IMAGE"
}

verify_image() {
    log_info "Verifying image..."

    FINAL_IMAGE="$OUTPUT_DIR/${IMAGE_NAME}.qcow2"

    # Quick verification with virt-cat
    if command -v virt-cat &>/dev/null; then
        log_info "Checking /etc/os-release..."
        sudo virt-cat -a "$FINAL_IMAGE" /etc/os-release | head -5
    fi

    log_info "Image verification complete"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build a custom TDX VM image with Docker and attestation tools.

Options:
    -n, --name NAME       Image name (default: tdx-runner)
    -s, --size SIZE       Image size (default: 20G)
    -o, --output DIR      Output directory (default: ./output)
    -b, --base-only       Create base image only (no customization)
    -c, --customize-only  Customize existing base image only
    -h, --help            Show this help message

Environment Variables:
    CREATE_TD_IMAGE_PATH  Path to create-td-image.sh
    UBUNTU_VERSION        Ubuntu version (default: noble)

Examples:
    $0                          # Build full custom image
    $0 -n my-image -s 30G      # Custom name and size
    $0 --base-only              # Only create base image
    $0 --customize-only         # Only customize existing base
EOF
}

main() {
    BASE_ONLY=false
    CUSTOMIZE_ONLY=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--name)
                IMAGE_NAME="$2"
                shift 2
                ;;
            -s|--size)
                IMAGE_SIZE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -b|--base-only)
                BASE_ONLY=true
                shift
                ;;
            -c|--customize-only)
                CUSTOMIZE_ONLY=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    log_info "Building TDX image: $IMAGE_NAME"
    log_info "Output directory: $OUTPUT_DIR"

    # Check dependencies
    check_dependencies

    # Check for TDX tools
    if [ ! -d "$TDX_DIR" ]; then
        log_warn "TDX tools not found in $TDX_DIR"
        log_info "Will use fallback image sources if available..."
    fi

    if [ "$CUSTOMIZE_ONLY" = true ]; then
        customize_image
    elif [ "$BASE_ONLY" = true ]; then
        create_base_image
    else
        create_base_image
        customize_image
    fi

    verify_image

    log_info "Build complete!"
    echo
    echo "Image location: $OUTPUT_DIR/${IMAGE_NAME}.qcow2"
    echo
    echo "Next steps:"
    echo "  1. Test the image: python3 infra/tdx_cli.py vm new -i $OUTPUT_DIR/${IMAGE_NAME}.qcow2"
    echo "  2. Or with the CLI: tdx vm new -i $OUTPUT_DIR/${IMAGE_NAME}.qcow2"
}

main "$@"
