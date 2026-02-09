# EasyEnclave VM Image Build
#
# Builds a dm-verity protected TDX VM image using mkosi.
#
# Prerequisites: nix develop (provides mkosi, systemd, qemu-utils)
# Usage:
#   make build    - Build the image
#   make clean    - Remove build artifacts
#
# Outputs (in output/):
#   easyenclave.vmlinuz     - Kernel
#   easyenclave.initrd      - Initrd with dm-verity support
#   easyenclave.root.raw    - Root filesystem (read-only)
#   easyenclave.root.verity - Verity hash tree
#   easyenclave.cmdline     - Kernel cmdline with roothash=

LAUNCHER_DIR := ../launcher
EXTRA_DIR := mkosi.extra/opt/launcher
PKG_MGR_DIR := mkosi.pkg-manager/etc/apt
OUTPUT_DIR := output

LAUNCHER_FILES := $(LAUNCHER_DIR)/launcher.py $(wildcard $(LAUNCHER_DIR)/admin.html)

.PHONY: build clean setup-repos

build: $(EXTRA_DIR)/launcher.py setup-repos
	mkosi build --sandbox=no
	@# Copy split artifacts to output/ for easy consumption by tdx_cli.py
	mkdir -p $(OUTPUT_DIR)
	@# mkosi puts split artifacts in the build directory
	@# Find and copy the key artifacts
	@for f in mkosi.output/easyenclave*.vmlinuz; do \
		[ -f "$$f" ] && cp "$$f" $(OUTPUT_DIR)/easyenclave.vmlinuz && break; \
	done 2>/dev/null || true
	@for f in mkosi.output/easyenclave*.initrd; do \
		[ -f "$$f" ] && cp "$$f" $(OUTPUT_DIR)/easyenclave.initrd && break; \
	done 2>/dev/null || true
	@for f in mkosi.output/easyenclave*.root*.raw; do \
		[ -f "$$f" ] && cp "$$f" $(OUTPUT_DIR)/easyenclave.root.raw && break; \
	done 2>/dev/null || true
	@for f in mkosi.output/easyenclave*.root*.verity; do \
		[ -f "$$f" ] && cp "$$f" $(OUTPUT_DIR)/easyenclave.root.verity && break; \
	done 2>/dev/null || true
	@# Extract roothash from mkosi output and create cmdline file
	@if [ -f mkosi.output/easyenclave*.roothash ]; then \
		ROOTHASH=$$(cat mkosi.output/easyenclave*.roothash); \
		echo "root=/dev/dm-0 roothash=$$ROOTHASH console=ttyS0,115200 console=tty0" \
			> $(OUTPUT_DIR)/easyenclave.cmdline; \
		echo "Roothash: $$ROOTHASH"; \
	else \
		echo "Warning: roothash file not found in mkosi output"; \
		ls mkosi.output/ 2>/dev/null || true; \
	fi
	@echo ""
	@echo "Build complete. Artifacts in $(OUTPUT_DIR)/:"
	@ls -lh $(OUTPUT_DIR)/ 2>/dev/null || true

# Download third-party GPG keys and create apt source lists.
# PackageManagerTrees= injects these into the image before Packages= runs.
setup-repos:
	@echo "Setting up third-party apt repos..."
	@mkdir -p $(PKG_MGR_DIR)/keyrings $(PKG_MGR_DIR)/sources.list.d
	@curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
		| gpg --batch --yes --dearmor -o $(PKG_MGR_DIR)/keyrings/docker.gpg
	@chmod a+r $(PKG_MGR_DIR)/keyrings/docker.gpg
	@echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" \
		> $(PKG_MGR_DIR)/sources.list.d/docker.list
	@curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
		| gpg --batch --yes --dearmor -o $(PKG_MGR_DIR)/keyrings/cloudflare.gpg
	@chmod a+r $(PKG_MGR_DIR)/keyrings/cloudflare.gpg
	@echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/cloudflare.gpg] https://pkg.cloudflare.com/cloudflared noble main" \
		> $(PKG_MGR_DIR)/sources.list.d/cloudflared.list
	@echo "Apt repos ready."

# Copy launcher files into mkosi.extra tree before build
$(EXTRA_DIR)/launcher.py: $(LAUNCHER_FILES)
	mkdir -p $(EXTRA_DIR)
	cp $(LAUNCHER_DIR)/launcher.py $(EXTRA_DIR)/
	cp $(LAUNCHER_DIR)/admin.html $(EXTRA_DIR)/ 2>/dev/null || true

clean:
	rm -rf mkosi.output mkosi.extra mkosi.pkg-manager $(OUTPUT_DIR)
	mkosi clean 2>/dev/null || true
