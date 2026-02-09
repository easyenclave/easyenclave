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
OUTPUT_DIR := output

LAUNCHER_FILES := $(LAUNCHER_DIR)/launcher.py $(wildcard $(LAUNCHER_DIR)/admin.html)

.PHONY: build clean

build: $(EXTRA_DIR)/launcher.py
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

# Copy launcher files into mkosi.extra tree before build
$(EXTRA_DIR)/launcher.py: $(LAUNCHER_FILES)
	mkdir -p $(EXTRA_DIR)
	cp $(LAUNCHER_DIR)/launcher.py $(EXTRA_DIR)/
	cp $(LAUNCHER_DIR)/admin.html $(EXTRA_DIR)/ 2>/dev/null || true

clean:
	rm -rf mkosi.output mkosi.extra $(OUTPUT_DIR)
	mkosi clean 2>/dev/null || true
