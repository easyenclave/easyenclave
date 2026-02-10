# EasyEnclave VM Image Build
#
# Builds a dm-verity protected TDX VM image using mkosi.
# mkosi produces a UKI (Unified Kernel Image) that embeds kernel + initrd +
# cmdline (with roothash derived from the verity partitions automatically).
# We extract the boot artifacts from the UKI using objcopy.
#
# Prerequisites: nix develop (provides mkosi, systemd, qemu-utils, binutils)
# Usage:
#   make build    - Build the image
#   make clean    - Remove build artifacts
#
# Outputs (in output/):
#   easyenclave.vmlinuz     - Kernel
#   easyenclave.initrd      - Initrd with dm-verity support
#   easyenclave.root.raw    - Full GPT disk (ESP + root + verity hash partitions)
#   easyenclave.cmdline     - Kernel cmdline with roothash=

LAUNCHER_DIR := ../launcher
EXTRA_DIR := mkosi.extra/opt/launcher
OUTPUT_DIR := output

LAUNCHER_FILES := $(LAUNCHER_DIR)/launcher.py $(wildcard $(LAUNCHER_DIR)/admin.html)

.PHONY: build clean

build: $(EXTRA_DIR)/launcher.py
	mkosi build --sandbox=no
	mkdir -p $(OUTPUT_DIR)
	@# mkosi v25 places split artifacts in CWD (not mkosi.output/)
	@# Find the UKI (.efi) and extract kernel, initrd, cmdline using objcopy.
	@# The UKI's cmdline already contains the roothash derived by mkosi from
	@# the verity partition configuration — no manual extraction needed.
	@UKI=""; \
	for f in easyenclave*.efi; do \
		[ -f "$$f" ] && UKI="$$f" && break; \
	done 2>/dev/null; \
	if [ -n "$$UKI" ]; then \
		echo "Extracting boot artifacts from UKI: $$UKI"; \
		objcopy --dump-section .linux=$(OUTPUT_DIR)/easyenclave.vmlinuz \
		        --dump-section .initrd=$(OUTPUT_DIR)/easyenclave.initrd \
		        --dump-section .cmdline=$(OUTPUT_DIR)/easyenclave.cmdline.raw \
		        "$$UKI"; \
		tr -d '\000' < $(OUTPUT_DIR)/easyenclave.cmdline.raw \
			> $(OUTPUT_DIR)/easyenclave.cmdline; \
		rm -f $(OUTPUT_DIR)/easyenclave.cmdline.raw; \
		echo "Kernel cmdline: $$(cat $(OUTPUT_DIR)/easyenclave.cmdline)"; \
	else \
		echo "Error: no UKI (.efi) found after build"; \
		echo "Available artifacts:"; \
		ls -la easyenclave* 2>/dev/null || echo "  (none)"; \
		exit 1; \
	fi
	@# Copy the full GPT disk image (ESP + root + verity hash partitions).
	@# Use --sparse=never to materialize sparse holes — QEMU needs real data.
	@if [ -f "easyenclave.raw" ]; then \
		cp --sparse=never easyenclave.raw $(OUTPUT_DIR)/easyenclave.root.raw; \
	else \
		echo "Warning: easyenclave.raw not found"; \
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
	rm -f easyenclave easyenclave.raw easyenclave.vmlinuz easyenclave.initrd
	rm -f easyenclave.efi easyenclave.root-*.raw easyenclave.manifest
	mkosi clean 2>/dev/null || true
