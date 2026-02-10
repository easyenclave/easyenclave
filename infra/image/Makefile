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
#   easyenclave.root.raw    - Full GPT disk (root + verity hash partitions, non-sparse)
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
	@for f in easyenclave*.vmlinuz; do \
		[ -f "$$f" ] && cp "$$f" $(OUTPUT_DIR)/easyenclave.vmlinuz && break; \
	done 2>/dev/null || true
	@for f in easyenclave*.initrd; do \
		[ -f "$$f" ] && cp "$$f" $(OUTPUT_DIR)/easyenclave.initrd && break; \
	done 2>/dev/null || true
	@# Copy the full GPT disk image (contains root + verity hash partitions).
	@# Use --sparse=never to materialize sparse holes — QEMU needs real data.
	@if [ -f "easyenclave.raw" ]; then \
		cp --sparse=never easyenclave.raw $(OUTPUT_DIR)/easyenclave.root.raw; \
	fi
	@# Compute roothash from verity data+hash partitions
	@VERITY_HASH=""; \
	for f in easyenclave*verity*.raw; do \
		[ -f "$$f" ] && VERITY_HASH="$$f" && break; \
	done 2>/dev/null; \
	ROOT_DATA=""; \
	for f in easyenclave*.root*.raw; do \
		case "$$f" in *verity*) continue;; esac; \
		[ -f "$$f" ] && ROOT_DATA="$$f" && break; \
	done 2>/dev/null; \
	if [ -n "$$VERITY_HASH" ] && [ -n "$$ROOT_DATA" ]; then \
		SALT=$$(veritysetup dump "$$VERITY_HASH" | grep "Salt:" | awk '{print $$NF}'); \
		ROOTHASH=$$(veritysetup format "$$ROOT_DATA" /tmp/verity-recompute.raw \
			--salt="$$SALT" 2>&1 | grep "Root hash:" | awk '{print $$NF}'); \
		rm -f /tmp/verity-recompute.raw; \
		echo "root=/dev/dm-0 roothash=$$ROOTHASH console=tty0 console=ttyS0,115200" \
			> $(OUTPUT_DIR)/easyenclave.cmdline; \
		echo "Roothash: $$ROOTHASH"; \
	else \
		echo "Warning: verity partition files not found"; \
	fi
	@# Verify rootfs has essential files
	@echo "Verifying rootfs contents..."
	@LOOP=$$(sudo losetup --find --show --partscan $(OUTPUT_DIR)/easyenclave.root.raw 2>/dev/null) && \
	if [ -n "$$LOOP" ]; then \
		sudo mkdir -p /tmp/rootfs-verify && \
		sudo mount -o ro "$${LOOP}p1" /tmp/rootfs-verify 2>/dev/null && \
		echo "Root partition contents:" && \
		ls /tmp/rootfs-verify/ && \
		echo "Init check:" && \
		ls -la /tmp/rootfs-verify/usr/lib/systemd/systemd 2>/dev/null || echo "  /usr/lib/systemd/systemd NOT FOUND" && \
		ls -la /tmp/rootfs-verify/sbin/init 2>/dev/null || echo "  /sbin/init NOT FOUND" && \
		echo "Disk usage:" && \
		du -sh /tmp/rootfs-verify/ 2>/dev/null || true && \
		sudo umount /tmp/rootfs-verify 2>/dev/null; \
		sudo losetup -d "$$LOOP" 2>/dev/null; \
	else \
		echo "Warning: could not set up loop device (skipping rootfs verification)"; \
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
	rm -f easyenclave.root-*.raw easyenclave.manifest
	mkosi clean 2>/dev/null || true
