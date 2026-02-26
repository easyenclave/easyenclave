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
	@# Git does not preserve 0600 for non-executable files; enforce secure key perms.
	@if [ -f "mkosi.key" ]; then chmod 600 mkosi.key; fi
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
	@# Extract roothash from GPT partition UUIDs.
	@# systemd-repart derives partition UUIDs from the roothash per the
	@# Discoverable Partitions Specification: data UUID = first 128 bits,
	@# verity hash UUID = last 128 bits.  We reconstruct the full 256-bit
	@# roothash by concatenating them.
	@# (We cannot use veritysetup dump because mkosi's systemd-repart
	@#  creates verity without a superblock that older veritysetup can read.)
	@if [ -f "easyenclave.raw" ]; then \
		DATA_UUID=$$(sfdisk -d easyenclave.raw \
			| grep -i "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" \
			| sed 's/.*uuid=\([^, ]*\).*/\1/' | tr -d '-' | tr '[:upper:]' '[:lower:]'); \
		HASH_UUID=$$(sfdisk -d easyenclave.raw \
			| grep -i "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5" \
			| sed 's/.*uuid=\([^, ]*\).*/\1/' | tr -d '-' | tr '[:upper:]' '[:lower:]'); \
		ROOTHASH="$${DATA_UUID}$${HASH_UUID}"; \
		if [ $${#ROOTHASH} -ne 64 ]; then \
			echo "Error: could not extract roothash from GPT (got '$$ROOTHASH')"; \
			echo "  data UUID: $$DATA_UUID"; \
			echo "  hash UUID: $$HASH_UUID"; \
			sfdisk -d easyenclave.raw; \
			exit 1; \
		fi; \
		echo "Roothash: $$ROOTHASH"; \
		echo "roothash=$$ROOTHASH systemd.verity_root_data=/dev/vda1 systemd.verity_root_hash=/dev/vda2 fsck.mode=skip console=tty0 console=ttyS0,115200" \
			> $(OUTPUT_DIR)/easyenclave.cmdline; \
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
