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
	@# Extract roothash from verity hash partition and build cmdline
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
		echo "Verity hash file: $$VERITY_HASH ($$(stat -c%s "$$VERITY_HASH") bytes)"; \
		echo "Root data file: $$ROOT_DATA ($$(stat -c%s "$$ROOT_DATA") bytes)"; \
		echo "--- veritysetup dump ---"; \
		veritysetup dump "$$VERITY_HASH" || echo "veritysetup dump FAILED"; \
		echo "--- end dump ---"; \
		SALT=$$(veritysetup dump "$$VERITY_HASH" | grep "Salt:" | awk '{print $$NF}'); \
		ROOTHASH=$$(veritysetup format "$$ROOT_DATA" /tmp/verity-recompute.raw \
			--salt="$$SALT" 2>&1 | grep "Root hash:" | awk '{print $$NF}'); \
		rm -f /tmp/verity-recompute.raw; \
		echo "Roothash: $$ROOTHASH"; \
		if [ -n "$$ROOTHASH" ]; then \
			echo "Verifying verity integrity..."; \
			veritysetup verify "$$ROOT_DATA" "$$VERITY_HASH" "$$ROOTHASH" \
				&& echo "Verity verification: PASSED" \
				|| echo "Verity verification: FAILED (roothash mismatch!)"; \
		fi; \
		echo "Checking rootfs contents..."; \
		debugfs -R "ls -l /usr/lib/" "$$ROOT_DATA" 2>&1 | head -5 || echo "(debugfs not available)"; \
		debugfs -R "stat /usr/lib/os-release" "$$ROOT_DATA" 2>&1 || echo "(debugfs not available)"; \
		debugfs -R "stat /etc/os-release" "$$ROOT_DATA" 2>&1 || echo "(debugfs not available)"; \
		echo "root=/dev/dm-0 roothash=$$ROOTHASH rd.systemd.log_level=debug rd.systemd.log_target=kmsg console=tty0 console=ttyS0,115200" \
			> $(OUTPUT_DIR)/easyenclave.cmdline; \
	else \
		echo "Warning: verity partition files not found"; \
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
