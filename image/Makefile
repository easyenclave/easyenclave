# EasyEnclave VM Image Build
#
# Per-target image builds. Each target is a directory under targets/
# supplying a profile.env that drives modules, cmdline, root strategy,
# and output format.
#
# Boot chain (all targets):
#   UEFI firmware → ESP/EFI/BOOT/BOOTX64.EFI (UKI) → kernel + initrd
#                 → our init script → switch_root → easyenclave (PID 1)
#
# Workflow:
#   1. cargo build --release                     (shared across targets)
#   2. mkosi Format=directory → rootfs tree      (shared)
#   3. copy host kernel                          (shared)
#   4. mkinitrd.sh <...> <profile>               (per-target modules + init template)
#   5. ukify → UKI                               (per-target cmdline)
#   6. mkimage.sh <profile>                      (per-target format: disk or iso)
#
# Prerequisites: mkosi 25+, cargo, busybox-static, e2fsprogs, mtools,
#   systemd-boot-efi (for the EFI stub), systemd-ukify, qemu-utils (qcow2)
#
# Usage:
#   make build                          # default TARGET=gcp
#   make build TARGET=azure             # Azure VHD for TDX CVMs
#   make build TARGET=local-tdx-qcow2   # libvirt backing-file qcow2
#   make clean                          # clean just the current TARGET's output
#   make clean-all                      # clean output/ entirely

REPO_ROOT := ..
EXTRA_BIN := mkosi.extra/usr/local/bin
EE_BIN := $(REPO_ROOT)/target/release/easyenclave
EFI_STUB := /usr/lib/systemd/boot/efi/linuxx64.efi.stub
KVER ?= $(shell uname -r)

TARGET ?= gcp
OUTPUT_DIR := output/$(TARGET)
PROFILE := targets/$(TARGET)/profile.env
ROOTFS_DIR := $(OUTPUT_DIR)/easyenclave.rootfs

.PHONY: build clean clean-all

build: $(EXTRA_BIN)/easyenclave
	@[ -f $(PROFILE) ] || { echo "Unknown TARGET=$(TARGET). Available: $$(ls targets/ 2>/dev/null)"; exit 1; }
	chmod +x mkosi.postinst.chroot mkosi.finalize mkinitrd.sh mkimage.sh assemble-disk.sh lib/mkesp.sh
	mkdir -p $(OUTPUT_DIR)
	@echo ""
	@echo "=== Building target: $(TARGET) ==="
	@cat $(PROFILE) | sed 's/^/  /'
	@echo ""
	# 1. Build rootfs as a directory (Format=disk has a bug where the split
	#    partition artifact is empty — directory output is populated correctly).
	#    If the profile declares TARGET_MKOSI_PROFILE, pass it through so
	#    mkosi.profiles/<name>/ overlays apply.
	sudo rm -rf easyenclave
	. $(PROFILE); sudo mkosi build --force --format directory $${TARGET_MKOSI_PROFILE:+--profile=$$TARGET_MKOSI_PROFILE}
	sudo du -sh easyenclave/
	# 2. Move the populated rootfs under the target's output dir so concurrent
	#    target builds don't step on each other.
	sudo rm -rf $(ROOTFS_DIR)
	sudo mv easyenclave $(ROOTFS_DIR)
	# 3. Per-target kernel cmdline.
	. $(PROFILE); echo "$$TARGET_CMDLINE" > $(OUTPUT_DIR)/easyenclave.cmdline
	# 4. Per-target initrd (profile-driven modules + init template).
	sudo bash mkinitrd.sh $(OUTPUT_DIR)/easyenclave.initrd $(KVER) $(PROFILE)
	# 5. Host kernel.
	sudo cp /boot/vmlinuz-$(KVER) $(OUTPUT_DIR)/easyenclave.vmlinuz
	sudo chmod 644 $(OUTPUT_DIR)/easyenclave.vmlinuz
	# 6. Build UKI.
	ukify build \
		--stub $(EFI_STUB) \
		--linux $(OUTPUT_DIR)/easyenclave.vmlinuz \
		--initrd $(OUTPUT_DIR)/easyenclave.initrd \
		--cmdline @$(OUTPUT_DIR)/easyenclave.cmdline \
		--output $(OUTPUT_DIR)/easyenclave.efi
	# 7. Per-target final image (GPT disk + derived formats).
	bash mkimage.sh $(PROFILE) $(OUTPUT_DIR)
	@echo ""
	@echo "=== Build complete ($(TARGET)) ==="
	@ls -lh $(OUTPUT_DIR)/ 2>/dev/null || true

$(EE_BIN):
	cargo build --manifest-path $(REPO_ROOT)/Cargo.toml --release

$(EXTRA_BIN)/easyenclave: $(EE_BIN)
	mkdir -p $(EXTRA_BIN)
	cp $(EE_BIN) $(EXTRA_BIN)/easyenclave
	chmod 0755 $(EXTRA_BIN)/easyenclave

clean:
	# Only remove generated staging binaries inside mkosi.extra — the
	# rest of mkosi.extra (e.g. usr/share/udhcpc/default.script) is
	# tracked content and must survive `make clean`.
	sudo rm -f $(EXTRA_BIN)/easyenclave
	sudo rm -rf $(OUTPUT_DIR) easyenclave
	sudo mkosi clean 2>/dev/null || true

clean-all:
	sudo rm -f $(EXTRA_BIN)/easyenclave
	sudo rm -rf output easyenclave
	sudo mkosi clean 2>/dev/null || true
