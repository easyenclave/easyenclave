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
	chmod +x mkosi.postinst.chroot mkosi.finalize mkinitrd.sh mkimage.sh assemble-disk.sh lib/mkesp.sh lib/mkroot.sh
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
	# 3a. Build the per-strategy root partition payload. ext4-label
	#     produces rootfs.img; dm-verity-squashfs produces
	#     rootfs.squashfs + rootfs.verity + roothash.txt. Done HERE
	#     (before cmdline assembly + ukify) so the verity roothash can
	#     be folded into the cmdline that the UKI embeds — that's how
	#     the rootfs ends up under attestation measurement.
	sudo bash lib/mkroot.sh $$(. $(PROFILE); echo $$TARGET_ROOT_STRATEGY) $(ROOTFS_DIR) $(OUTPUT_DIR)
	# 3b. Per-target kernel cmdline. For dm-verity-squashfs we append
	#     the systemd verity entries plus roothash=<hex>; for ext4-label
	#     the cmdline is the profile's TARGET_CMDLINE verbatim (so the
	#     existing `root=LABEL=root` story stays untouched).
	. $(PROFILE); \
	cmdline=$$TARGET_CMDLINE; \
	if [ "$$TARGET_ROOT_STRATEGY" = "dm-verity-squashfs" ]; then \
		ROOTHASH=$$(cat $(OUTPUT_DIR)/roothash.txt); \
		cmdline="$$cmdline systemd.verity_root_data=PARTLABEL=root systemd.verity_root_hash=PARTLABEL=verity roothash=$$ROOTHASH"; \
	fi; \
	echo "$$cmdline" > $(OUTPUT_DIR)/easyenclave.cmdline; \
	echo "cmdline: $$cmdline"
	# 4-5. Kernel + initrd. Two modes:
	#   - host kernel (default): copy /boot/vmlinuz-$(uname -r), build
	#     initrd against /lib/modules/$(uname -r) on the build host.
	#   - packaged kernel (TARGET_USE_PACKAGED_KERNEL=yes): the rootfs
	#     contains its own kernel package (e.g. linux-generic-hwe-24.04
	#     for llm-cuda); resolve KVER from $(ROOTFS_DIR)/lib/modules/,
	#     copy the kernel from the rootfs, and point mkinitrd.sh at the
	#     rootfs module tree via EE_MOD_SRC. Lets DKMS-built drivers
	#     (e.g. nvidia-driver-*) target the same kernel that ends up in
	#     the UKI and decouples the rootfs hash from the build host.
	. $(PROFILE); \
	if [ "$${TARGET_USE_PACKAGED_KERNEL:-no}" = "yes" ]; then \
		KVER_PKG=$$(ls $(ROOTFS_DIR)/lib/modules/ 2>/dev/null | head -1); \
		[ -n "$$KVER_PKG" ] || { echo "FATAL: TARGET_USE_PACKAGED_KERNEL=yes but no kernel modules under $(ROOTFS_DIR)/lib/modules/"; exit 1; }; \
		[ -f $(ROOTFS_DIR)/boot/vmlinuz-$$KVER_PKG ] || { echo "FATAL: no kernel image at $(ROOTFS_DIR)/boot/vmlinuz-$$KVER_PKG"; exit 1; }; \
		echo "Using packaged kernel from rootfs: $$KVER_PKG"; \
		sudo EE_MOD_SRC=$(ROOTFS_DIR)/lib/modules/$$KVER_PKG bash mkinitrd.sh $(OUTPUT_DIR)/easyenclave.initrd $$KVER_PKG $(PROFILE); \
		sudo cp $(ROOTFS_DIR)/boot/vmlinuz-$$KVER_PKG $(OUTPUT_DIR)/easyenclave.vmlinuz; \
	else \
		echo "Using host kernel: $(KVER)"; \
		sudo bash mkinitrd.sh $(OUTPUT_DIR)/easyenclave.initrd $(KVER) $(PROFILE); \
		sudo cp /boot/vmlinuz-$(KVER) $(OUTPUT_DIR)/easyenclave.vmlinuz; \
	fi
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
