# EasyEnclave VM Image Build
#
# Builds a bootable TDX VM image with easyenclave as PID 1.
# Boots via Unified Kernel Image (UKI): kernel + initrd + cmdline in one
# EFI binary. No bootloader. One file = one measurement.
#
# Workflow:
#   1. mkosi Format=directory → produces populated rootfs tree
#   2. mkfs.ext4 -d → packs the tree into an ext4 image
#   3. mkinitrd.sh → builds minimal initrd with nvme+dm-verity modules
#   4. ukify → builds UKI from host kernel + initrd + cmdline
#   5. assemble-disk.sh → GPT disk with ESP (UKI) + root partitions
#
# We use Format=directory because Format=disk has a bug where the split
# partition artifacts come out empty. Assembling the disk manually also
# gives us full control over partition layout.
#
# TODO: add dm-verity back once base boot works.
#
# Prerequisites: mkosi 25+, cargo, busybox-static, e2fsprogs, mtools,
#   systemd-boot-efi (for the EFI stub), systemd-ukify
# Usage:
#   make build    - Build the image
#   make clean    - Remove build artifacts

REPO_ROOT := ..
EXTRA_BIN := mkosi.extra/usr/local/bin
OUTPUT_DIR := output
EE_BIN := $(REPO_ROOT)/target/release/easyenclave
EFI_STUB := /usr/lib/systemd/boot/efi/linuxx64.efi.stub
KVER ?= $(shell uname -r)

.PHONY: build clean

build: $(EXTRA_BIN)/easyenclave
	chmod +x mkosi.postinst.chroot mkosi.finalize mkinitrd.sh assemble-disk.sh
	mkdir -p $(OUTPUT_DIR)
	# 1. Build rootfs as a directory (Format=disk has a bug where the split
	#    partition artifact is empty — directory output is populated correctly).
	sudo mkosi build --force --format directory
	sudo du -sh easyenclave/
	# 2. Pack the directory into a plain ext4 image.
	#    256MB is enough for ~81MB of content with room for logs/state.
	rm -f $(OUTPUT_DIR)/rootfs.img
	dd if=/dev/zero of=$(OUTPUT_DIR)/rootfs.img bs=1M count=256 status=none
	sudo mkfs.ext4 -F -L root -d easyenclave $(OUTPUT_DIR)/rootfs.img 2>&1 | tail -3
	# 3. Kernel cmdline: resolve root by label so the same UKI works on
	#    GCP (nvme0n1p2) and local libvirt (vda2) — the initrd calls
	#    `findfs LABEL=root` to get the device path at runtime.
	echo "root=LABEL=root console=ttyS0,115200" > $(OUTPUT_DIR)/easyenclave.cmdline
	# 4. Minimal initrd (nvme + dm-verity + deps via modprobe)
	sudo bash mkinitrd.sh $(OUTPUT_DIR)/easyenclave.initrd $(KVER)
	# 5. Host kernel
	sudo cp /boot/vmlinuz-$(KVER) $(OUTPUT_DIR)/easyenclave.vmlinuz
	sudo chmod 644 $(OUTPUT_DIR)/easyenclave.vmlinuz
	# 6. Build UKI
	ukify build \
		--stub $(EFI_STUB) \
		--linux $(OUTPUT_DIR)/easyenclave.vmlinuz \
		--initrd $(OUTPUT_DIR)/easyenclave.initrd \
		--cmdline @$(OUTPUT_DIR)/easyenclave.cmdline \
		--output $(OUTPUT_DIR)/easyenclave.efi
	# 7. Assemble bootable GPT disk: ESP (with UKI) + rootfs
	bash assemble-disk.sh $(OUTPUT_DIR)
	# 8. Convert raw disk to compressed qcow2 for QEMU/libvirt users.
	#    qcow2 is the standard QEMU format: smaller on disk, supports
	#    snapshots, copy-on-write, etc.
	qemu-img convert -f raw -O qcow2 -c \
		$(OUTPUT_DIR)/easyenclave.root.raw \
		$(OUTPUT_DIR)/easyenclave.qcow2
	@echo ""
	@echo "Build complete:"
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
	sudo rm -rf $(OUTPUT_DIR) easyenclave easyenclave.raw easyenclave.root-*.raw easyenclave.vmlinuz easyenclave.initrd easyenclave.efi easyenclave.manifest easyenclave-image.tar.gz disk.raw
	sudo mkosi clean 2>/dev/null || true
