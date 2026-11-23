#!/bin/bash
# x86_64 内核交叉编译（Lima aarch64 客机内；在客机本地 fs 构建，避免 9p 权限/性能问题）
set -euxo pipefail
SRC=/mnt/vmiss/hyos-build
WORK="$HOME/hyos-build-kernel"
mkdir -p "$WORK" "$SRC/build"
cd "$WORK"
if [ ! -f linux-6.12.1.tar.xz ]; then
  if [ -f "$SRC/build/kernel/linux-6.12.1.tar.xz" ]; then
    cp "$SRC/build/kernel/linux-6.12.1.tar.xz" .
  else
    mkdir -p "$SRC/build/kernel"
    curl -fL --retry 3 -o "$SRC/build/kernel/linux-6.12.1.tar.xz" https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.1.tar.xz
    cp "$SRC/build/kernel/linux-6.12.1.tar.xz" .
  fi
fi
rm -rf linux-6.12.1
tar xf linux-6.12.1.tar.xz --no-same-owner --no-same-permissions
cd linux-6.12.1
export ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu-
make defconfig
scripts/config --file .config \
  -d MODULES \
  -e ATA -e ATA_PIIX -e SCSI -e BLK_DEV_SD \
  -e E1000 -e ETHERNET -e NET_VENDOR_INTEL -e NETDEVICES \
  -e DEVTMPFS -e DEVTMPFS_MOUNT \
  -e SERIAL_8250 -e SERIAL_8250_CONSOLE \
  -e INET -e PACKET -e BINFMT_ELF \
  -e TMPFS -d WERROR
make olddefconfig
make -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "$SRC/build/vmlinuz"
echo KERNEL_BUILD_OK
