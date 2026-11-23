#!/bin/bash
# x86_64 内核交叉编译（Lima aarch64 客机内；客机本地 fs 构建）
# 注意：内核 >= 6.13 才原生支持 SELinux 策略 v34（6.12 上限为 v33）
set -euxo pipefail
KVER=${KVER:-6.14.11}
SRC=/mnt/vmiss/hyos-build
WORK="$HOME/hyos-build-kernel"
mkdir -p "$WORK" "$SRC/build" "$SRC/build/kernel"
cd "$WORK"
if [ ! -f "linux-$KVER.tar.xz" ]; then
  if [ -f "$SRC/build/kernel/linux-$KVER.tar.xz" ]; then
    cp "$SRC/build/kernel/linux-$KVER.tar.xz" .
  else
    curl -fL --retry 3 -o "$SRC/build/kernel/linux-$KVER.tar.xz" "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz"
    cp "$SRC/build/kernel/linux-$KVER.tar.xz" .
  fi
fi
rm -rf "linux-$KVER"
tar xf "linux-$KVER.tar.xz" --no-same-owner --no-same-permissions
cd "linux-$KVER"
export ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu-
make defconfig
scripts/config --file .config \
  -d MODULES \
  -e ATA -e ATA_PIIX -e SCSI -e BLK_DEV_SD \
  -e E1000 -e ETHERNET -e NET_VENDOR_INTEL -e NETDEVICES \
  -e DEVTMPFS -e DEVTMPFS_MOUNT \
  -e SERIAL_8250 -e SERIAL_8250_CONSOLE \
  -e INET -e PACKET -e BINFMT_ELF \
  -e TMPFS -d WERROR \
  -e SECURITY -e SECURITY_SELINUX -e SECURITY_SELINUX_BOOTPARAM \
  --set-str LSM "landlock,lockdown,yama,loadpin,safesetid,selinux,bpf"
make olddefconfig
make -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "$SRC/build/vmlinuz"
echo "KERNEL_BUILD_OK $KVER"