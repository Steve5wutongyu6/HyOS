#!/bin/bash
# x86_64 内核交叉编译（Lima aarch64 客机内；客机本地 fs 构建）
# 最小化内核：allnoconfig 基座 + scripts/kernel-minimal.config 白名单
# 仅保留：串口控制台、SELinux、IPv4+e1000/virtio、IDE/SCSI/virtio-blk、ACPI 断电、
#         iptables DNAT(端口跳跃)。不编入 HID/USB/无线/蓝牙/声卡/DRM/磁盘文件系统。
# 注：6.14 内核 SELinux 策略上限为 v33(POLICYDB_VERSION_COND_XPERMS)，
#     build-policy.sh 会把编译出的 v34 自动对齐改写为 v33。
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
    # 多镜像轮换 + 超时（140MB 大包；cdn.kernel.org 异常时切 mirror.kernel.org）
    dl_ok=0
    for u in \
      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz" \
      "https://mirrors.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz"; do
      echo "KERNEL dl: $u"
      if curl -fL --connect-timeout 15 --max-time 900 --retry 2 -sS -o "$SRC/build/kernel/linux-$KVER.tar.xz" "$u" && [ -s "$SRC/build/kernel/linux-$KVER.tar.xz" ]; then
        dl_ok=1; break
      fi
      echo "KERNEL dl failed: $u"
    done
    [ "$dl_ok" = 1 ] || { echo "ERROR: 内核源码包所有镜像均失败"; exit 1; }
    cp "$SRC/build/kernel/linux-$KVER.tar.xz" .
  fi
fi
rm -rf "linux-$KVER"
tar xf "linux-$KVER.tar.xz" --no-same-owner --no-same-permissions
cd "linux-$KVER"
export ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu-

# ---- 最小化配置：allnoconfig + 白名单合并 + 依赖解析 ----
make allnoconfig
./scripts/kconfig/merge_config.sh -m .config "$SRC/scripts/kernel-minimal.config"
make olddefconfig

# ---- 关键选项断言（依赖缺失会被 olddefconfig 静默丢弃，必须显式校验）----
MISSING=""
for opt in 64BIT PRINTK FUTEX EPOLL POSIX_TIMERS ADVISE_SYSCALLS MEMBARRIER MULTIUSER \
  BINFMT_ELF PROC_FS PROC_SYSCTL SYSFS TMPFS DEVTMPFS DEVTMPFS_MOUNT TTY SERIAL_8250 SERIAL_8250_CONSOLE \
  SMP X86_MPPARSE X86_IO_APIC PCI PCI_MSI ACPI DMI HZ_250 RELOCATABLE RANDOMIZE_BASE \
  STACKPROTECTOR_STRONG HYPERVISOR_GUEST KVM_GUEST PARAVIRT AUDIT SECURITY_NETWORK \
  BLOCK BLK_DEV_INITRD RD_GZIP KERNEL_GZIP SCSI BLK_DEV_SD ATA ATA_PIIX SATA_AHCI \
  NET INET UNIX NETDEVICES ETHERNET NET_VENDOR_INTEL E1000 \
  VIRTIO VIRTIO_PCI VIRTIO_BLK VIRTIO_NET HW_RANDOM HW_RANDOM_VIRTIO \
  NETFILTER NF_CONNTRACK NF_NAT IP_NF_IPTABLES IP_NF_FILTER IP_NF_NAT \
  RTC_CLASS RTC_HCTOSYS RTC_DRV_CMOS \
  SECURITY SECURITY_SELINUX; do
  grep -q "^CONFIG_$opt=y" .config || MISSING="$MISSING $opt"
done
[ -z "$MISSING" ] || { echo "KERNEL_CONFIG_MISSING:$MISSING"; grep -E "^CONFIG_(LSM|NR_CPUS)=" .config; exit 1; }
grep -q '^CONFIG_MODULES=y' .config && { echo "MODULES must be off"; exit 1; }
# ---- 反向断言：这些大块组件被 default y 静默回拉时立即失败 ----
# 含 32 位指令集兼容（平台契约：HyOS 仅支持 x86_64 纯 64 位，不允许 IA32/x32/COMPAT 回拉）
PRESENT=""
for opt in VT INPUT TOUCHSCREEN PPS WIRELESS USB HID SOUND DRM IPV6 USB_SUPPORT \
  IA32_EMULATION COMPAT X86_X32_ABI X86_32; do
  grep -q "^CONFIG_$opt=y" .config && PRESENT="$PRESENT $opt"
done
[ -z "$PRESENT" ] || { echo "KERNEL_CONFIG_UNEXPECTED:$PRESENT（default y 残余，检查 EXPERT 与 unset 行）"; exit 1; }
OPTCOUNT=$(grep -c '=y' .config); LINES=$(wc -l < .config); echo "KERNEL_CONFIG_OK options=$OPTCOUNT lines=$LINES"

NPROC=$(nproc); make -j"$NPROC" bzImage
cp arch/x86/boot/bzImage "$SRC/build/vmlinuz"
ls -la "$SRC/build/vmlinuz"
echo "KERNEL_BUILD_OK $KVER"
