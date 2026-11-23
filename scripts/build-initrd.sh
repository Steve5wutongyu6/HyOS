#!/bin/bash
# initramfs 组装：/init(=hyinit) /supervisor(=hyinit) /system.manifest(.sig) + SELinux 策略
set -euxo pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
R=$B/initrd-root
rm -rf $R
mkdir -p $R/bin $R/proc $R/sys $R/dev $R/apps $R/run $R/etc/selinux $R/etc/hysteria
cp $B/hyinit $R/init
cp $B/hyinit $R/supervisor
chmod 755 $R/init $R/supervisor
cp $B/manifests/system.manifest $R/system.manifest
cp $B/manifests/system.manifest.sig $R/system.manifest.sig
# SELinux 单块策略（缺失时先按需构建）
if [ ! -s $B/selinux/policy ]; then bash $REPO/selinux/build-policy.sh >/dev/null; fi
cp $B/selinux/policy $R/etc/selinux/policy
cd $R
find . | cpio -o -H newc --quiet | gzip -1 > $B/initrd.img
ls -la $B/initrd.img
echo INITRD_OK