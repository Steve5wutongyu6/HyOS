#!/bin/bash
# initramfs 组装：/init(=hyinit) /supervisor(=hyinit) /system.manifest(.sig)
set -euxo pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
R=$B/initrd-root
rm -rf $R
mkdir -p $R/bin $R/proc $R/sys $R/dev $R/apps
cp $B/hyinit $R/init
cp $B/hyinit $R/supervisor
chmod 755 $R/init $R/supervisor
cp $B/manifests/system.manifest $R/system.manifest
cp $B/manifests/system.manifest.sig $R/system.manifest.sig
cd $R
find . | cpio -o -H newc --quiet | gzip -1 > $B/initrd.img
ls -la $B/initrd.img
echo INITRD_OK
