#!/bin/bash
sudo losetup -D 2>/dev/null
LOOP=$(sudo losetup -Pf --show /mnt/vmiss/hyos-build/build/deploy-test.img)
mdir -i ${LOOP}p1 ::/boot/grub 2>/dev/null | head -8
echo ===CFG_IN_FAT===
mtype -i ${LOOP}p1 ::/boot/grub/grub.cfg 2>/dev/null
sudo losetup -d $LOOP
