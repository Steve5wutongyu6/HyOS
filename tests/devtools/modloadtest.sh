#!/bin/bash
# hyverify 模块加载 + 命令注册 + 自校验 + 槽解析 全链路单测（测试盘无有效槽 → 期望 DESTROY）
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
GC=$ST/grub-core
source /mnt/vmiss/hyos-build/tests/embedboot.sh

printf "serial --unit=0 --speed=115200\nterminal_output --append serial\necho START-MARK\nhyverify_boot\necho AFTER-HYVERIFY\nhalt\n" > /tmp/hy-cfg.cfg
$ST/grub-mkimage -O i386-pc -o /tmp/hytest.img -d $GC -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat disk configfile terminal serial halt echo hyverify && echo MKIMG_OK

sudo losetup -D 2>/dev/null
rm -f /tmp/t.img /tmp/t.log
dd if=/dev/zero of=/tmp/t.img bs=1M count=8 status=none
echo "type=83" | sudo sfdisk /tmp/t.img >/dev/null 2>&1
dd if=$GC/boot.img of=/tmp/t.img bs=446 count=1 conv=notrunc status=none
python3 - /tmp/hytest.img <<'PYEOF'
import struct, sys
core = bytearray(open(sys.argv[1], "rb").read())
if len(core) % 512:
    core += b"\x00" * (512 - len(core) % 512)
n = len(core) // 512
core[0x1F4:0x1FC] = struct.pack("<Q", 2)
core[0x1FC:0x1FE] = struct.pack("<H", n - 1)
core[0x1FE:0x200] = struct.pack("<H", 0x0820)
img = open("/tmp/t.img", "r+b")
img.seek(512)
img.write(core)
img.close()
print("EMBED n=%d" % n)
PYEOF
# 把 grub.cfg 放进一个 FAT p1（模拟 deploy 布局：2048 起的 FAT）
rm -f /tmp/p1.img; mformat -i /tmp/p1.img -C -t 128 -h 4 -s 4 :: >/dev/null 2>&1 || python3 -c "open('/tmp/p1.img','wb').write(b'\x00'*(2048*512))"
mformat -i /tmp/p1.img -C -t 128 -h 4 -s 4 :: >/dev/null 2>&1
mmd -i /tmp/p1.img ::/boot >/dev/null 2>&1; mmd -i /tmp/p1.img ::/boot/grub >/dev/null 2>&1
mcopy -i /tmp/p1.img /tmp/hy-cfg.cfg ::/boot/grub/grub.cfg >/dev/null 2>&1
dd if=/tmp/p1.img of=/tmp/t.img bs=512 seek=2048 conv=notrunc status=none
rm -f /tmp/t.log
timeout 30 qemu-system-x86_64 -machine pc -m 512 -display none -serial file:/tmp/t.log -drive file=/tmp/t.img,format=raw,if=ide -no-reboot 2>/dev/null
echo ===OUT===
cat /tmp/t.log
