#!/bin/bash
# 生成"无 test"与"有 test"两个未压缩 core，diff 内核头
set -o pipefail
ST=$HOME/hyos-build-grub/grub-2.12
GC=$ST/grub-core
$ST/grub-mkimage -C none -O i386-pc -o /tmp/hdr-notest.img -d $GC -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo
$ST/grub-mkimage -C none -O i386-pc -o /tmp/hdr-withtest.img -d $GC -c /tmp/min-embed.cfg -p "(hd0,msdos1)/boot/grub" biosdisk part_msdos fat configfile terminal serial halt echo test
python3 - <<'PYEOF'
import struct
a = open("/tmp/hdr-notest.img","rb").read()
b = open("/tmp/hdr-withtest.img","rb").read()
print("notest:", len(a), "withtest:", len(b))
# 内核头在 diskboot 之后: 文件偏移 0x200 起
for off in range(0x200, 0x280, 16):
    da = a[off:off+16].hex()
    db = b[off:off+16].hex()
    mark = "  <<< DIFF" if da != db else ""
    print(hex(off), da, mark)
    if mark:
        print("      ", db)
# offsets.h 已知字段（i386-pc）：kernel_base 在 0x8200 运行地址 = 文件 0x200
# GRUB_KERNEL_I386_PC_TOTAL_MODULE_SIZE / UNCOMPRESSED_SIZE 等字段逐个打印
def u32(buf, off): return struct.unpack("<I", buf[off:off+4])[0]
for name, fo in [("field@0x208", 0x208), ("field@0x20c", 0x20c), ("field@0x210", 0x210), ("field@0x214", 0x214), ("field@0x218", 0x218)]:
    print(name, "notest=%#x withtest=%#x" % (u32(a, fo), u32(b, fo)))
PYEOF
'