#!/bin/bash
# 挂死时 dump 0x8200 起的内存，与 core 文件对比
CORE=$1
sudo losetup -D 2>/dev/null
rm -f /tmp/t.img /tmp/mon2.sock
dd if=/dev/zero of=/tmp/t.img bs=1M count=8 status=none
echo "type=83" | sudo sfdisk /tmp/t.img >/dev/null 2>&1
dd if=$ST/grub-core/boot.img of=/tmp/t.img bs=446 count=1 conv=notrunc status=none
python3 - "$CORE" <<'PYEOF'
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
(timeout 25 qemu-system-x86_64 -machine pc -m 512 -display none \
  -monitor unix:/tmp/mon2.sock,server,nowait -drive file=/tmp/t.img,format=raw,if=ide -no-reboot >/dev/null 2>&1 &)
sleep 6
echo "xp /48bx 0x8200" | timeout 5 socat - UNIX-CONNECT:/tmp/mon2.sock 2>/dev/null | tail -8
echo "info registers" | timeout 5 socat - UNIX-CONNECT:/tmp/mon2.sock 2>/dev/null | grep -E "^EIP|^EAX|CS ="
sleep 20
