#!/bin/bash
# 全景诊断：SeaBIOS debugcon + int log + serial
CORE=$1
sudo losetup -D 2>/dev/null
rm -f /tmp/t.img /tmp/t.log /tmp/bios3.log /tmp/qlog2
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
timeout 20 qemu-system-x86_64 -machine pc -m 512 -display none -serial file:/tmp/t.log \
  -debugcon file:/tmp/bios3.log -global isa-debugcon.iobase=0x402 \
  -d int -D /tmp/qlog2 -drive file=/tmp/t.img,format=raw,if=ide -no-reboot >/dev/null 2>&1
echo ===BIOS_TAIL===
tail -8 /tmp/bios3.log 2>/dev/null
echo ===SERIAL===
cat /tmp/t.log 2>/dev/null | head -5
echo ===INT_STATS===
grep -c "check_exception" /tmp/qlog2 2>/dev/null
grep -m1 -B2 -A18 "v=06" /tmp/qlog2 2>/dev/null | head -24
grep -m1 -A18 "v=0d" /tmp/qlog2 2>/dev/null | head -22
