#!/bin/bash
# 可复用：嵌入 + 引导测试（embed_and_boot <core> <label>；块列表 ceil，完整写入）
ST=$HOME/hyos-build-grub/grub-2.12
IMG=/tmp/t.img
LOG=/tmp/t.log

embed_and_boot() {
  local core=$1 name=$2
  sudo losetup -D 2>/dev/null
  rm -f $IMG $LOG
  dd if=/dev/zero of=$IMG bs=1M count=8 status=none
  echo "type=83" | sudo sfdisk $IMG >/dev/null 2>&1
  dd if=$ST/grub-core/boot.img of=$IMG bs=446 count=1 conv=notrunc status=none
  python3 - "$core" <<'PYEOF'
import struct, sys
core = bytearray(open(sys.argv[1], "rb").read())
if len(core) % 512:
    core += b"\x00" * (512 - len(core) % 512)
n = (len(core)) // 512
core[0x1F4:0x1FC] = struct.pack("<Q", 2)
core[0x1FC:0x1FE] = struct.pack("<H", n - 1)
core[0x1FE:0x200] = struct.pack("<H", 0x0820)
img = open("/tmp/t.img", "r+b")
img.seek(512)
img.write(core)
img.close()
print("EMBED sectors=%d bytes=%d" % (n, len(core)))
PYEOF
  rm -f $LOG
  timeout 15 qemu-system-x86_64 -machine pc -m 512 -display none -serial file:$LOG \
    -drive file=$IMG,format=raw,if=ide -no-reboot 2>/dev/null
  echo "$name => [$(head -c 150 $LOG 2>/dev/null | tr -d "\n" | tr -d "\r")]"
}
