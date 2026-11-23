#!/usr/bin/env python3
"""读取 SELinux 二进制策略版本号（偏移 16）；可选第二参数用于改写。"""
import struct, sys

MAGIC = 0xF97CFF8C
path = sys.argv[1]
with open(path, "rb") as f:
    head = f.read(20)
if struct.unpack("<I", head[0:4])[0] != MAGIC:
    print("ERR_NOT_POLICY", file=sys.stderr)
    sys.exit(2)
version = struct.unpack("<I", head[16:20])[0]
if len(sys.argv) > 2:
    new = int(sys.argv[2])
    with open(path, "r+b") as f:
        f.seek(16)
        f.write(struct.pack("<I", new))
    print("SET %d -> %d" % (version, new))
else:
    print(version)