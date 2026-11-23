#!/bin/bash
# 用户态构建：hyinit/stubapp 编译为 x86_64 静态二进制；mkdisk 本地构建
# Lima 客机(aarch64)交叉编译 --target x86_64；x86_64 原生机(CI runner)不传 --target，
# 避免 proc-macro 交叉语义问题（curve25519-dalek-derive 等）
set -euxo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
REPO=${REPO:-/mnt/vmiss/hyos-build}
B=$REPO/build
mkdir -p $B
cd $REPO
node scripts/gen-hykeys.mjs
find verifier/src grub/src -name "*.rs" -exec touch {} + 2>/dev/null || true
touch verifier/src/genkeys.rs 2>/dev/null || true

HOST_TRIPLE=$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2}')
TGT=x86_64-unknown-linux-gnu
if [ "$HOST_TRIPLE" != "$TGT" ]; then
  rustup target add $TGT 2>&1 | tail -1
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static"
  TGTDIR="target/$TGT/release"
  TFLAG="--target $TGT"
else
  export RUSTFLAGS="-C target-feature=+crt-static"
  TGTDIR="target/release"
  TFLAG=""
fi

cd verifier && cargo build --release $TFLAG
file $REPO/verifier/$TGTDIR/hyinit | grep -i static || echo "WARN: hyinit not static"
cp $REPO/verifier/$TGTDIR/hyinit $B/hyinit

cd $REPO/tools/stubapp && cargo build --release $TFLAG
cp $REPO/tools/stubapp/$TGTDIR/stubapp $B/hello

cd $REPO/tools/mkdisk && cargo build --release
cp $REPO/tools/mkdisk/target/release/mkdisk $B/mkdisk

file $B/hyinit $B/hello $B/mkdisk
echo USERLAND_OK
