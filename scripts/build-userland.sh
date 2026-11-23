#!/bin/bash
# 用户态构建（Lima 客机内）：hyinit/stubapp 交叉编译为 x86_64 静态二进制；mkdisk 客机本地构建
set -euxo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
mkdir -p $B
cd $REPO
node scripts/gen-hykeys.mjs
find verifier/src grub/src -name "*.rs" -exec touch {} + 2>/dev/null || true
touch verifier/src/genkeys.rs 2>/dev/null || true

TGT=x86_64-unknown-linux-gnu
rustup target add $TGT 2>&1 | tail -1
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static"

cd verifier && cargo build --release --target $TGT
file $REPO/verifier/target/$TGT/release/hyinit | grep -i static || echo "WARN: hyinit not static"
cp $REPO/verifier/target/$TGT/release/hyinit $B/hyinit

cd $REPO/tools/stubapp && cargo build --release --target $TGT
cp $REPO/tools/stubapp/target/$TGT/release/stubapp $B/hello

cd $REPO/tools/mkdisk && cargo build --release
cp $REPO/tools/mkdisk/target/release/mkdisk $B/mkdisk

file $B/hyinit $B/hello $B/mkdisk
echo USERLAND_OK