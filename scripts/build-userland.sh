#!/bin/bash
# 用户态构建：hyinit/stubapp 一律显式 --target x86_64-unknown-linux-gnu 静态编译
# （aarch64 Lima 客机交叉编译；x86_64 CI 原生机显式 target——runner 上不带 --target 的
#   原生 cargo 构建存在 proc-macro 单元调度异常，显式 target 实测正常）；mkdisk 为构建机
# 本地工具：aarch64 客机原生构建，x86_64 机与 hyinit 同 target 构建
set -euxo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
REPO=${REPO:-/mnt/vmiss/hyos-build}
B=$REPO/build
mkdir -p $B
cd $REPO
node scripts/gen-hykeys.mjs
find verifier/src grub/src -name "*.rs" -exec touch {} + 2>/dev/null || true
touch verifier/src/genkeys.rs 2>/dev/null || true

TGT=x86_64-unknown-linux-gnu
rustup target add $TGT 2>&1 | tail -1
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-x86_64-linux-gnu-gcc}
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static"
TGTDIR="target/$TGT/release"

cd verifier && cargo build --release --target $TGT
file $REPO/verifier/$TGTDIR/hyinit | grep -i static || echo "WARN: hyinit not static"
cp $REPO/verifier/$TGTDIR/hyinit $B/hyinit

cd $REPO/tools/stubapp && cargo build --release --target $TGT
cp $REPO/tools/stubapp/$TGTDIR/stubapp $B/hello

HOST_TRIPLE=$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2}')
if [ "$HOST_TRIPLE" = "$TGT" ]; then
  cd $REPO/tools/mkdisk && cargo build --release --target $TGT
  cp $REPO/tools/mkdisk/$TGTDIR/mkdisk $B/mkdisk
else
  cd $REPO/tools/mkdisk && cargo build --release
  cp $REPO/tools/mkdisk/target/release/mkdisk $B/mkdisk
fi

file $B/hyinit $B/hello $B/mkdisk
echo USERLAND_OK
