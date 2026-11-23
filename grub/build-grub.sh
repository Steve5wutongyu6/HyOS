#!/bin/bash
# GRUB 构建集成流程（v2，树内一等公民）：
# 1) 首次解压 tarball 并打集成补丁（extra_deps、core.def 模块、shim、aes.c 适配）
# 2) configure + make（全量，一次）
# 3) 同步最新源码 → make hyverify.mod → 重建 syminfo/moddep → mkimage core.img
set -o pipefail
REPO=/mnt/vmiss/hyos-build
WORK="$HOME/hyos-build-grub"
MODDIR="$REPO/grub"
ST="$WORK/grub-2.12"
OUT="$REPO/build/core"
mkdir -p "$WORK" "$REPO/build/grub" "$OUT"
cd "$WORK"

if [ ! -f grub-2.12.tar.xz ]; then
  if [ -f "$REPO/build/grub/grub-2.12.tar.xz" ]; then
    cp "$REPO/build/grub/grub-2.12.tar.xz" .
  else
    curl -fL --retry 3 -o "$REPO/build/grub/grub-2.12.tar.xz" https://ftp.gnu.org/gnu/grub/grub-2.12.tar.xz
    cp "$REPO/build/grub/grub-2.12.tar.xz" .
  fi
fi

if [ ! -d grub-2.12 ]; then
  echo "PRISTINE: extracting and integrating"
  tar xf grub-2.12.tar.xz
  touch grub-2.12/grub-core/extra_deps.lst
  cd grub-2.12
  # 源码集成
  cp $MODDIR/hyverify.c $MODDIR/hysha.c $MODDIR/hysha.h $MODDIR/hygcm.c $MODDIR/hygcm.h \
     $MODDIR/aes.c $MODDIR/aes.h $MODDIR/tweetnacl.c $MODDIR/tweetnacl.h grub-core/
  mkdir -p grub-core/hyshim
  cp $MODDIR/shim/*.h grub-core/hyshim/
  cp $MODDIR/hykeys.h grub-core/hykeys.h 2>/dev/null || true
  # aes.c 适配（freestanding：string.h 不可用）
  node /mnt/vmiss/hyos-build/scripts/fixaes-tree.js grub-core/aes.c
  # core.def 注册模块
  python3 /mnt/vmiss/hyos-build/scripts/definject.py grub-core/Makefile.core.def
  # 构建系统重生成（gentpl + automake 仅 grub-core + aux 兜底）
  ./autogen.sh > /tmp/autogen.log 2>&1 || { tail -10 /tmp/autogen.log; exit 1; }
  automake --add-missing --copy -f grub-core/Makefile > /dev/null 2>&1 || true
  ./configure --with-platform=pc --target=i386-linux-gnu \
    TARGET_CC=i686-linux-gnu-gcc TARGET_LD=i686-linux-gnu-ld \
    TARGET_OBJCOPY=i686-linux-gnu-objcopy TARGET_STRIP=i686-linux-gnu-strip \
    TARGET_RANLIB=i686-linux-gnu-ranlib \
    --disable-werror --disable-nls --disable-grub-mkfont \
    --disable-efiemu --disable-device-mapper --disable-libzfs --disable-liblzma \
    > /tmp/grub-configure.log 2>&1 || { tail -20 /tmp/grub-configure.log; exit 1; }
  sudo apt-get install -y -qq gawk pkg-config autopoint gettext >/dev/null 2>&1 || true
  sudo sh -c "ln -sf $(which automake) /usr/local/bin/automake-1.15; ln -sf $(which aclocal) /usr/local/bin/aclocal-1.15" 2>/dev/null || true
  make -j"$(nproc)" AWK=gawk > /tmp/grub-make.log 2>&1 || { tail -20 /tmp/grub-make.log; exit 1; }
  echo "TREE_READY"
else
  echo "TREE_EXISTS: incremental"
fi

cd "$ST"
# 同步最新源码与密钥
cp $MODDIR/hyverify.c $MODDIR/hysha.c $MODDIR/hygcm.c grub-core/
cp $MODDIR/hykeys.h grub-core/hykeys.h
# 模块重建（禁 makefile 重生成）
cd grub-core
make -o ../config.status -o Makefile.in AWK=gawk hyverify.mod > /tmp/hym.log 2>&1 \
  || { tail -12 /tmp/hym.log; exit 1; }
# 模块元数据（syminfo/moddep）重建
cat kernel_syms.lst extra_deps.lst > syminfo.lst.new
for m in *.module; do sh gensyminfo.sh "$m" >> syminfo.lst.new || exit 1; done
cat syminfo.lst.new | sort | gawk -f genmoddep.awk > moddep.lst
echo "MODDEP lines: $(wc -l < moddep.lst)"
grep -q "^hyverify:" moddep.lst || echo "hyverify:" >> moddep.lst

# mkimage（依赖闭包自动包含 disk 等）
$ST/grub-mkimage -O i386-pc -o $OUT/core.img \
  -d $ST/grub-core -c "$MODDIR/embed.cfg" -p "(hd0,msdos1)/boot/grub" \
  biosdisk part_msdos fat linux normal configfile boot halt reboot serial terminal echo net http pxe disk hyverify \
  && echo "CORE_OK $OUT/core.img"
ls -la $OUT
