#!/bin/bash
set -o pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
K=$REPO/tests/fixtures/dev-keys.json
GTK=$HOME/hyos-build-grub/grub-2.12
echo ===REBUILD_IMAGE===
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img --hello $B/hello --keys $K --grubtree $GTK --work $B/work3 --out $B/deploy-test.img --cfg $REPO/tests/grub-test.cfg 2>&1 | tail -2
echo ===HYINIT_EMBEDS_CURRENT_KEY===
node -e '
const fs=require("fs"),fx=JSON.parse(fs.readFileSync("/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json","utf8"));
const bin=fs.readFileSync("/mnt/vmiss/hyos-build/build/hyinit");
console.log("dk_pub present:", bin.includes(Buffer.from(fx.dk_pub_hex,"hex")));
console.log("vk_sig present:", bin.includes(Buffer.from(fx.sig_pub_hex,"hex")));
'
echo ===ANALYZE_PRISTINE_P3===
bash $REPO/tests/analyze-p3.sh 2>&1 | tail -18