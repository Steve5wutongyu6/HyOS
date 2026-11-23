#!/bin/bash
set -o pipefail
REPO=/mnt/vmiss/hyos-build
B=$REPO/build
K=$REPO/tests/fixtures/dev-keys.json
GTK=$HOME/hyos-build-grub/grub-2.12
export PATH="$HOME/.cargo/bin:$PATH"
echo ===REBUILD_MKDISK===
cd $REPO/tools/mkdisk && cargo build --release 2>&1 | grep -E "^error" -A3 | head -6
cp $REPO/tools/mkdisk/target/release/mkdisk $B/mkdisk || exit 1
echo ===BUILD_IMAGE===
$B/mkdisk disk --core $B/core/core.img --vmlinuz $B/vmlinuz --initrd $B/initrd.img --hello $B/hello --keys $K --grubtree $GTK --work $B/work3 --out $B/deploy-test.img --cfg $REPO/tests/grub-test.cfg 2>&1 | tail -1
echo ===EXTRACT_CPIO===
node - <<'NODEOF'
const fs=require("fs"),crypto=require("crypto");
const fx=JSON.parse(fs.readFileSync("/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json","utf8"));
const img=fs.readFileSync("/mnt/vmiss/hyos-build/build/deploy-test.img");
const P3=36864;
const h=img.subarray(P3*512,P3*512+512);
const be8=(e)=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(e));return b;};
const hkdf=(ikm,info)=>Buffer.from(crypto.hkdfSync("sha256",ikm,Buffer.alloc(0),info,32));
const epoch=Number(h.readBigUInt64BE(17)),plen=Number(h.readBigUInt64BE(117));
const wrap=h.subarray(25,85);
const kek=hkdf(Buffer.from(fx.wk1_root,"hex"),Buffer.concat([Buffer.from("app"),be8(epoch)]));
const d=crypto.createDecipheriv("aes-256-gcm",kek,wrap.subarray(0,12));
d.setAAD(Buffer.concat([Buffer.from("hyos-dek"),be8(epoch)]));d.setAuthTag(wrap.subarray(44));
const dek=Buffer.concat([d.update(wrap.subarray(12,44)),d.final()]);
const ct=img.subarray((P3+8)*512,(P3+8)*512+plen);
const dd=crypto.createDecipheriv("aes-256-gcm",dek,hkdf(dek,Buffer.from("payload-nonce")).subarray(0,12));
dd.setAAD(Buffer.from("hyos-payload"));dd.setAuthTag(ct.subarray(ct.length-16));
const pt=Buffer.concat([dd.update(ct.subarray(0,ct.length-16)),dd.final()]);
fs.writeFileSync("/tmp/app.cpio",pt);
console.log("cpio bytes:",pt.length);
NODEOF
echo ===CPIO_LIST===
cpio -itv < /tmp/app.cpio 2>&1 | head -8