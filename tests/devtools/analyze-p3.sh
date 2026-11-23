#!/bin/bash
node - <<'NODEOF'
const fs = require("fs");
const crypto = require("crypto");
const fx = JSON.parse(fs.readFileSync("/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json", "utf8"));
const img = fs.readFileSync("/mnt/vmiss/hyos-build/build/deploy-test.img");
const P3 = 36864;
const be8 = (e) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(e)); return b; };
const hkdf = (ikm, info) => Buffer.from(crypto.hkdfSync("sha256", ikm, Buffer.alloc(0), info, 32));
const ckOf = (e) => crypto.createHash("sha256").update(Buffer.concat([Buffer.from(fx.wk0_root, "hex"), Buffer.from(fx.wk1_root, "hex"), Buffer.from([e & 0xff])])).digest();

// 1) 找出镜像内所有 HYOSLOT1 位置
const needle = Buffer.from("HYOSLOT1");
let idx = -1, hits = [];
while ((idx = img.indexOf(needle, idx + 1)) !== -1) hits.push(idx);
console.log("HYOSLOT1 hits (offset -> LBA):", hits.map(o => o + "@" + Math.floor(o / 512)).join(", "));
console.log("expected p3 header LBA:", P3, " img size:", img.length);

// 2) 解析 p3 头部区域（1024B）
const region = img.subarray(P3 * 512, P3 * 512 + 1024);
console.log("p3 first16:", region.subarray(0, 16).toString("hex"));
for (const [name, off] of [["A", 0], ["B", 512]]) {
  const h = region.subarray(off, off + 512);
  const magic = h.subarray(0, 8).toString();
  console.log("--- slot " + name + " magic=" + JSON.stringify(magic));
  if (magic !== "HYOSLOT1") continue;
  const seq = Number(h.readBigUInt64BE(9));
  const epoch = Number(h.readBigUInt64BE(17));
  const wrap = h.subarray(25, 85);
  const plen = Number(h.readBigUInt64BE(117));
  console.log("  seq=" + seq + " epoch=" + epoch + " plen=" + plen);
  for (const e of [epoch, epoch + 1]) {
    try {
      const kek = hkdf(Buffer.from(fx.wk1_root, "hex"), Buffer.concat([Buffer.from("app"), be8(e)]));
      const d = crypto.createDecipheriv("aes-256-gcm", kek, wrap.subarray(0, 12));
      d.setAAD(Buffer.concat([Buffer.from("hyos-dek"), be8(epoch)]));
      d.setAuthTag(wrap.subarray(44));
      const dek = Buffer.concat([d.update(wrap.subarray(12, 44)), d.final()]);
      console.log("  unwrap OK e=" + e);
      const ck = ckOf(epoch);
      const mac = crypto.createHmac("sha256", ck).update(h.subarray(0, 480)).digest();
      console.log("  MAC(computed ck) match:", mac.equals(h.subarray(480, 512)));
      const dekIsApp = dek.toString("hex") === fx.dek_app;
      console.log("  dek == fixture.dek_app:", dekIsApp);
      const nonce = hkdf(dek, Buffer.from("payload-nonce")).subarray(0, 12);
      const ct = img.subarray((P3 + 8) * 512, (P3 + 8) * 512 + plen);
      const dd = crypto.createDecipheriv("aes-256-gcm", dek, nonce);
      dd.setAAD(Buffer.from("hyos-payload"));
      dd.setAuthTag(ct.subarray(ct.length - 16));
      const pt = Buffer.concat([dd.update(ct.subarray(0, ct.length - 16)), dd.final()]);
      console.log("  payload OK len=" + pt.length + " sha_match=" + (crypto.createHash("sha256").update(pt).digest("hex") === h.subarray(85, 117).toString("hex")));
    } catch (err) { console.log("  e=" + e + " FAIL: " + err.message.slice(0, 70)); }
  }
}
NODEOF