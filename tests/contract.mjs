// HyOS Worker 契约测试（在 Lima 客机内、wrangler dev --local 下运行）
// 前置: cd server && npm install && node ../scripts/gen-dev-keys.mjs && npx wrangler d1 execute hyos --local --file schema.sql
//       且 wrangler dev --local 已在 :8787 监听
// 用法: KEY_SERVER=http://127.0.0.1:8787 node tests/contract.mjs
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, randomBytes, sign, verify, createDecipheriv, hkdfSync } from "node:crypto";

const BASE = process.env.KEY_SERVER || "http://127.0.0.1:8787";
const fx = JSON.parse(readFileSync(new URL("./fixtures/dev-keys.json", import.meta.url), "utf8"));
const b64u = (u8) => Buffer.from(u8).toString("base64url");
const unbuf = (b64) => new Uint8Array(Buffer.from(b64, "base64url"));
const hexd = (u8) => Buffer.from(u8).toString("hex");

let pass = 0, fail = 0;
function check(name, cond, detail = "") {
  if (cond) { pass++; console.log("PASS " + name); }
  else { fail++; console.log("FAIL " + name + " " + detail); }
}

const dk = createPrivateKey({ key: Buffer.from(fx.dk_priv_pkcs8_hex, "hex"), format: "der", type: "pkcs8" });
// 裸 32B Ed25519 公钥 → SPKI DER → KeyObject
function pubFromRaw(hexStr) {
  const raw = Buffer.from(hexStr, "hex");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}
const srvPub = pubFromRaw(fx.srv_pub_raw_hex);

function dkSign(msgStr) {
  return hexd(sign(null, Buffer.from(msgStr, "utf8"), dk));
}

function deriveKek(rootHex, layer, epoch) {
  const e8 = Buffer.alloc(8); e8.writeBigUInt64BE(BigInt(epoch));
  return new Uint8Array(hkdfSync("sha256", Buffer.from(rootHex, "hex"), Buffer.alloc(0), Buffer.concat([Buffer.from(layer), e8]), 32));
}

function openEnvelope(tkHex, nc, ns, nonce, ct) {
  const e8 = Buffer.alloc(8); // aad = nc||ns
  void e8;
  const sk = new Uint8Array(hkdfSync("sha256", Buffer.from(tkHex, "hex"), Buffer.alloc(0),
    Buffer.concat([Buffer.from("envelope"), Buffer.from(nc), Buffer.from(ns)]), 32));
  const d = createDecipheriv("aes-256-gcm", Buffer.from(sk), Buffer.from(nonce));
  d.setAAD(Buffer.concat([Buffer.from(nc), Buffer.from(ns)]));
  d.setAuthTag(Buffer.from(ct.subarray(ct.length - 16)));
  const pt = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  return pt;
}

async function main() {
  const t0 = Date.now();
  // 1. enroll
  let r = await fetch(BASE + "/v1/enroll", {
    method: "POST",
    headers: { "authorization": "Bearer " + fx.ci_token, "content-type": "application/json" },
    body: JSON.stringify({
      did: fx.did, dk_pub: fx.dk_pub_hex, tk_master: fx.tk_master,
      wk0_root: fx.wk0_root, wk1_root: fx.wk1_root,
      dek_sys: fx.dek_sys, dek_app: fx.dek_app, grub_ver_max: 1,
    }),
  });
  check("enroll 200", r.status === 200, String(r.status));

  // 2. challenge epoch=1（合法签名）→ 解信封
  const nc = new Uint8Array(randomBytes(32));
  const sig = dkSign(fx.did + "|1|1|" + b64u(nc));
  r = await fetch(BASE + "/v1/boot/challenge?did=" + fx.did + "&epoch=1&grub_ver=1&nc=" + b64u(nc) + "&sig=" + sig);
  check("challenge 200", r.status === 200, String(r.status));
  const ch = await r.json();
  const ns = unbuf(ch.ns), nonce = unbuf(ch.nonce), ct = unbuf(ch.ct);
  // 3. 服务端签名验证: Ed25519(ct||nc||ns)
  const okSrv = verify(null, Buffer.concat([Buffer.from(ct), Buffer.from(nc), Buffer.from(ns)]), srvPub, Buffer.from(ch.sig_srv, "hex"));
  check("server ed25519 sig", okSrv === true);
  const pt = openEnvelope(fx.tk_master, nc, ns, nonce, ct).toString();
  const payload = JSON.parse(pt);
  check("payload epoch=1", payload.epoch === 1, pt);
  check("payload wrap_sys present", typeof payload.wrap_sys === "string" && payload.wrap_sys.length > 0);
  // 解 DEK 验证 wrap 正确性（与 Rust kek() 同构）
  const kek0 = deriveKek(fx.wk0_root, "sys", 1);
  const wrapBuf = Buffer.from(payload.wrap_sys, "base64url");
  const d0 = createDecipheriv("aes-256-gcm", Buffer.from(kek0), wrapBuf.subarray(0, 12));
  const e8 = Buffer.alloc(8); e8.writeBigUInt64BE(1n);
  d0.setAAD(Buffer.concat([Buffer.from("hyos-dek"), e8]));
  d0.setAuthTag(wrapBuf.subarray(wrapBuf.length - 16));
  const dek = Buffer.concat([d0.update(wrapBuf.subarray(12, wrapBuf.length - 16)), d0.final()]);
  check("wrap_sys opens to dek_sys", hexd(dek) === fx.dek_sys, hexd(dek).slice(0, 12));

  // 4. 错误签名 → 403
  r = await fetch(BASE + "/v1/boot/challenge?did=" + fx.did + "&epoch=1&grub_ver=1&nc=" + b64u(nc) + "&sig=" + "00".repeat(64));
  check("challenge bad sig 403", r.status === 403, String(r.status));

  // 5. 状态机推进 grub_ok → sys_ok → app_ok
  const ack = async (stage, epoch) => {
    const nonceA = b64u(new Uint8Array(randomBytes(8)));
    const s = dkSign(fx.did + "|" + stage + "|" + epoch + "|" + nonceA);
    return fetch(BASE + "/v1/ack", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ did: fx.did, stage, epoch, nonce: nonceA, sig: s }),
    });
  };
  r = await ack("grub_ok", 1); check("ack grub_ok 200", r.status === 200, String(r.status) + JSON.stringify(await r.json().catch(() => "")));
  r = await ack("sys_ok", 1); check("ack sys_ok 200", r.status === 200);
  r = await ack("app_ok", 1);
  const ackBody = await r.json();
  check("ack app_ok 200 sealed", r.status === 200 && ackBody.state === "sealed", JSON.stringify(ackBody));
  check("app_ok returns wrapped_next", !!ackBody.wrapped_sys_next && !!ackBody.wrapped_app_next);
  // 乱序 transition 被拒
  r = await ack("grub_ok", 1); check("bad transition 409", r.status === 409, String(r.status));

  // 6. 新 epoch 正常；旧 epoch 回退被拒并 quarantine
  const nc2 = new Uint8Array(randomBytes(32));
  r = await fetch(BASE + "/v1/boot/challenge?did=" + fx.did + "&epoch=2&grub_ver=1&nc=" + b64u(nc2) + "&sig=" + dkSign(fx.did + "|2|1|" + b64u(nc2)));
  check("challenge epoch=2 ok", r.status === 200, String(r.status));
  // 真实回滚场景：sealed epoch=2 后，用旧磁盘头 epoch=1 发起 challenge → 403 + quarantine
  r = await ack("grub_ok", 2); check("ack2 grub_ok", r.status === 200);
  r = await ack("sys_ok", 2);  check("ack2 sys_ok", r.status === 200);
  r = await ack("app_ok", 2);  check("ack2 app_ok sealed", r.status === 200);
  const nc0 = new Uint8Array(randomBytes(32));
  r = await fetch(BASE + "/v1/boot/challenge?did=" + fx.did + "&epoch=1&grub_ver=1&nc=" + b64u(nc0) + "&sig=" + dkSign(fx.did + "|1|1|" + b64u(nc0)));
  check("rollback epoch=1 after sealed2 403", r.status === 403, String(r.status));

  // 7. rearm 后旧磁盘头（epoch=2）可再次启动
  r = await fetch(BASE + "/v1/rearm", {
    method: "POST", headers: { "authorization": "Bearer " + fx.owner_token, "content-type": "application/json" },
    body: JSON.stringify({ did: fx.did }),
  });
  check("rearm 200", r.status === 200, String(r.status));
  r = await fetch(BASE + "/v1/boot/challenge?did=" + fx.did + "&epoch=2&grub_ver=1&nc=" + b64u(nc2) + "&sig=" + dkSign(fx.did + "|2|1|" + b64u(nc2)));
  check("post-rearm challenge epoch=2 ok", r.status === 200, String(r.status));

  // 8. revoke 后拒绝
  r = await fetch(BASE + "/v1/revoke", {
    method: "POST", headers: { "authorization": "Bearer " + fx.owner_token, "content-type": "application/json" },
    body: JSON.stringify({ did: fx.did }),
  });
  check("revoke 200", r.status === 200);
  r = await fetch(BASE + "/v1/boot/challenge?did=" + fx.did + "&epoch=3&grub_ver=1&nc=" + b64u(nc2) + "&sig=" + dkSign(fx.did + "|3|1|" + b64u(nc2)));
  check("revoked challenge 403", r.status === 403, String(r.status));

  const ms = Date.now() - t0;
  console.log("\ncontract: " + pass + " pass, " + fail + " fail, " + ms + "ms");
  process.exit(fail ? 1 : 0);
}
main().catch(e => { console.error("FATAL", e); process.exit(2); });