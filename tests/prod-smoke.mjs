// HyOS 生产端到端冒烟：enroll → challenge → 解信封 → unwrap DEK → ack 状态机 → sealed
// 与 contract.mjs 的区别：设备密钥现场随机生成（不依赖 fixture）、服务端签名公钥来自
// SRV_PUB_RAW_HEX 环境变量、不执行 rearm/revoke（属运维操作）。
// 用法: KEY_SERVER=https://hyos.nanachi.cloud CI_TOKEN=xxx [SRV_PUB_RAW_HEX=xxx] node tests/prod-smoke.mjs
import { createPrivateKey, createPublicKey, randomBytes, sign, verify, createDecipheriv, hkdfSync } from "node:crypto";

const BASE = (process.env.KEY_SERVER || "https://hyos.nanachi.cloud").replace(/\/$/, "");
const CI_TOKEN = process.env.CI_TOKEN;
if (!CI_TOKEN) { console.error("需要 CI_TOKEN 环境变量"); process.exit(2); }

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
let pass = 0, fail = 0;
function check(name, cond, detail = "") {
  if (cond) { pass++; console.log("PASS " + name); }
  else { fail++; console.log("FAIL " + name + " " + detail); }
}
const b64u = (u8) => Buffer.from(u8).toString("base64url");
const hexd = (u8) => Buffer.from(u8).toString("hex");

function ed25519FromSeed(seed) {
  const pkcs8Der = Buffer.concat([PKCS8_PREFIX, seed]);
  const priv = createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ type: "spki", format: "der" });
  return { priv, pubRawHex: spki.subarray(spki.length - 32).toString("hex") };
}

function pubFromRaw(hexStr) {
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hexStr, "hex")]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

const dkSeed = randomBytes(32);
const dk = ed25519FromSeed(dkSeed);
const sig = ed25519FromSeed(randomBytes(32));
const srv = ed25519FromSeed(randomBytes(32));
const did = "prod" + randomBytes(5).toString("hex");
const tkMaster = randomBytes(32).toString("hex");
const wk0Root = randomBytes(32).toString("hex");
const wk1Root = randomBytes(32).toString("hex");
const dekSys = randomBytes(32).toString("hex");
const dekApp = randomBytes(32).toString("hex");

const dkSign = (msg) => hexd(sign(null, Buffer.from(msg, "utf8"), dk.priv));

function deriveKek(rootHex, layer, epoch) {
  const e8 = Buffer.alloc(8); e8.writeBigUInt64BE(BigInt(epoch));
  return new Uint8Array(hkdfSync("sha256", Buffer.from(rootHex, "hex"), Buffer.alloc(0),
    Buffer.concat([Buffer.from(layer), e8]), 32));
}

async function main() {
  // 1. enroll（CI_TOKEN 鉴权）
  let r = await fetch(BASE + "/v1/enroll", {
    method: "POST",
    headers: { "authorization": "Bearer " + CI_TOKEN, "content-type": "application/json" },
    body: JSON.stringify({
      did, dk_pub: dk.pubRawHex, tk_master: tkMaster,
      wk0_root: wk0Root, wk1_root: wk1Root,
      dek_sys: dekSys, dek_app: dekApp, grub_ver_max: 1,
    }),
  });
  check("enroll 200", r.status === 200, String(r.status) + " " + (await r.text()).slice(0, 120));

  // 2. challenge epoch=1
  const nc = new Uint8Array(randomBytes(32));
  r = await fetch(BASE + "/v1/boot/challenge?did=" + did + "&epoch=1&grub_ver=1&nc=" + b64u(nc) + "&sig=" + dkSign(did + "|1|1|" + b64u(nc)));
  check("challenge 200", r.status === 200, String(r.status));
  const ch = await r.json();
  const ns = new Uint8Array(Buffer.from(ch.ns, "base64url"));
  const nonce = new Uint8Array(Buffer.from(ch.nonce, "base64url"));
  const ct = new Uint8Array(Buffer.from(ch.ct, "base64url"));

  // 3. 服务端签名（若提供 SRV_PUB_RAW_HEX）
  if (process.env.SRV_PUB_RAW_HEX) {
    const ok = verify(null, Buffer.concat([Buffer.from(ct), Buffer.from(nc), Buffer.from(ns)]),
      pubFromRaw(process.env.SRV_PUB_RAW_HEX), Buffer.from(ch.sig_srv, "hex"));
    check("server ed25519 sig", ok === true);
  }

  // 4. 解信封
  const sk = new Uint8Array(hkdfSync("sha256", Buffer.from(tkMaster, "hex"), Buffer.alloc(0),
    Buffer.concat([Buffer.from("envelope"), Buffer.from(nc), Buffer.from(ns)]), 32));
  const d = createDecipheriv("aes-256-gcm", Buffer.from(sk), Buffer.from(nonce));
  d.setAAD(Buffer.concat([Buffer.from(nc), Buffer.from(ns)]));
  d.setAuthTag(Buffer.from(ct.subarray(ct.length - 16)));
  const payload = JSON.parse(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString());
  check("payload epoch=1", payload.epoch === 1, JSON.stringify(payload).slice(0, 80));

  // 5. unwrap DEK（与 Rust kek() 同构）
  const kek0 = deriveKek(wk0Root, "sys", 1);
  const wrapBuf = Buffer.from(payload.wrap_sys, "base64url");
  const d0 = createDecipheriv("aes-256-gcm", Buffer.from(kek0), wrapBuf.subarray(0, 12));
  const e8 = Buffer.alloc(8); e8.writeBigUInt64BE(1n);
  d0.setAAD(Buffer.concat([Buffer.from("hyos-dek"), e8]));
  d0.setAuthTag(wrapBuf.subarray(wrapBuf.length - 16));
  const dek = Buffer.concat([d0.update(wrapBuf.subarray(12, wrapBuf.length - 16)), d0.final()]);
  check("wrap_sys opens to dek_sys", hexd(dek) === dekSys);

  // 6. ack 状态机
  const ack = async (stage, epoch) => {
    const nonceA = b64u(new Uint8Array(randomBytes(8)));
    return fetch(BASE + "/v1/ack", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ did, stage, epoch, nonce: nonceA, sig: dkSign(did + "|" + stage + "|" + epoch + "|" + nonceA) }),
    });
  };
  r = await ack("grub_ok", 1); check("ack grub_ok 200", r.status === 200, String(r.status));
  r = await ack("sys_ok", 1); check("ack sys_ok 200", r.status === 200);
  r = await ack("app_ok", 1);
  const body = await r.json();
  check("ack app_ok sealed", r.status === 200 && body.state === "sealed", JSON.stringify(body).slice(0, 100));
  check("wrapped_next issued", !!body.wrapped_sys_next && !!body.wrapped_app_next);
  r = await ack("grub_ok", 1); check("bad transition 409", r.status === 409, String(r.status));

  console.log("\nprod-smoke: " + pass + " pass, " + fail + " fail  (did=" + did + " @ " + BASE + ")");
  process.exit(fail ? 1 : 0);
}
main().catch(e => { console.error("FATAL", e); process.exit(2); });
