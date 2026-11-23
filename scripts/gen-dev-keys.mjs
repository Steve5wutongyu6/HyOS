// HyOS 联调密钥生成器（自检 + 原子写入）
// 输出: tests/fixtures/dev-keys.json 与 server/.dev.vars
import { randomBytes, createPrivateKey, createPublicKey, createHash, sign, verify } from "node:crypto";
import { writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function ed25519FromSeed(seed) {
  const pkcs8Der = Buffer.concat([PKCS8_PREFIX, seed]);
  const priv = createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ type: "spki", format: "der" });
  return { priv, pkcs8Der, pubRawHex: spki.subarray(spki.length - 32).toString("hex") };
}

function rawPub(priv) {
  const spki = createPublicKey(priv).export({ type: "spki", format: "der" });
  return spki.subarray(spki.length - 32).toString("hex");
}

const srv = ed25519FromSeed(randomBytes(32));
const sigk = ed25519FromSeed(randomBytes(32));
const dk = ed25519FromSeed(randomBytes(32));

// 一致性自检（首个真实断言，防陈旧/撕裂产物）
const probe = Buffer.from("hyos-selfcheck");
const probeSig = sign(null, probe, dk.priv);
if (!verify(null, probe, createPublicKey(dk.priv), probeSig)) {
  throw new Error("FATAL: dk keypair inconsistent");
}
if (rawPub(dk.priv) !== dk.pubRawHex) {
  throw new Error("FATAL: dk_pub does not match derived public key");
}
if (rawPub(sigk.priv) !== sigk.pubRawHex) {
  throw new Error("FATAL: sig_pub does not match derived public key");
}
if (rawPub(srv.priv) !== srv.pubRawHex) {
  throw new Error("FATAL: srv_pub does not match derived public key");
}

const did = "dev" + createHash("sha256").update(randomBytes(8)).digest("hex").slice(0, 10);
const fixture = {
  did,
  srv_pub_raw_hex: srv.pubRawHex,
  srv_seed_hex: srv.pkcs8Der.subarray(srv.pkcs8Der.length - 32).toString("hex"),
  tk_master: randomBytes(32).toString("hex"),
  wk0_root: randomBytes(32).toString("hex"),
  wk1_root: randomBytes(32).toString("hex"),
  dek_sys: randomBytes(32).toString("hex"),
  dek_app: randomBytes(32).toString("hex"),
  ci_token: "dev-ci-token",
  owner_token: "dev-owner-token",
  dk_priv_pkcs8_hex: dk.pkcs8Der.toString("hex"),
  dk_pub_hex: dk.pubRawHex,
  sig_seed_hex: sigk.pkcs8Der.subarray(sigk.pkcs8Der.length - 32).toString("hex"),
  sig_pub_hex: sigk.pubRawHex,
};

// 落盘前再校一次（防止对象构造被改坏）
const chkPriv = createPrivateKey({ key: Buffer.from(fixture.dk_priv_pkcs8_hex, "hex"), format: "der", type: "pkcs8" });
if (rawPub(chkPriv) !== fixture.dk_pub_hex) {
  throw new Error("FATAL: fixture dk mismatch before write");
}

mkdirSync(join(ROOT, "tests/fixtures"), { recursive: true });
const tmp = join(ROOT, "tests/fixtures/.dev-keys.json.tmp");
writeFileSync(tmp, JSON.stringify(fixture, null, 2));
renameSync(tmp, join(ROOT, "tests/fixtures/dev-keys.json"));
writeFileSync(join(ROOT, "server/.dev.vars"),
  "CI_TOKEN=" + fixture.ci_token + String.fromCharCode(10) +
  "OWNER_TOKEN=" + fixture.owner_token + String.fromCharCode(10) +
  "SRV_SK_PKCS8=" + srv.pkcs8Der.toString("hex") + String.fromCharCode(10));
console.log("dev keys OK did=" + did + " dk_pub=" + fixture.dk_pub_hex.slice(0, 12));
