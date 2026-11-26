// 部署前自检：确认线上 Worker 的响应签名私钥与镜像内置 SRV_PUB 匹配。
// 背景：Worker 的 SRV_SK 与镜像 SRV_PUB 若不一致，设备在 grub_ok 响应验签失败后会 fail-closed 自毁，
//       而服务端事件已记录 grub_ok —— 表现为"上电后立刻断电、VNC 空白"，极难现场定位。
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, createHash, sign, verify, randomBytes } from "node:crypto";

const fx = JSON.parse(readFileSync(new URL("../tests/fixtures/dev-keys.json", import.meta.url), "utf8"));
const BASE = process.env.KEY_SERVER || "https://hyos.nanachi.cloud";
const dkPriv = createPrivateKey({ key: Buffer.from(fx.dk_priv_pkcs8_hex, "hex"), format: "der", type: "pkcs8" });
const srvPub = createPublicKey({
  key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(fx.srv_pub_raw_hex, "hex")]),
  format: "der", type: "spki",
});
const b64u = (b) => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hex = (b) => Buffer.from(b).toString("hex");

const nonce = randomBytes(32);
const nb = b64u(nonce);
const msg = fx.did + "|alive|1|" + nb;
const sig = sign(null, Buffer.from(msg), dkPriv);
const r = await fetch(BASE + "/v1/ack", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ did: fx.did, stage: "alive", epoch: 1, nonce: nb, sig: hex(sig) }),
});
const body = await r.text();
let j = {};
try { j = JSON.parse(body); } catch {}
const outcome = j.outcome || "";
const sigOk = j.sig ? verify(null, Buffer.from(msg + "|" + outcome), srvPub, Buffer.from(j.sig, "hex")) : false;
if (r.status !== 200 || !sigOk) {
  console.error("WORKER_KEY_MISMATCH did=" + fx.did + " http=" + r.status + " outcome=" + outcome + " sig_ok=" + sigOk);
  console.error("  提示：把本构建的 SRV_SK_PKCS8 同步到 Worker（build-for-target 已自动执行）后重试");
  console.error("  body=" + body.slice(0, 160));
  process.exit(1);
}
console.log("WORKER_KEYS_OK did=" + fx.did + " outcome=" + outcome);
