// 设备注册助手：读 tests/fixtures/dev-keys.json，向密钥服务 enroll（CI_TOKEN 鉴权）
// 用法: KEY_SERVER=https://hyos.nanachi.cloud CI_TOKEN=xxx node scripts/enroll-device.mjs
import { readFileSync } from "node:fs";

const BASE = (process.env.KEY_SERVER || "").replace(/\/$/, "");
const CI_TOKEN = process.env.CI_TOKEN;
if (!BASE || !CI_TOKEN) {
  console.error("需要 KEY_SERVER 与 CI_TOKEN 环境变量");
  process.exit(2);
}
const fx = JSON.parse(readFileSync(new URL("../tests/fixtures/dev-keys.json", import.meta.url), "utf8"));
const r = await fetch(BASE + "/v1/enroll", {
  method: "POST",
  headers: { "content-type": "application/json", "authorization": "Bearer " + CI_TOKEN },
  body: JSON.stringify({
    did: fx.did, dk_pub: fx.dk_pub_hex, tk_master: fx.tk_master,
    wk0_root: fx.wk0_root, wk1_root: fx.wk1_root,
    dek_sys: fx.dek_sys, dek_app: fx.dek_app, grub_ver_max: 1,
  }),
});
const body = await r.text();
console.log(r.status === 200 ? "ENROLL_OK " + body.slice(0, 120) : "ENROLL_FAIL " + r.status + " " + body.slice(0, 200));
process.exit(r.status === 200 ? 0 : 1);
