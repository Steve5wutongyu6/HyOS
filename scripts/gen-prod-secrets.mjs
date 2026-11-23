// 生成生产密钥服务 secrets（一次性工具；输出写到仓库外，绝不入库）
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const skPkcs8 = privateKey.export({ type: "pkcs8", format: "der" }).toString("hex");
const pubRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
const ci = randomBytes(24).toString("hex");
const owner = randomBytes(24).toString("hex");

const out = process.argv[2] || "/mnt/vmiss/hyos-prod-secrets.env";
writeFileSync(out, [
  "# HyOS 生产密钥服务 secrets（勿入库勿外传）",
  "SRV_SK_PKCS8=" + skPkcs8,
  "SRV_PUB_RAW_HEX=" + pubRaw,
  "CI_TOKEN=" + ci,
  "OWNER_TOKEN=" + owner,
  "",
].join("\n"), { mode: 0o600 });
console.log("SECRETS_WRITTEN", out);
console.log("SRV_PUB", pubRaw.slice(0, 16) + "...");
