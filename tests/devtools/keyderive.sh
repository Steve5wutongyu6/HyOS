#!/bin/bash
node - <<'NODEOF'
const crypto = require("crypto");
const fs = require("fs");
const fx = JSON.parse(fs.readFileSync("/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json", "utf8"));
const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const priv = crypto.createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(fx.dk_priv_pkcs8_hex, "hex")]), format: "der", type: "pkcs8" });
const pubKeyObj = crypto.createPublicKey(priv);
const spki = pubKeyObj.export({ type: "spki", format: "der" });
console.log("spki len:", spki.length);
console.log("derived raw:", spki.subarray(spki.length - 32).toString("hex"));
console.log("fixture pub:", fx.dk_pub_hex);
NODEOF
