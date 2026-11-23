#!/bin/bash
node - <<'NODEOF'
const crypto = require("crypto");
const fs = require("fs");
const fx = JSON.parse(fs.readFileSync("/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json", "utf8"));
const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const priv = crypto.createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(fx.dk_priv_pkcs8_hex, "hex")]), format: "der", type: "pkcs8" });
const pubFromPriv = crypto.createPublicKey(priv);
const spki = pubFromPriv.export({ type: "spki", format: "der" });
const derivedPub = spki.subarray(spki.length - 32).toString("hex");
console.log("pub from priv :", derivedPub);
console.log("fixture dk_pub:", fx.dk_pub_hex);
console.log("MATCH:", derivedPub === fx.dk_pub_hex);
NODEOF
