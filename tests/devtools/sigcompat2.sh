#!/bin/bash
sleep 3
node - <<'NODEOF'
const crypto = require("crypto");
const fs = require("fs");
const fx = JSON.parse(fs.readFileSync("/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json", "utf8"));
const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const priv = crypto.createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(fx.dk_priv_pkcs8_hex, "hex")]), format: "der", type: "pkcs8" });
const msg = Buffer.from("test-message");
const sig = crypto.sign(null, msg, priv);
const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(fx.dk_pub_hex, "hex")]);
const pub = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
console.log("fixture did:", fx.did);
console.log("node sign/verify with fixture:", crypto.verify(null, msg, pub, sig));
NODEOF
