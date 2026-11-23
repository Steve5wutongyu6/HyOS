#!/bin/bash
echo ===FIXTURE_CONSISTENCY===
node -e '
const crypto=require("crypto"),fs=require("fs");
const fx=JSON.parse(fs.readFileSync("/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json","utf8"));
const raw=(priv)=>{const s=crypto.createPublicKey(priv).export({type:"spki",format:"der"});return s.subarray(s.length-32).toString("hex");};
const dkPriv=crypto.createPrivateKey({key:Buffer.from(fx.dk_priv_pkcs8_hex,"hex"),format:"der",type:"pkcs8"});
console.log("dk_pub matches derived:", raw(dkPriv)===fx.dk_pub_hex);
const seed=Buffer.from(fx.dk_priv_pkcs8_hex.slice(-64),"hex");
const fromSeed=crypto.createPrivateKey({key:Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"),seed]),format:"der",type:"pkcs8"});
console.log("seed(used by rust/grub) matches dk_pub:", raw(fromSeed)===fx.dk_pub_hex);
const sigSeed=Buffer.from(fx.sig_seed_hex,"hex");
const sigPriv=crypto.createPrivateKey({key:Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"),sigSeed]),format:"der",type:"pkcs8"});
console.log("sig_pub matches derived:", raw(sigPriv)===fx.sig_pub_hex);
console.log("did:", fx.did);
'
echo ===SCENARIOS===
grep -aE "^== |E2E ALL|E2E HAS|E2E_EXIT" /tmp/e2e15.log 2>/dev/null | tail -8