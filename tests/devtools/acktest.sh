#!/bin/bash
set -e
FX=/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json
node -e '
const crypto=require("crypto"),fs=require("fs");
const fx=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
const priv=crypto.createPrivateKey({key:Buffer.from(fx.dk_priv_pkcs8_hex,"hex"),format:"der",type:"pkcs8"});
const nonce=Buffer.from(crypto.randomBytes(8)).toString("base64url");
const msg=fx.did+"|grub_ok|1|"+nonce;
const sig=crypto.sign(null,Buffer.from(msg,"utf8"),priv).toString("hex");
const body=JSON.stringify({did:fx.did,stage:"grub_ok",epoch:1,nonce,sig});
fetch("http://127.0.0.1:8787/v1/ack",{method:"POST",headers:{"content-type":"application/json"},body})
  .then(async r=>{console.log("ACK_STATUS",r.status,await r.text());})
  .catch(e=>console.log("ACK_ERR",e.message));
' $FX
sleep 2
echo ===DEVICE_STATE===
cd /mnt/vmiss/hyos-build/server
npx wrangler d1 execute hyos --local --command "SELECT did,status FROM devices" 2>/dev/null | tail -12