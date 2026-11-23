#!/bin/bash
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
console.log("node sign/verify with fixture:", crypto.verify(null, msg, pub, sig));
NODEOF
echo ===RUST_SIDE===
cd /mnt/vmiss/hyos-build/verifier
cat > /tmp/sigtest.rs <<'EOF'
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
fn main() {
    let fx = std::fs::read_to_string("/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json").unwrap();
    let grab = |k: &str| -> String {
        let pat = format!("\"{}\": \"", k);
        let i = fx.find(&pat).unwrap_or(fx.find(&format!("\"{}\":\"", k)).unwrap());
        let rest = &fx[i + pat.len()..];
        rest[..rest.find('"').unwrap()].to_string()
    };
    let seed_hex = grab("sig_seed_hex");
    let mut seed = [0u8; 32];
    for i in 0..32 { seed[i] = u8::from_str_radix(&seed_hex[i*2..i*2+2], 16).unwrap(); }
    let sk = SigningKey::from_bytes(&seed);
    let msg = b"test-message";
    let sig = sk.sign(msg);
    let pk_hex = grab("sig_pub_hex");
    let mut pk = [0u8; 32];
    for i in 0..32 { pk[i] = u8::from_str_radix(&pk_hex[i*2..i*2+2], 16).unwrap(); }
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    println!("rust sign/verify with fixture: {}", vk.verify(msg, &sig).is_ok());
    println!("rust sig hex: {}", hex_like(&sig.to_bytes()));
}
fn hex_like(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
EOF
cd /tmp && cargo script 2>/dev/null || true
