//! HyOS 密码学核心（设计文档 v1.2 §4/§5/§6）
//!
//! 全部纯 Rust 实现，便于静态交叉编译，与 GRUB C 模块共享同一规范：
//! - KEK 派生:  WK0[e] = HKDF-SHA256(WK0_root, info="sys"|epoch), WK1[e] 同理 info="app"
//! - 双槽头:    512B 定长，seq 单调、epoch、wrap(DEK)、img_sha256、HMAC(WK[e]) 自检
//! - 信封:      SK_s = HKDF(TK_master, info="envelope"|nc|ns)，AES-256-GCM
//! - manifest:  规范化文本 + Ed25519 detached 签名

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

pub const SLOT_SIZE: usize = 512;
pub const SLOT_MAGIC: &[u8; 8] = b"HYOSLOT1";
pub const DEK_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

#[derive(Debug)]
pub enum HyError {
    BadSlot(&'static str),
    Crypto(&'static str),
    Sig,
    Format(&'static str),
}

// ---------- KEK 派生 ----------

/// WK0[e]（GRUB 侧/系统镜像层）；info 域分离两层密钥链
pub fn kek(root: &[u8; 32], layer: &str, epoch: u64) -> [u8; 32] {
    let mut info = Vec::with_capacity(layer.len() + 9);
    info.extend_from_slice(layer.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("hkdf expand");
    out
}

pub fn kek_sys(root: &[u8; 32], epoch: u64) -> [u8; 32] { kek(root, "sys", epoch) }
pub fn kek_app(root: &[u8; 32], epoch: u64) -> [u8; 32] { kek(root, "app", epoch) }

// ---------- AEAD 基元 ----------

pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key");
    cipher.encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("seal")
}

pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, HyError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key");
    cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| HyError::Crypto("gcm tag mismatch"))
}

/// wrap(DEK) = nonce(12) || ct(DEK+tag)，AAD = b"hyos-dek" || epoch(8B BE)
pub const WRAP_LEN: usize = 12 + 32 + 16;

pub fn wrap_dek(kek: &[u8; 32], epoch: u64, dek: &[u8; 32]) -> [u8; WRAP_LEN] {
    let mut nonce = [0u8; 12];
    fill_random(&mut nonce);
    let mut aad = Vec::with_capacity(16);
    aad.extend_from_slice(b"hyos-dek");
    aad.extend_from_slice(&epoch.to_be_bytes());
    let ct = aead_seal(kek, &nonce, dek, &aad);
    let mut out = [0u8; WRAP_LEN];
    out[..12].copy_from_slice(&nonce);
    out[12..].copy_from_slice(&ct);
    out
}

pub fn unwrap_dek(kek: &[u8; 32], epoch: u64, blob: &[u8; WRAP_LEN]) -> Result<[u8; 32], HyError> {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut aad = Vec::with_capacity(16);
    aad.extend_from_slice(b"hyos-dek");
    aad.extend_from_slice(&epoch.to_be_bytes());
    let pt = aead_open(kek, &nonce, &blob[12..], &aad)?;
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&pt);
    Ok(dek)
}

// ---------- 双槽头（512B） ----------
// 布局: magic(8) slot_id(1) seq(8) epoch(8) wrap(60) img_sha256(32) payload_len(8)
//       reserved(pad) mac(32)  —— mac = HMAC-SHA256(ck_stage, 本头除 mac 外全部字段)
// 设计说明：MAC 键 = 服务端每轮下发的 ck_stage（GRUB 从 challenge 载荷获得、verifier 从
// sys_ok 应答获得）。这样任何持有本轮 ck 的一方都能重写槽（verifier 推进 epoch），但无需
// 掌握 DEK1（verifier 不应持有系统层 DEK）；wrap 的 GCM tag 仍负责 DEK 本身的认证。
pub const HDR_WRAP_OFF: usize = 25;
pub const HDR_IMG_OFF: usize = 85;
pub const HDR_LEN_OFF: usize = 117;
pub const HDR_MAC_OFF: usize = SLOT_SIZE - 32;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SlotHeader {
    pub slot_id: u8,       // 0 = A, 1 = B
    pub seq: u64,
    pub epoch: u64,
    pub img_sha256: [u8; 32],
    pub payload_len: u64,
}

impl SlotHeader {
    /// 编码：wrap = wrap_dek(kek_e, epoch, dek)；mac = HMAC(ck, header_body)
    pub fn encode(&self, kek_e: &[u8; 32], dek: &[u8; 32], ck: &[u8; 32]) -> [u8; SLOT_SIZE] {
        let mut buf = [0u8; SLOT_SIZE];
        buf[..8].copy_from_slice(SLOT_MAGIC);
        buf[8] = self.slot_id;
        buf[9..17].copy_from_slice(&self.seq.to_be_bytes());
        buf[17..25].copy_from_slice(&self.epoch.to_be_bytes());
        let wrap = wrap_dek(kek_e, self.epoch, dek);
        buf[HDR_WRAP_OFF..HDR_WRAP_OFF + 60].copy_from_slice(&wrap);
        buf[HDR_IMG_OFF..HDR_IMG_OFF + 32].copy_from_slice(&self.img_sha256);
        buf[HDR_LEN_OFF..HDR_LEN_OFF + 8].copy_from_slice(&self.payload_len.to_be_bytes());
        let mac = hmac32(ck, &buf[..HDR_MAC_OFF]);
        buf[HDR_MAC_OFF..].copy_from_slice(&mac);
        buf
    }

    /// 解析：对候选 epoch 的 KEK 尝试 unwrap（GCM tag 验 DEK 正确），成功后再验 ck-MAC（防头字段篡改）。
    pub fn parse(buf: &[u8; SLOT_SIZE], kek_e: &[u8; 32], ck: &[u8; 32]) -> Result<(SlotHeader, [u8; WRAP_LEN]), HyError> {
        if &buf[..8] != SLOT_MAGIC { return Err(HyError::BadSlot("magic")); }
        let mut wrap = [0u8; WRAP_LEN];
        wrap.copy_from_slice(&buf[HDR_WRAP_OFF..HDR_WRAP_OFF + 60]);
        let epoch = u64::from_be_bytes(buf[17..25].try_into().unwrap());
        let _dek = unwrap_dek(kek_e, epoch, &wrap)?;
        let want = &buf[HDR_MAC_OFF..];
        let got = hmac32(ck, &buf[..HDR_MAC_OFF]);
        let mut diff = 0u8;
        for (a, b) in want.iter().zip(got.iter()) { diff |= a ^ b; }
        if diff != 0 { return Err(HyError::BadSlot("hmac")); }
        let h = SlotHeader {
            slot_id: buf[8],
            seq: u64::from_be_bytes(buf[9..17].try_into().unwrap()),
            epoch,
            img_sha256: buf[HDR_IMG_OFF..HDR_IMG_OFF + 32].try_into().unwrap(),
            payload_len: u64::from_be_bytes(buf[HDR_LEN_OFF..HDR_LEN_OFF + 8].try_into().unwrap()),
        };
        Ok((h, wrap))
    }
}

/// 从双槽中选有效且 seq 最大的头（两槽全坏返回错误）。
/// 每槽先用头内 epoch 的 KEK 校验；不匹配再试 epoch+1（容差"已写入下一轮头但 GRUB 侧 KEK 缓存为旧值"的场景）。
pub fn select_slot(
    slot_a: Option<&[u8; SLOT_SIZE]>,
    slot_b: Option<&[u8; SLOT_SIZE]>,
    kek_of: impl Fn(u64) -> [u8; 32],
    ck: &[u8; 32],
) -> Result<(SlotHeader, [u8; WRAP_LEN]), HyError> {
    let mut best: Option<(SlotHeader, [u8; WRAP_LEN])> = None;
    for s in [slot_a, slot_b].into_iter().flatten() {
        let base = u64::from_be_bytes(s[17..25].try_into().unwrap());
        for e in [base, base.saturating_add(1)] {
            if let Ok((h, w)) = SlotHeader::parse(s, &kek_of(e), ck) {
                if best.as_ref().map_or(true, |(bh, _)| h.seq > bh.seq) {
                    best = Some((h, w));
                }
                break;
            }
        }
    }
    best.ok_or(HyError::BadSlot("both slots invalid"))
}

pub fn hmac32(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().into()
}

// ---------- 信封（GRUB↔Worker，http 传输机密性，§6.1 步骤 4） ----------

pub fn envelope_session_key(tk_master: &[u8; 32], nc: &[u8; 32], ns: &[u8; 32]) -> [u8; 32] {
    let mut info = Vec::with_capacity(8 + 64);
    info.extend_from_slice(b"envelope");
    info.extend_from_slice(nc);
    info.extend_from_slice(ns);
    let hk = Hkdf::<Sha256>::new(None, tk_master);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("hkdf");
    out
}

pub struct Envelope { pub ns: [u8; 32], pub nonce: [u8; 12], pub ct: Vec<u8> }

pub fn envelope_seal(tk_master: &[u8; 32], nc: &[u8; 32], plaintext: &[u8]) -> Envelope {
    let mut ns = [0u8; 32]; fill_random(&mut ns);
    let sk = envelope_session_key(tk_master, nc, &ns);
    let mut nonce = [0u8; 12]; fill_random(&mut nonce);
    let mut aad = Vec::with_capacity(64); aad.extend_from_slice(nc); aad.extend_from_slice(&ns);
    let ct = aead_seal(&sk, &nonce, plaintext, &aad);
    Envelope { ns, nonce, ct }
}

pub fn envelope_open(tk_master: &[u8; 32], nc: &[u8; 32], ns: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>, HyError> {
    let sk = envelope_session_key(tk_master, nc, ns);
    let mut aad = Vec::with_capacity(64); aad.extend_from_slice(nc); aad.extend_from_slice(ns);
    aead_open(&sk, nonce, ct, &aad)
}

// ---------- Ed25519 ----------

pub fn ed25519_sign(sk_bytes: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let vk = SigningKey::from_bytes(sk_bytes);
    vk.sign(msg).to_bytes()
}

pub fn ed25519_verify(pk_bytes: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), HyError> {
    let vk = VerifyingKey::from_bytes(pk_bytes).map_err(|_| HyError::Sig)?;
    let s = Signature::from_slice(sig).map_err(|_| HyError::Sig)?;
    vk.verify(msg, &s).map_err(|_| HyError::Sig)
}

pub fn ed25519_keypair(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let sgn = SigningKey::from_bytes(seed);
    (sgn.verifying_key().to_bytes(), *seed)
}

// ---------- 杂项 ----------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn fill_random(buf: &mut [u8]) {
    use rand_core::RngCore;
    use rand_core::OsRng;
    OsRng.fill_bytes(buf);
}

pub fn wipe(buf: &mut [u8]) { buf.zeroize(); }

/// 原始 HKDF-SHA256 展开（供 verifier/payload-nonce 等复用）
pub fn hkdf_sha256_raw(ikm: &[u8; 32], info: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = vec![0u8; 32];
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn hex_decode_into(s: &str, out: &mut [u8]) -> Result<(), ()> {
    let b = s.as_bytes();
    if b.len() != out.len() * 2 { return Err(()); }
    for (i, o) in out.iter_mut().enumerate() {
        let hi = (b[i * 2] as char).to_digit(16).ok_or(())?;
        let lo = (b[i * 2 + 1] as char).to_digit(16).ok_or(())?;
        *o = ((hi << 4) | lo) as u8;
    }
    Ok(())
}

// ============================ 测试 ============================

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> [u8; 32] {
        let mut r = [0u8; 32];
        fill_random(&mut r);
        r
    }

    #[test]
    fn kek_epoch_chain_differs_per_layer_and_epoch() {
        let r = root();
        assert_ne!(kek_sys(&r, 1), kek_app(&r, 1));
        assert_ne!(kek_sys(&r, 1), kek_sys(&r, 2));
        assert_eq!(kek_sys(&r, 3), kek_sys(&r, 3));
    }

    #[test]
    fn wrap_roundtrip_and_wrong_kek_fails() {
        let r = root();
        let dek = { let mut d = [0u8; 32]; fill_random(&mut d); d };
        let blob = wrap_dek(&kek_sys(&r, 1), 1, &dek);
        let ok = unwrap_dek(&kek_sys(&r, 1), 1, &blob).unwrap();
        assert_eq!(ok, dek);
        assert!(unwrap_dek(&kek_sys(&r, 2), 2, &blob).is_err());
        let mut bad = blob; bad[20] ^= 1;
        assert!(unwrap_dek(&kek_sys(&r, 1), 1, &bad).is_err());
    }

    #[test]
    fn slot_roundtrip_select_and_tamper() {
        let r = root();
        let dek = { let mut d = [0u8; 32]; fill_random(&mut d); d };
        let ck = { let mut c = [0u8; 32]; fill_random(&mut c); c };
        let h1 = SlotHeader { slot_id: 0, seq: 1, epoch: 1, img_sha256: [7u8; 32], payload_len: 4096 };
        let a = h1.encode(&kek_sys(&r, 1), &dek, &ck);
        let (h, wrap) = select_slot(Some(&a), None, |e| kek_sys(&r, e), &ck).unwrap();
        assert_eq!(h.seq, 1);
        assert_eq!(unwrap_dek(&kek_sys(&r, h.epoch), h.epoch, &wrap).unwrap(), dek);

        let h2 = SlotHeader { slot_id: 1, seq: 2, epoch: 1, img_sha256: [7u8; 32], payload_len: 4096 };
        let b = h2.encode(&kek_sys(&r, 1), &dek, &ck);
        let (h, _) = select_slot(Some(&a), Some(&b), |e| kek_sys(&r, e), &ck).unwrap();
        assert_eq!(h.seq, 2);

        let mut b_bad = b; b_bad[200] ^= 0x80;
        let (h, _) = select_slot(Some(&a), Some(&b_bad), |e| kek_sys(&r, e), &ck).unwrap();
        // ck 错误 → mac 失败 → 两槽均无效
        let ck_bad = { let mut c = [0u8; 32]; fill_random(&mut c); c };
        assert!(select_slot(Some(&a), None, |e| kek_sys(&r, e), &ck_bad).is_err());
        assert_eq!(h.seq, 1);

        // 篡改头字段（slot_id）→ DEK-MAC 失败
        let mut a_bad = a; a_bad[8] = 0xEE;
        let mut b_bad2 = b; b_bad2[17] ^= 1;
        assert!(select_slot(Some(&a_bad), Some(&b_bad2), |e| kek_sys(&r, e), &ck).is_err());
    }

    #[test]
    fn envelope_roundtrip_and_wrong_tk_fails() {
        let tk = root();
        let nc = { let mut n = [0u8; 32]; fill_random(&mut n); n };
        let env = envelope_seal(&tk, &nc, b"wrap(WK0[5],DEK1)");
        let pt = envelope_open(&tk, &nc, &env.ns, &env.nonce, &env.ct).unwrap();
        assert_eq!(pt, b"wrap(WK0[5],DEK1)");
        let tk2 = root();
        assert!(envelope_open(&tk2, &nc, &env.ns, &env.nonce, &env.ct).is_err());
        let nc2 = { let mut n = [0u8; 32]; fill_random(&mut n); n };
        assert!(envelope_open(&tk, &nc2, &env.ns, &env.nonce, &env.ct).is_err());
    }

    #[test]
    fn ed25519_sign_verify() {
        let seed = root();
        let (pk, sk) = ed25519_keypair(&seed);
        let msg = b"did|epoch|grub_ver|nc";
        let sig = ed25519_sign(&sk, msg);
        assert!(ed25519_verify(&pk, msg, &sig).is_ok());
        let mut bad = sig; bad[0] ^= 1;
        assert!(ed25519_verify(&pk, msg, &bad).is_err());
        let mut m2 = *msg; m2[0] ^= 1;
        assert!(ed25519_verify(&pk, &m2, &sig).is_err());
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}