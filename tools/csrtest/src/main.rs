use ring::signature::KeyPair;
use std::io::Write;

fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 { out.push(n as u8); }
    else if n < 0x100 { out.push(0x81); out.push(n as u8); }
    else { out.push(0x82); out.push((n >> 8) as u8); out.push((n & 0xff) as u8); }
}

fn der_seq(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x30];
    der_len(payload.len(), &mut v);
    v.extend_from_slice(payload);
    v
}

fn der_set(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x31];
    der_len(payload.len(), &mut v);
    v.extend_from_slice(payload);
    v
}

fn der_oid(oid: &[u8]) -> Vec<u8> {
    let mut v = vec![0x06];
    der_len(oid.len(), &mut v);
    v.extend_from_slice(oid);
    v
}

fn der_int_small(n: u8) -> Vec<u8> { vec![0x02, 0x01, n] }

fn der_bitstring(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x03];
    der_len(data.len() + 1, &mut v);
    v.push(0);
    v.extend_from_slice(data);
    v
}

fn der_octet(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04];
    der_len(payload.len(), &mut v);
    v.extend_from_slice(payload);
    v
}

fn der_utf8(s: &str) -> Vec<u8> {
    let mut v = vec![0x0c];
    der_len(s.len(), &mut v);
    v.extend_from_slice(s.as_bytes());
    v
}

fn der_ctx_n(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut inner = vec![0xa0 + tag];
    der_len(payload.len(), &mut inner);
    inner.extend_from_slice(payload);
    inner
}

// ECDSA 签名：ring 输出 r||s（64B）→ DER SEQUENCE { INTEGER r, INTEGER s }
fn ecdsa_sig_der(sig: &[u8]) -> Vec<u8> {
    let trim = |x: &[u8]| -> Vec<u8> {
        let mut i = 0;
        while i < x.len() - 1 && x[i] == 0 { i += 1; }
        let mut v = x[i..].to_vec();
        if v[0] & 0x80 != 0 { v.insert(0, 0); }
        v
    };
    let (r, s) = sig.split_at(32);
    let mut ints = Vec::new();
    for part in [trim(r), trim(s)] {
        let mut it = vec![0x02];
        der_len(part.len(), &mut it);
        it.extend_from_slice(&part);
        ints.extend_from_slice(&it);
    }
    der_seq(&ints)
}


fn build_csr(key: &ring::signature::EcdsaKeyPair, domain: &str) -> Vec<u8> {
    let pub_bit = key.public_key().as_ref();
    // SubjectPublicKeyInfo: SEQ { SEQ { OID id-ecPublicKey(1.2.840.10045.2.1), OID prime256v1(1.2.840.10045.3.1.7) }, BITSTRING }
    let mut alg_inner = der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    alg_inner.extend_from_slice(&der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]));
    let alg_seq = der_seq(&alg_inner);
    let spki = der_seq(&[alg_seq, der_bitstring(pub_bit)].concat());
    // Subject: CN=domain —— SEQ { SET { SEQ { OID(2.5.4.3 CN), UTF8String } } }
    let mut atv = der_oid(&[0x55, 0x04, 0x03]);
    atv.extend_from_slice(&der_utf8(domain));
    let subject = der_seq(&der_set(&der_seq(&atv)));
    // SAN: GeneralNames = [2] dNSName (0x82 primitive IA5String)
    let mut dns = vec![0x82];
    der_len(domain.len(), &mut dns);
    dns.extend_from_slice(domain.as_bytes());
    // SAN 扩展：Extension = SEQ { OID(2.5.29.17 subjectAltName), OCTET { SEQ { dNSName } } }
    let mut san_ext_body = der_oid(&[0x55, 0x1d, 0x11]);
    san_ext_body.extend_from_slice(&der_octet(&der_seq(&dns)));
    let san_ext = der_seq(&san_ext_body); // Extension = SEQ { OID, OCTET }
    let extensions = der_seq(&san_ext);   // Extensions = SEQ { Extension }
    // PKCS#9 extensionRequest 属性：OID(1.2.840.113549.1.9.14) + SET { OCTET(Extensions) }
    let mut attr = der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]);
    // RFC 2986 字面值是 SET{OCTET}，但 OpenSSL/Go 事实标准为 SET{Extensions-SEQ}（无 OCTET 包装）
    attr.extend_from_slice(&der_set(&extensions));
    let attrs = der_ctx_n(0, &der_seq(&attr));
    // CertificationRequestInfo
    let mut cri = der_int_small(0);
    cri.extend_from_slice(&subject);
    cri.extend_from_slice(&spki);
    cri.extend_from_slice(&attrs);
    let cri = der_seq(&cri);
    let sig_raw = key.sign(&ring::rand::SystemRandom::new(), &cri).expect("csr sign");
    let mut cr = cri;
    // 签名算法：ecdsa-with-SHA256(1.2.840.10045.4.3.2)
    cr.extend_from_slice(&der_seq(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
    cr.extend_from_slice(&der_bitstring(&ecdsa_sig_der(sig_raw.as_ref())));
    der_seq(&cr)
}



fn main() {
    let key = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &ring::rand::SystemRandom::new(),
    ).expect("keygen");
    let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(alg, key.as_ref(), &ring::rand::SystemRandom::new()).expect("import");
    let csr = build_csr(&kp, "oa.nanachi.cloud");
    let mut hexs = String::new();
    for b in &csr { hexs.push_str(&format!("{:02x}", b)); }
    std::io::stdout().write_all(hexs.as_bytes()).unwrap();
    println!();
}
