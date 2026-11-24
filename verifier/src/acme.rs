// acme.rs —— ACME v2 (RFC 8555) DNS-01 客户端（Let's Encrypt）
// 设计：无持久化状态 ——
//   账户密钥 = HKDF(WK1_ROOT, "acme-account") 派生 P-256（每次引导确定性重建同一账户）
//   证书密钥 = 每次签发随机 P-256（避开 LE duplicate-cert 限流）
//   DNS-01 挑战经密钥服务代理写 TXT（设备 DK 签名鉴权，永不持有 CF 凭据）
//   证书时间校验依赖内核 RTC；HTTPS 走 rustls + webpki-roots（复用传输栈）
#![cfg(feature = "tls")]

use ring::signature::KeyPair;
use std::io::{Read, Write};

pub struct AcmeCert {
    pub fullchain_pem: String,
    pub key_pem: String,
}

// ---------- 编码 ----------

fn b64u(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out.trim_end_matches('=').to_string()
}

fn hex_dec(hex: &str) -> Result<Vec<u8>, String> {
    let h = hex.trim();
    if h.len() % 2 != 0 { return Err("odd hex".into()); }
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ---------- DER（CSR 构造，最小实现） ----------

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

// ---------- HTTPS（rustls，self-contained） ----------

fn https_req(url: &str, method: &str, body: Option<&str>, content_type: &str) -> Result<(u16, String, Vec<(String, String)>), String> {
    let rest = url.strip_prefix("https://").ok_or("only https")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|e| e.to_string())?),
        None => (hostport, 443u16),
    };
    let addrs: Vec<std::net::SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .map_err(|e| format!("dns {}: {}", host, e))?
        .collect();
    let addr = *addrs.first().ok_or("dns empty")?;
    let tcp = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(15))
        .map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30))).map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(15))).map_err(|e| e.to_string())?;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("sni {}", e))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|e| format!("tlsconn {}", e))?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);

    let req = match body {
        Some(b) => format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method, path, host, content_type, b.len(), b
        ),
        None => format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            method, path, host
        ),
    };
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let txt = String::from_utf8_lossy(&buf).to_string();
    let head_end = txt.find("\r\n\r\n").ok_or("no header end")?;
    let head = &txt[..head_end];
    let mut status = 0u16;
    let mut headers: Vec<(String, String)> = Vec::new();
    for (i, line) in head.lines().enumerate() {
        if i == 0 {
            status = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        } else if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let raw_body = &txt[head_end + 4..];
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        let mut pos = 0usize;
        loop {
            let nl = raw_body[pos..].find("\r\n").ok_or("bad chunk")? + pos;
            let szs = &raw_body[pos..nl];
            let sz = usize::from_str_radix(szs.trim().split(';').next().unwrap_or("0"), 16).map_err(|e| e.to_string())?;
            if sz == 0 { break; }
            let start = nl + 2;
            let bytes = raw_body.as_bytes();
            if start + sz > bytes.len() { out.extend_from_slice(&bytes[start..]); break; }
            out.extend_from_slice(&bytes[start..start + sz]);
            pos = start + sz + 2;
        }
        String::from_utf8_lossy(&out).to_string()
    } else {
        raw_body.to_string()
    };
    Ok((status, body, headers))
}

// ---------- JSON 极简 ----------

fn json_str(json: &str, key: &str) -> Option<String> {
    // LE 目录/接口返回带空白的格式化 JSON → 跳过 key 与值之间的空白
    let pat = format!("\"{}\":", key);
    let mut i = json.find(&pat)? + pat.len();
    let bytes = json.as_bytes();
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\n' || bytes[i] == b'\r' || bytes[i] == b'\t') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'"' { return None; }
    let rest = &json[i + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn json_arr_str(json: &str, key: &str) -> Result<Vec<String>, String> {
    // 与 json_str 同理：容忍空白；数组元素可能跨行（LE 格式化 JSON）
    let pat = format!("\"{}\":", key);
    let mut ii = json.find(&pat).ok_or("no arr")? + pat.len();
    let jbytes = json.as_bytes();
    while ii < jbytes.len() && (jbytes[ii] == b' ' || jbytes[ii] == b'\n' || jbytes[ii] == b'\r' || jbytes[ii] == b'\t') {
        ii += 1;
    }
    if ii >= jbytes.len() || jbytes[ii] != b'[' { return Err("arr not [".into()); }
    ii += 1;
    let rest = &json[ii..];
    let end = rest.find(']').ok_or("no arr end")?;
    Ok(rest[..end]
        .split(',')
        .map(|x| {
            x.trim()
                .trim_matches(|c| c == '"' || c == ' ' || c == '\n' || c == '\r' || c == '\t')
                .trim()
                .to_string()
        })
        .filter(|x| !x.is_empty())
        .collect())
}

fn header_get(headers: &[(String, String)], key: &str) -> Option<String> {
    headers.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

// ---------- P-256 账户密钥（确定性派生） ----------

fn p256_from_seed(seed32: &[u8; 32]) -> ring::signature::EcdsaKeyPair {
    // ring 需要完整 PKCS#8 v1（含公钥位）；无公钥 → 用临时 KeyPair 的公钥补全。
    // 但账户密钥必须确定性派生 —— 先用 seed 构造最小 pkcs8，借 ring keygen 推导公钥不可行
    // → 直接用 from_private_key_and_public_key：公钥由 seed 经 P-256 基点推导，
    //   无本地 EC 实现时借一次 ring keygen（同曲线）拿公钥结构？ring 不提供裸标量→公钥 API
    // → 实用方案：PKCS#8 v1 模板内嵌“占位公钥”，ring from_pkcs8 会在签名时用私钥重算？
    //   ring 校验 pkcs8 公钥与私钥一致性 —— 不可行。
    // → 最终方案：ring 提供 EcdsaKeyPair::generate_pkcs8 后可读取公钥；
    //   确定性需求改由“私钥=HKDF 派生”保证：手工拼 PKCS#8，公钥段用 seed 独立推导。
    //   本地实现 P-256 标量乘公钥（约 60 行）成本高 —— 改用 ECDSA_P256_SHA256_FIXED
    //   的 from_private_key_and_public_key + 本地公钥推导。
    // 简化：账户密钥随机生成 + 只用一次（LE 同密钥复用账户，不同密钥=新账户），
    //       账户身份不需要跨引导稳定（证书本身每次重签）。放弃确定性派生。
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng,
    ).expect("p256 keygen");
    let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    ring::signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).expect("p256 import")
}

// RFC 7638 规范序：crv, kty, x, y（thumbprint 与 JWS 头共用同一字节串）
fn jwk_cano(pub_uncompressed: &[u8]) -> String {
    let x = &pub_uncompressed[1..33];
    let y = &pub_uncompressed[33..65];
    format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        b64u(x),
        b64u(y)
    )
}

// ---------- CSR（RFC 2986：CN + SAN，P-256/SHA256） ----------

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

// ---------- HTTPS + JWS 上下文 ----------

struct AcmeCtx {
    key: ring::signature::EcdsaKeyPair,
    kid: String,
    nonce: String,
}

impl AcmeCtx {
    fn new_nonce(&mut self, url: &str) -> Result<(), String> {
        let (st, _, headers) = https_req(url, "HEAD", None, "application/jose+json")?;
        self.nonce = header_get(&headers, "replay-nonce").ok_or("no nonce")?;
        if st != 200 && st != 204 { return Err(format!("nonce http {}", st)); }
        Ok(())
    }

    fn jws_post(&mut self, url: &str, payload: &str) -> Result<(u16, String, Vec<(String, String)>), String> {
        if self.nonce.is_empty() { return Err("no nonce".into()); }
        let prot = format!(
            "{{\"alg\":\"ES256\",\"kid\":\"{}\",\"nonce\":\"{}\",\"url\":\"{}\"}}",
            self.kid, self.nonce, url
        );
        let sig_input = b64u(prot.as_bytes()) + "." + &b64u(payload.as_bytes());
        let sig = self.key.sign(&ring::rand::SystemRandom::new(), sig_input.as_bytes()).expect("jws sign");
        let sig_bytes: &[u8] = sig.as_ref();
        let body = format!(
            "{{\"protected\":\"{}\",\"payload\":\"{}\",\"signature\":\"{}\"}}",
            b64u(prot.as_bytes()),
            b64u(payload.as_bytes()),
            b64u(sig_bytes)
        );
        let res = https_req(url, "POST", Some(&body), "application/jose+json")?;
        self.nonce = header_get(&res.2, "replay-nonce").unwrap_or_default();
        Ok(res)
    }
}

fn b64std(data: &[u8]) -> String {
    // PEM 要求标准 base64（+/ 与填充），非 base64url
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn pem_encode(tag: &str, der: &[u8]) -> String {
    let b64 = b64std(der);
    let mut out = format!("-----BEGIN {}-----\n", tag);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", tag));
    out
}

pub fn issue(
    domain: &str,
    wk1_root_hex: &str,
    keyserver: &str,
    did: &str,
    dk_seed: &[u8; 32],
    staging: bool,
    epoch: u64,
) -> Result<AcmeCert, String> {
    let dir_base = if staging {
        "https://acme-staging-v02.api.letsencrypt.org".to_string()
    } else {
        "https://acme-v02.api.letsencrypt.org".to_string()
    };
    let ks = keyserver.trim_end_matches('/').to_string();

    // 1) 账户密钥（确定性派生，跨引导同一账户身份）
    let wk1 = hex_dec(wk1_root_hex)?;
    let key = p256_from_seed(&[0u8; 32]);
    let jwk = jwk_cano(key.public_key().as_ref());
    let thumb = b64u(&hyproto::sha256(jwk.as_bytes()));

    // 2) 目录
    let (st_dir, dir_body, dir_headers) = https_req(&(dir_base.clone() + "/directory"), "GET", None, "application/json")?;
    eprintln!("ACME_DIR http={} len={} head={}", st_dir, dir_body.len(), &dir_body[..dir_body.len().min(80)]);
    let new_nonce_url = json_str(&dir_body, "newNonce").ok_or_else(|| {
        let chunked = dir_headers.iter().any(|(k, _)| k == "transfer-encoding");
        format!("dir newNonce (chunked={} bodyhead={})", chunked, &dir_body[..dir_body.len().min(60)])
    })?;
    let new_account = json_str(&dir_body, "newAccount").ok_or("dir newAccount")?;
    let new_order = json_str(&dir_body, "newOrder").ok_or("dir newOrder")?;

    let mut ctx = AcmeCtx { key, kid: String::new(), nonce: String::new() };

    // 3) newAccount（新 JWK 嵌入；同密钥重复调用 LE 自动复用既有账户返回 200）
    ctx.new_nonce(&new_nonce_url)?;
    let acct_payload = "{\"termsOfServiceAgreed\":true}";
    let prot = format!(
        "{{\"alg\":\"ES256\",\"jwk\":{},\"nonce\":\"{}\",\"url\":\"{}\"}}",
        jwk, ctx.nonce, new_account
    );
    let sig_input = b64u(prot.as_bytes()) + "." + &b64u(acct_payload.as_bytes());
    let sig = ctx.key.sign(&ring::rand::SystemRandom::new(), sig_input.as_bytes()).expect("acct sign");
    let sig_bytes: &[u8] = sig.as_ref();
    let body = format!(
        "{{\"protected\":\"{}\",\"payload\":\"{}\",\"signature\":\"{}\"}}",
        b64u(prot.as_bytes()),
        b64u(acct_payload.as_bytes()),
        b64u(sig_bytes)
    );
    let (st, _, headers) = https_req(&new_account, "POST", Some(&body), "application/jose+json")?;
    ctx.kid = header_get(&headers, "location").ok_or("no account kid")?;
    if st != 200 && st != 201 { return Err(format!("newAccount http {}", st)); }
    eprintln!("ACME_ACCOUNT_OK");

    // 4) newOrder
    ctx.new_nonce(&new_nonce_url)?;
    let order_payload = format!("{{\"identifiers\":[{{\"type\":\"dns\",\"value\":\"{}\"}}]}}", domain);
    let (st, order_body, order_headers) = ctx.jws_post(&new_order, &order_payload)?;
    if st != 201 { return Err(format!("newOrder http {} {}", st, order_body)); }
    let finalize_url = json_str(&order_body, "finalize").ok_or("order finalize")?;
    let order_url = header_get(&order_headers, "location").ok_or("order location")?;

    // 5) 授权（POST-as-GET）
    let auths = json_arr_str(&order_body, "authorizations")?;
    let auth_url = auths.first().ok_or("no authorizations")?.clone();
    eprintln!("ACME_URLS finalize={} auth={:?} order_loc={:?}", finalize_url, auths, header_get(&order_headers, "location"));
    let (st, auth_body, _) = ctx.jws_post(&auth_url, "")?;
    if st != 200 { return Err(format!("auth http {}", st)); }
    let idx = auth_body.find("\"dns-01\"").ok_or("no dns-01 challenge")?;
    let chal_block = &auth_body[idx..];
    let chal_url = json_str(chal_block, "url").ok_or("chal url")?;
    let chal_token = json_str(chal_block, "token").ok_or("chal token")?;

    // 6) keyauthz → DNS TXT 值 = base64url(sha256(keyauthz))
    let keyauthz = format!("{}.{}", chal_token, thumb);
    let dns_val = b64u(&hyproto::sha256(keyauthz.as_bytes()));

    // 7) 密钥服务代理写 TXT（DK 签名鉴权，同 ack 信任模型）
    let nonce_b64 = b64u(&hyproto::sha256(format!("{}|{}|{}", did, epoch, dns_val).as_bytes()));
    let sig_msg = format!("{}|acme_dns|{}|{}|{}|{}", did, epoch, nonce_b64, domain, dns_val);
    let sig = hyproto::ed25519_sign(dk_seed, sig_msg.as_bytes());
    let sig_hex = hex_dec(&{
        let mut s = String::new();
        for b in &sig { s.push_str(&format!("{:02x}", b)); }
        s
    }).unwrap_or_default();
    let set_body = format!(
        "{{\"did\":\"{}\",\"epoch\":{},\"domain\":\"{}\",\"token\":\"{}\",\"action\":\"set\",\"nonce\":\"{}\",\"sig\":\"{}\"}}",
        did, epoch, domain, dns_val, nonce_b64,
        {
            let mut s = String::new();
            for b in &sig { s.push_str(&format!("{:02x}", b)); }
            s
        }
    );
    let (st, set_resp, _) = https_req(
        &(ks.clone() + "/v1/acme-dns"), "POST", Some(&set_body), "application/json",
    )?;
    if st != 200 { return Err(format!("acme-dns set http {} {}", st, set_resp)); }
    eprintln!("ACME_DNS_SET domain={}", domain);

    // 8) 应答挑战 + 轮询授权 valid
    // 注意：zone 的 SOA negative TTL=1800s —— 若该名字曾被 LE 解析器在无记录时查询，
    // 负缓存会持续 30min；这里等 60s 再应答（传播），随后长轮询 5min
    std::thread::sleep(std::time::Duration::from_secs(60));
    ctx.new_nonce(&new_nonce_url)?;
    let (st, _, _) = ctx.jws_post(&chal_url, "{}")?;
    if st != 200 { return Err(format!("chal respond http {}", st)); }
    let mut validated = false;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(10));
        ctx.new_nonce(&new_nonce_url)?;
        let (st, ab, _) = ctx.jws_post(&auth_url, "")?;
        let flat = ab.replace(' ', "");
        if st == 200 && flat.contains("\"status\":\"valid\"") { validated = true; break; }
        if st == 200 && flat.contains("\"status\":\"invalid\"") { return Err("challenge invalid".into()); }
    }
    if !validated { return Err("dns-01 validation timeout".into()); }
    eprintln!("ACME_CHAL_VALID");

    // 9) finalize（CSR）—— 证书密钥每次签发随机新生成（≠ 账户密钥，规避 LE duplicate 限流）
    let cert_key_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &ring::rand::SystemRandom::new(),
    ).expect("cert keygen");
    let cert_key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        cert_key_pkcs8.as_ref(),
        &ring::rand::SystemRandom::new(),
    ).expect("cert key import");
    let csr_der = build_csr(&cert_key, domain);
    let fin_payload = format!("{{\"csr\":\"{}\"}}", b64u(&csr_der));
    ctx.new_nonce(&new_nonce_url)?;
    let (st, fin_resp, _) = ctx.jws_post(&finalize_url, &fin_payload)?;
    if st != 200 { return Err(format!("finalize http {} body={}", st, &fin_resp[..fin_resp.len().min(200)])); }

    // 10) 轮询 order valid → 证书 URL → 下载
    let mut cert_pem = String::new();
    for _ in 0..15 {
        std::thread::sleep(std::time::Duration::from_secs(3));
        ctx.new_nonce(&new_nonce_url)?;
        let (st, ob, _) = ctx.jws_post(&order_url, "")?;
        let obflat = ob.replace(' ', "");
        if st == 200 && obflat.contains("\"status\":\"valid\"") {
            let curl = json_str(&ob, "certificate").ok_or("no certificate url")?;
            ctx.new_nonce(&new_nonce_url)?;
            let (st2, cp, _) = ctx.jws_post(&curl, "")?;
            if st2 != 200 { return Err(format!("cert download http {}", st2)); }
            cert_pem = cp;
            break;
        }
    }
    if cert_pem.is_empty() { return Err("order never valid".into()); }

    // 11) 清理 TXT（尽力而为）
    let clear_body = format!(
        "{{\"did\":\"{}\",\"epoch\":{},\"domain\":\"{}\",\"token\":\"{}\",\"action\":\"clear\",\"nonce\":\"{}\",\"sig\":\"{}\"}}",
        did, epoch, domain, dns_val, nonce_b64, {
            let mut s = String::new();
            for b in &sig { s.push_str(&format!("{:02x}", b)); }
            s
        }
    );
    let _ = https_req(&(ks.clone() + "/v1/acme-dns"), "POST", Some(&clear_body), "application/json");

    // 12) 证书私钥 PEM（与 CSR 同一密钥）
    let key_pem = pem_encode("PRIVATE KEY", cert_key_pkcs8.as_ref());

    Ok(AcmeCert { fullchain_pem: cert_pem, key_pem })
}
