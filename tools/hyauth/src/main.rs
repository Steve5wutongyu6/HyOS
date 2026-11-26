// hyauth —— Hysteria2 HTTP 认证后端（Rust 重写，替代原 hysteria-auth-server.py）
// 语义与 Python 版一致：POST /auth {auth: SECRET} → {"ok":true,"id":AUTH_ID} / {"ok":false}
// 监听 127.0.0.1:18080；机密经环境变量 HYSTERIA_AUTH_SECRET / HYSTERIA_AUTH_ID 注入
use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    let secret = std::env::var("HYSTERIA_AUTH_SECRET").expect("HYSTERIA_AUTH_SECRET");
    let auth_id = std::env::var("HYSTERIA_AUTH_ID").unwrap_or_else(|_| "default".into());
    // 监听地址来自 HysteriaConfig（auth.listen，经 auth.env → 环境变量），平台侧不内置默认
    let listen = std::env::var("HYSTERIA_AUTH_LISTEN").unwrap_or_default();
    if listen.is_empty() {
        eprintln!("HYAUTH_ERR 缺少 HYSTERIA_AUTH_LISTEN");
        std::process::exit(2);
    }
    let listener = TcpListener::bind(&listen).expect("bind auth listen");
    eprintln!("HYAUTH_READY {} id={}", listen, auth_id);
    for stream in listener.incoming() {
        let mut s = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let secret = secret.clone();
        let auth_id = auth_id.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            // 读请求头（逐步直到 \r\n\r\n；请求体很小，一次读足够）
            let mut tmp = [0u8; 4096];
            let mut header_end = None;
            loop {
                match s.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(p) = find_header_end(&buf) {
                            header_end = Some(p);
                            break;
                        }
                        if buf.len() > 65536 {
                            break;
                        }
                    }
                }
            }
            let head_end = match header_end.or_else(|| find_header_end(&buf)) {
                Some(p) => p,
                None => return,
            };
            // Content-Length
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let clen: usize = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let body_start = head_end + 4;
            while buf.len() < body_start + clen {
                match s.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let body = &buf[body_start..(body_start + clen).min(buf.len())];
            // 极简 JSON 字段提取："auth":"..."
            let ext = extract_json_str(body, "auth").or_else(|| extract_json_str_unquoted(body, "auth"));
            eprintln!("HYAUTH_REQ body={} ext={:?}", String::from_utf8_lossy(body), ext);
            let ok = ext.map(|a| a == secret).unwrap_or(false);
            let resp_body = if ok {
                format!("{{\"ok\":true,\"id\":\"{}\"}}", json_escape(&auth_id))
            } else {
                "{\"ok\":false}".to_string()
            };
            // 请求行路径校验（非 /auth 一律 404 语义，但按 Python 版行为：也回 JSON）
            let path_ok = head.split_whitespace().nth(1).map(|p| p == "/auth").unwrap_or(false);
            let http_status = if path_ok { "200 OK" } else { "404 Not Found" };
            let resp = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                http_status,
                resp_body.len(),
                resp_body
            );
            let _ = s.write_all(resp.as_bytes());
        });
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn extract_json_str(body: &[u8], key: &str) -> Option<String> {
    // 匹配 "key":"value"（值不含未转义引号）
    let pat = format!("\"{}\":\"", key);
    let text = String::from_utf8_lossy(body);
    let i = text.find(&pat)? + pat.len();
    let rest = &text[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_json_str_unquoted(body: &[u8], key: &str) -> Option<String> {
    let pat = format!("\"{}\":", key);
    let text = String::from_utf8_lossy(body);
    let i = text.find(&pat)? + pat.len();
    let rest = &text[i..];
    let end = rest.find(|c| c == ',' || c == '}')?;
    Some(rest[..end].trim().to_string())
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
