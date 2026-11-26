//! HyOS initramfs verifier (PID1) + app supervisor
//! Same binary: no args = verifier (init); argv[1]=="supervise" = supervisor.
//! Static linked (x86_64 gnu + crt-static), no shell dependency.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;

mod genkeys;
#[cfg(feature = "tls")]
mod acme;

use hyproto::{
    aead_open, ed25519_verify, hmac32, kek_app, select_slot, unwrap_dek,
    HyError, WRAP_LEN,
};
const P2_START: u64 = 4096;
const P3_START: u64 = 36864;
const PAYLOAD_OFF: u64 = 8;
const SECTOR: u64 = 512;

fn cmdline() -> BTreeMap<String, String> {
    let raw = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let mut m = BTreeMap::new();
    for tok in raw.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            m.insert(k.to_string(), v.to_string());
        } else {
            m.insert(tok.to_string(), String::new());
        }
    }
    m
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::new();
    for c in s.bytes() {
        if c == b'=' { break; }
        let v = T.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn b64url_encode(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for byte in b {
        acc = (acc << 8) | *byte as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(T[((acc >> bits) & 63) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(T[((acc << (6 - bits)) & 63) as usize] as char);
    }
    out
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_decode_into(s: &str, out: &mut [u8]) -> Result<(), ()> {
    let b = s.as_bytes();
    if b.len() != out.len() * 2 { return Err(()); }
    for (i, o) in out.iter_mut().enumerate() {
        let hi = (b[i * 2] as char).to_digit(16).ok_or(())?;
        let lo = (b[i * 2 + 1] as char).to_digit(16).ok_or(())?;
        *o = ((hi << 4) | lo) as u8;
    }
    Ok(())
}

fn json_str<'a>(j: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{}\":\"", key);
    let i = j.find(&pat)? + pat.len();
    let rest = &j[i..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn mounts() {
    let _ = std::fs::create_dir_all("/proc");
    let _ = std::fs::create_dir_all("/sys");
    let _ = std::fs::create_dir_all("/dev");
    unsafe {
        libc::mount(
            b"proc\0".as_ptr() as *const libc::c_char,
            b"/proc\0".as_ptr() as *const libc::c_char,
            b"proc\0".as_ptr() as *const libc::c_char,
            0, std::ptr::null_mut(),
        );
        libc::mount(
            b"sysfs\0".as_ptr() as *const libc::c_char,
            b"/sys\0".as_ptr() as *const libc::c_char,
            b"sysfs\0".as_ptr() as *const libc::c_char,
            0, std::ptr::null_mut(),
        );
        libc::mount(
            b"devtmpfs\0".as_ptr() as *const libc::c_char,
            b"/dev\0".as_ptr() as *const libc::c_char,
            b"devtmpfs\0".as_ptr() as *const libc::c_char,
            0, std::ptr::null_mut(),
        );
    }
}


fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<Option<u8>> = s.trim().split('.').map(|p| p.parse().ok()).collect();
    if parts.len() != 4 || parts.iter().any(|p| p.is_none()) {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.unwrap();
    }
    Some(out)
}

/// 获取网卡 ifindex（ioctl SIOCGIFINDEX）
fn ifindex_of(name: &str) -> Option<u32> {
    // sysfs 读取（SIOCGIFINDEX 在 hyinit 环境不可用）
    let path = format!("/sys/class/net/{}/ifindex", name);
    let s = std::fs::read_to_string(&path).ok()?;
    s.trim().parse::<u32>().ok()
}

/// 默认路由：netlink RTM_NEWROUTE + RTNH_F_ONLINK + RTA_OIF
/// （ioctl SIOCADDRT 路径在本内核配置下 fib_check_nh 网关查找返回 ENETUNREACH，
///   ONLINK 分支仅要求设备 up + 地址类型检查，iproute2 等价行为）
fn route_add_default_via(name: &str, gw: [u8; 4]) -> i32 {
    use std::os::fd::RawFd;
    const NLM_F_REQUEST: u16 = 0x0001;
    const NLM_F_ACK: u16 = 0x0004;
    const NLM_F_CREATE: u16 = 0x0400;
    const NLM_F_EXCL: u16 = 0x0200;
    const RTM_NEWROUTE: u16 = 24;
    const NLMSG_ERROR: u16 = 2;
    const RTA_DST: u16 = 1;
    const RTA_OIF: u16 = 4;
    const RTA_GATEWAY: u16 = 5;
    const RTNH_F_ONLINK: u32 = 4;
    const RT_SCOPE_UNIVERSE: u8 = 0;
    const RT_TABLE_MAIN: u8 = 254;
    const RTPROT_STATIC: u8 = 4;
    const RTN_UNICAST: u8 = 1;

    let ifidx = match ifindex_of(name) {
        Some(v) => v,
        None => return -19,
    };

    let mut msg: Vec<u8> = Vec::with_capacity(128);
    // rtmsg（12 字节）
    msg.extend_from_slice(&[libc::AF_INET as u8, 0, 0, 0]); // family, dst_len=0(默认), src_len, tos
    msg.extend_from_slice(&[RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_UNIVERSE, RTN_UNICAST]);
    msg.extend_from_slice(&RTNH_F_ONLINK.to_ne_bytes());
    let rtmsg_len = msg.len();
    // RTA_DST 0.0.0.0
    msg.extend_from_slice(&(8u16).to_ne_bytes());
    msg.extend_from_slice(&RTA_DST.to_ne_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0]);
    // RTA_GATEWAY
    msg.extend_from_slice(&(8u16).to_ne_bytes());
    msg.extend_from_slice(&RTA_GATEWAY.to_ne_bytes());
    msg.extend_from_slice(&gw);
    // RTA_OIF
    msg.extend_from_slice(&(8u16).to_ne_bytes());
    msg.extend_from_slice(&RTA_OIF.to_ne_bytes());
    msg.extend_from_slice(&ifidx.to_ne_bytes());

    let nl_len = (16 + msg.len()) as u32;
    let mut pkt: Vec<u8> = Vec::with_capacity(nl_len as usize);
    pkt.extend_from_slice(&nl_len.to_ne_bytes());
    pkt.extend_from_slice(&RTM_NEWROUTE.to_ne_bytes());
    pkt.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL).to_ne_bytes());
    pkt.extend_from_slice(&1u32.to_ne_bytes()); // seq
    pkt.extend_from_slice(&0u32.to_ne_bytes()); // pid = kernel
    pkt.extend_from_slice(&msg);
    void_unused(rtmsg_len);

    unsafe {
        let fd: RawFd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE);
        if fd < 0 {
            return -1;
        }
        // 绑定 netlink 源（kernel 需要? sendto kernel pid=0 即可）
        let mut dst: libc::sockaddr_nl = std::mem::zeroed();
        dst.nl_family = libc::AF_NETLINK as u16;
        dst.nl_pid = 0;
        dst.nl_groups = 0;
        let sent = libc::sendto(
            fd,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        );
        if sent < 0 {
            let e = *libc::__errno_location();
            libc::close(fd);
            return e;
        }
        // 读 ACK（NLMSG_ERROR）
        let mut buf = [0u8; 256];
        let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
        libc::close(fd);
        if n < 16 {
            return if n < 0 { *libc::__errno_location() } else { -1 };
        }
        let rtype = u16::from_ne_bytes([buf[4], buf[5]]);
        if rtype != NLMSG_ERROR {
            return -1;
        }
        let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        err
    }
}

#[allow(dead_code)]
fn void_unused(_: usize) {}

/// 默认路由：ioctl SIOCADDRT（保留作诊断对照）
#[allow(dead_code)]
fn route_add_default_via_ioctl(gw: [u8; 4]) -> i32 {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            return -1;
        }
        // rtentry 字段是 sockaddr（16 字节）；sockaddr_in 在 Linux 上同为 16 字节，可直接转换
        fn sa(sin: libc::sockaddr_in) -> libc::sockaddr {
            unsafe { std::mem::transmute(sin) }
        }
        let mut rt: libc::rtentry = std::mem::zeroed();
        rt.rt_dst = sa(libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        });
        rt.rt_gateway = sa(libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: u32::from_be_bytes(gw) },
            sin_zero: [0; 8],
        });
        rt.rt_genmask = sa(libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        });
        rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
        let r = libc::ioctl(sock, libc::SIOCADDRT, &rt as *const libc::rtentry as *const libc::c_void);
        let errno = *libc::__errno_location();
        libc::close(sock);
        if r == 0 { 0 } else { errno }
    }
}

fn net_ifup(name: &str, ip: [u8; 4], mask: [u8; 4]) -> bool {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            eprintln!("IFSOCK_ERR {} errno={}", name, *libc::__errno_location());
            return false;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        let nb = name.as_bytes();
        let n = nb.len().min(15);
        for i in 0..n {
            ifr.ifr_name[i] = nb[i] as libc::c_char;
        }
        let sin_of = |ifr: &mut libc::ifreq| -> *mut libc::sockaddr_in {
            &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in
        };
        {
            let sin = sin_of(&mut ifr);
            (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
            (*sin).sin_port = 0;
            (*sin).sin_addr.s_addr = u32::from_ne_bytes(ip);
            if libc::ioctl(sock, libc::SIOCSIFADDR, &ifr) < 0 {
                eprintln!("IFADDR_ERR {} errno={}", name, *libc::__errno_location());
                libc::close(sock);
                return false;
            }
        }
        {
            let sin = sin_of(&mut ifr);
            (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
            (*sin).sin_port = 0;
            (*sin).sin_addr.s_addr = u32::from_ne_bytes(mask);
            if libc::ioctl(sock, libc::SIOCSIFNETMASK, &ifr) < 0 {
                eprintln!("IFMASK_ERR {} errno={}", name, *libc::__errno_location());
                libc::close(sock);
                return false;
            }
        }
        if libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) < 0 {
            eprintln!("IFFLAGS_GET_ERR {} errno={}", name, *libc::__errno_location());
            libc::close(sock);
            return false;
        }
        let flags = unsafe { ifr.ifr_ifru.ifru_flags };
        unsafe {
            ifr.ifr_ifru.ifru_flags = flags | (libc::IFF_UP as libc::c_short) | (libc::IFF_RUNNING as libc::c_short);
        }
        if libc::ioctl(sock, libc::SIOCSIFFLAGS, &mut ifr) < 0 {
            eprintln!("IFFLAGS_SET_ERR {} errno={}", name, *libc::__errno_location());
            libc::close(sock);
            return false;
        }
        libc::close(sock);
        true
    }
}

fn poweroff() -> ! {
    unsafe { libc::sync(); libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF); }
    loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
}

fn open_disk() -> File {
    for name in ["/dev/sda", "/dev/vda", "/dev/hda"] {
        if let Ok(f) = OpenOptions::new().read(true).write(true).open(name) {
            return f;
        }
    }
    eprintln!("HYVERIFY FAIL no root disk");
    std::process::exit(9);
}

fn read_at(f: &mut File, lba: u64, len: usize) -> std::io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(lba * SECTOR))?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_at(f: &mut File, lba: u64, data: &[u8]) -> std::io::Result<()> {
    f.seek(SeekFrom::Start(lba * SECTOR))?;
    f.write_all(data)?;
    f.sync_all()
}

fn wipe_sectors(f: &mut File, start_lba: u64, n: u64) {
    let mut junk = vec![0u8; 512];
    let mut seed = 0x9E3779B9u32;
    for i in 0..n {
        for chunk in junk.chunks_mut(4) {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            for (k, b) in chunk.iter_mut().enumerate() {
                *b = ((seed >> (k * 8)) & 0xFF) as u8;
            }
        }
        let _ = write_at(f, start_lba + i, &junk);
    }
}

fn payload_nonce(dek: &[u8; 32]) -> [u8; 12] {
    use hyproto::hkdf_sha256_raw;
    let mut info = Vec::with_capacity(13);
    info.extend_from_slice(b"payload-nonce");
    let hk = hkdf_sha256_raw(dek, &info);
    let mut n = [0u8; 12];
    n.copy_from_slice(&hk[..12]);
    n
}

/// TLS 传输开关（来自签名清单 hy_tls=1；静态二进制以 tls feature 编译支持）
static TLS_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn http_post(srv: &str, path: &str, body: &str) -> Result<(u16, String), String> {
    // srv 形如 "ip:port" 或 "ip:port@host"——@ 后为 SNI/HTTP Host 头。
    // 经 Cloudflare 边缘 IP 直连时按 Host 路由到对应域名（hyinit 无 DNS 能力）。
    let (conn, hosthdr) = match srv.split_once('@') {
        Some((c, h)) => (c, h),
        None => (srv, "hyos"),
    };
    if TLS_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        #[cfg(feature = "tls")]
        return http_post_tls(conn, hosthdr, path, body);
        #[cfg(not(feature = "tls"))]
        {
            eprintln!("TLS_UNSUPPORTED（二进制未以 tls feature 编译，拒绝明文回退）");
            return Err("tls-unsupported".to_string());
        }
    }
    use std::net::TcpStream;
    use std::time::Duration;
    let addr: std::net::SocketAddr = conn
        .parse()
        .map_err(|e| format!("bad srv addr: {}", e))?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(15))).map_err(|e| e.to_string())?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        path, hosthdr, body.len(), body
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let txt = String::from_utf8_lossy(&buf).to_string();
    let head_end = txt.find("\r\n\r\n").ok_or_else(|| "no header end".to_string())?;
    let status: u16 = txt
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| "bad status".to_string())?;
    Ok((status, txt[head_end + 4..].to_string()))
}

/// TLS 传输：rustls（ring 后端）+ webpki-roots 内嵌公共 CA。
/// SNI 与 HTTP Host 同为清单 hy_srv_host；连接地址为 hy_srv 的 IP:443。
/// 证书校验依赖真实系统时间（内核 RTC_HCTOSYS 从 CMOS 注入）。
#[cfg(feature = "tls")]
fn http_post_tls(conn: &str, hosthdr: &str, path: &str, body: &str) -> Result<(u16, String), String> {
    use std::io::{Read as TRead, Write as TWrite};
    use std::net::TcpStream;
    use std::time::Duration;
    use std::sync::Arc;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(hosthdr.to_string())
        .map_err(|e| format!("sni {}", e))?;
    let tls_conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("tlsconn {}", e))?;
    let addr: std::net::SocketAddr = conn
        .parse()
        .map_err(|e| format!("bad srv addr: {}", e))?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(Duration::from_secs(15))).map_err(|e| e.to_string())?;
    let mut stream = rustls::StreamOwned::new(tls_conn, tcp);
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        path, hosthdr, body.len(), body
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let txt = String::from_utf8_lossy(&buf).to_string();
    let head_end = txt.find("\r\n\r\n").ok_or_else(|| "no header end".to_string())?;
    let status: u16 = txt
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| "bad status".to_string())?;
    Ok((status, txt[head_end + 4..].to_string()))
}

fn dk_seed_recombine() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for sh in genkeys::DK_SEED_SH.iter() {
        for (j, b) in sh.iter().enumerate() {
            seed[j] ^= b;
        }
    }
    seed
}

fn dk_sign(msg: &str) -> [u8; 64] {
    let mut seed = [0u8; 32];
    for sh in genkeys::DK_SEED_SH.iter() {
        for (j, b) in sh.iter().enumerate() {
            seed[j] ^= b;
        }
    }
    let sig = hyproto::ed25519_sign(&seed, msg.as_bytes());
    seed.iter_mut().for_each(|b| *b = 0);
    sig
}

/// 从服务端 JSON 响应中取字符串字段（响应结构固定，避免引入 serde 依赖）
fn json_field(j: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    let i = j.find(&pat)? + pat.len();
    let rest = &j[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// 校验服务端响应签名：固定 SRV 公钥 + 本次一次性随机 nonce（防伪造/防跨次重放）
fn verify_srv_resp(msg: &str, sig_hex: &str) -> Result<(), String> {
    let mut sig = [0u8; 64];
    hex_decode_into(sig_hex, &mut sig).map_err(|_| "resp_sig_hex".to_string())?;
    hyproto::ed25519_verify(&genkeys::SRV_PUB, msg.as_bytes(), &sig)
        .map_err(|_| "resp_sig_invalid".to_string())
}

fn ack(did: &str, stage: &str, epoch: u64, srv: &str) -> Result<(u16, String), String> {
    // 传输层重试：单次网络抖动不应触发 fail-closed 销毁（签名与一次性 nonce 仍然强制）
    let mut last = String::from("no-attempt");
    for attempt in 0..6u32 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(match attempt { 1 => 1500, 2 => 3000, 3 => 5000, _ => 8000 }));
        }
        // 一次性随机 nonce：PID1 恒为 1，任何确定性构造都会被重放
        let mut nonce = [0u8; 32];
        hyproto::fill_random(&mut nonce);
        let nonce_b64 = b64url_encode(&nonce);
        let msg = format!("{}|{}|{}|{}", did, stage, epoch, nonce_b64);
        let sig = dk_sign(&msg);
        let sig_hex = hex_encode(&sig);
        let body = format!(
            "{{\"did\":\"{}\",\"stage\":\"{}\",\"epoch\":{},\"nonce\":\"{}\",\"sig\":\"{}\"}}",
            did, stage, epoch, nonce_b64, sig_hex
        );
        match http_post(srv, "/v1/ack", &body) {
            Ok((st, resp)) => {
                let outcome = json_field(&resp, "outcome");
                let rsig = json_field(&resp, "sig");
                match (outcome, rsig) {
                    (Some(o), Some(sg)) => {
                        let rmsg = format!("{}|{}|{}|{}|{}", did, stage, epoch, nonce_b64, o);
                        if verify_srv_resp(&rmsg, &sg).is_ok() {
                            // 有效签名：4xx 为服务端权威拒绝（不可重试），其余都交回调用方判定
                            if st < 500 {
                                return Ok((st, resp));
                            }
                            last = format!("http_{}", st);
                        } else {
                            last = "resp_sig_invalid".into();
                        }
                    }
                    _ => last = format!("resp_unsigned_http_{}", st),
                }
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}
fn parse_kv(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            m.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    m
}

fn verify_sig_file(body_path: &str, sig_path: &str, expect_pub: &[u8; 32]) -> Result<BTreeMap<String, String>, ()> {
    let body = std::fs::read(body_path).map_err(|_| ())?;
    let sig = std::fs::read(sig_path).map_err(|_| ())?;
    if sig.len() != 64 || ed25519_verify(expect_pub, &body, sig[..64].try_into().unwrap()).is_err() {
        return Err(());
    }
    Ok(parse_kv(&String::from_utf8_lossy(&body)))
}

// ---------- destroy paths ----------

fn l2_wipe_app_and_off(srv: &str, did: &str, epoch: u64, stage: &str) -> ! {
    eprintln!("HYOS DESTROY[{}] wiping p3...", stage);
    let mut f = open_disk();
    wipe_sectors(&mut f, P3_START, 2 + 16);
    // 诊断：销毁原因以 fatal:<tag> 事件上报（服务端仅记录，不推进状态机）
    let _ = ack(did, &format!("fatal:{}", stage), epoch, srv);
    poweroff();
}

fn l5_wipe_all_and_off() -> ! {
    eprintln!("HYOS L5 WIPE");
    let mut f = open_disk();
    wipe_sectors(&mut f, P2_START, 2 + 16);
    wipe_sectors(&mut f, P3_START, 2 + 16);
    poweroff();
}

/// SELinux 未生效等致命状态：清除两个分区的槽头与载荷头（密钥与磁盘内容），再断电
fn destroy_all_and_off(srv: &str, did: &str, epoch: u64, tag: &str) -> ! {
    eprintln!("HYOS DESTROY[{}] wiping p2+p3...", tag);
    let mut f = open_disk();
    wipe_sectors(&mut f, P2_START, 2 + 16);
    wipe_sectors(&mut f, P3_START, 2 + 16);
    let _ = ack(did, &format!("fatal:{}", tag), epoch, srv);
    poweroff();
}

fn l3_wipe(srv: &str, did: &str, epoch: u64, tag: &str) -> ! {
    eprintln!("HYOS DESTROY[{}] wiping p3 (L3)", tag);
    let mut f = open_disk();
    wipe_sectors(&mut f, P3_START, 2 + 16);
    let _ = ack(did, &format!("fatal:{}", tag), epoch, srv);
    poweroff();
}

// ---------- cpio (newc) ----------

fn parse_cpio(data: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut i = 0usize;
    while i + 110 <= data.len() {
        if &data[i..i + 6] != b"070701" { break; }
        let hexv = |s: &[u8]| -> usize {
            usize::from_str_radix(std::str::from_utf8(s).unwrap_or("0"), 16).unwrap_or(0)
        };
        let namesize = hexv(&data[i + 94..i + 102]);
        let filesize = hexv(&data[i + 54..i + 62]);
        let name_start = i + 110;
        if namesize == 0 || name_start + namesize > data.len() { break; }
        let name = String::from_utf8_lossy(&data[name_start..name_start + namesize - 1]).to_string();
        let mut off = name_start + namesize;
        off = (off + 3) & !3;
        if name == "TRAILER!!!" { break; }
        if off + filesize > data.len() { break; }
        out.insert(name, data[off..off + filesize].to_vec());
        off += filesize;
        off = (off + 3) & !3;
        i = off;
    }
    out
}

// ---------- verifier (PID1) ----------

// ---------- SELinux 强制访问控制 ----------

fn mount_fs(source: &str, target: &str, fstype: &str, opts: Option<&str>) -> bool {
    let s = std::ffi::CString::new(source).unwrap();
    let t = std::ffi::CString::new(target).unwrap();
    let f = std::ffi::CString::new(fstype).unwrap();
    let o = opts.map(|x| std::ffi::CString::new(x).unwrap());
    let r = unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            f.as_ptr(),
            0,
            o.as_ref().map_or(std::ptr::null(), |c| c.as_ptr() as *const libc::c_void),
        )
    };
    r == 0
}

/// 设置 SELinux 标签（security.selinux 扩展属性），无需 libselinux
fn selinux_label(path: &str, ctx: &str) -> bool {
    let p = std::ffi::CString::new(path).unwrap();
    let n = std::ffi::CString::new("security.selinux").unwrap();
    unsafe {
        libc::setxattr(
            p.as_ptr(),
            n.as_ptr(),
            ctx.as_ptr() as *const libc::c_void,
            ctx.len(),
            0,
        ) == 0
    }
}

/// 挂载 selinuxfs、加载单块策略、切换 enforcing，并准备应用运行区（tmpfs）
fn selinux_setup() -> bool {
    let _ = std::fs::create_dir_all("/sys/fs/selinux");
    let mounted = mount_fs("selinuxfs", "/sys/fs/selinux", "selinuxfs", None);
    // 应用运行区必须支持 security.* 扩展属性 → tmpfs
    let _ = mount_fs("tmpfs", "/run", "tmpfs", Some("size=96m,mode=0755"));
    // 策略加载必须一次性写入（内核 sel_write_load 只接受单次完整写入）
    // 临时放开内核日志级别以捕获 SELinux 初始化/加载错误
    let _ = std::fs::write("/proc/sys/kernel/printk", "7 4 1 7");
    let mut loaded = false;
    match std::fs::read("/etc/selinux/policy") {
        Ok(pol) => {
            use std::io::Write;
            match std::fs::OpenOptions::new()
                .write(true)
                .open("/sys/fs/selinux/load")
            {
                Ok(mut f) => match f.write(&pol) {
                    Ok(n) => {
                        if n == pol.len() {
                            loaded = true;
                        } else {
                            eprintln!("SELINUX_LOAD_PARTIAL {}/{}", n, pol.len());
                        }
                    }
                    Err(e) => eprintln!("SELINUX_LOAD_WRITE_ERR errno={:?}", e.raw_os_error()),
                },
                Err(e) => eprintln!("SELINUX_LOAD_OPEN_ERR errno={:?}", e.raw_os_error()),
            }
            eprintln!("SELINUX_POLICY_BYTES={}", pol.len());
        }
        Err(e) => eprintln!("SELINUX_POLICY_READ_ERR errno={:?}", e.raw_os_error()),
    }
    let _ = std::fs::write("/proc/sys/kernel/printk", "1 4 1 7");
    // 生产无 permissive 后门：cmdline 不可信（grub.cfg 曾以明文落在 P1），一律强制 enforcing
    if !mounted || !loaded {
        eprintln!("SELINUX_SETUP_FAIL mounted={} loaded={}", mounted, loaded);
        return false;
    }
    // 写入结果不得丢弃：写失败或回读非 "1" 都视为策略未生效（fail-closed，绝不静默 permissive）
    let wrote = std::fs::write("/sys/fs/selinux/enforce", "1");
    let readback = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if wrote.is_err() || readback != "1" {
        eprintln!(
            "SELINUX_ENFORCE_FAIL write_errno={:?} readback={:?}",
            wrote.err().map(|e| e.raw_os_error()),
            readback
        );
        return false;
    }
    let _ = std::fs::create_dir_all("/run/apps");
    let _ = std::fs::create_dir_all("/run/hyos-tmp");
    // 目录先标注：此后创建的文件继承 conf_t；可执行文件再逐个显式改为 exec_t（此前漏标，
    // 应用实际一直跑在初始域，SELinux 从未真正约束过它们）
    let _ = selinux_label("/run/apps", "system_u:object_r:hyos_app_conf_t:s0");
    // 最小 initramfs 无 file_contexts：/dev/null 等曾落到 event_device_t，应用无法使用。
    // 显式重标注为标准设备类型（应用域只被授予这几种基础设备）
    for (dev, ctx) in [
        ("/dev/null", "system_u:object_r:null_device_t:s0"),
        ("/dev/zero", "system_u:object_r:zero_device_t:s0"),
        ("/dev/urandom", "system_u:object_r:urandom_device_t:s0"),
        ("/dev/random", "system_u:object_r:random_device_t:s0"),
    ] {
        let _ = selinux_label(dev, ctx);
    }
    // supervisor 的域转换在 exec 阶段由 type_transition(kernel_t, hyos_init_exec_t)
    // 完成——PID1 自身保持初始域负责特权引导（挂载/解密/清盘），不做运行中 dyntransition
    eprintln!("SELINUX_SETUP mounted=1 policy_loaded=1 enforce=1");
    true
}

fn selinux_enforcing() -> Option<String> {
    std::fs::read_to_string("/sys/fs/selinux/enforce")
        .ok()
        .map(|s| s.trim().to_string())
}

/// 重组 CI 部署密钥（XOR 份额）并写入 tmpfs（0600），仅供运行期读取私有配置仓库
fn materialize_git_key() -> Option<usize> {
    let n = genkeys::GIT_KEY_SH[0].len();
    if genkeys::GIT_KEY_LEN == 0 {
        return None;
    }
    let mut data = vec![0u8; n];
    for sh in genkeys::GIT_KEY_SH.iter() {
        for (i, b) in sh.iter().enumerate() {
            data[i] ^= *b;
        }
    }
    data.truncate(genkeys::GIT_KEY_LEN);
    let _ = std::fs::create_dir_all("/run/secrets");
    let path = "/run/secrets/git_deploy_key";
    if std::fs::write(path, &data).is_ok() {
        let _ = std::fs::set_permissions(
            path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        );
        Some(data.len())
    } else {
        None
    }
}

fn run_verify() -> ! {
    mounts();
    // 预读 supervisor（SELinux enforce 后 initramfs 未标注文件将不可执行）
    let supervisor_bytes = std::fs::read("/supervisor").unwrap_or_default();
    // 降低内核控制台日志级别：避免 printk 与关键判定消息在串口交错，保证可审计性
    let _ = std::fs::write("/proc/sys/kernel/printk", "1 4 1 7");
    // loopback：hyauth bind 127.0.0.1 依赖（minimal 内核不自动配置 lo）
    if net_ifup("lo", [127, 0, 0, 1], [255, 0, 0, 0]) {
        eprintln!("NET UP lo 127.0.0.1/8");
    } else {
        eprintln!("NET UP lo FAILED errno={}", unsafe { *libc::__errno_location() });
    }
    // 目标网络参数：优先签名清单注入（一机一镜像）；缺省回落 QEMU 联调值。
    // 清单在下方 467 行处验签——篡改网络字段会破坏签名触发销毁。
    let mankv = parse_kv(&std::fs::read_to_string("/system.manifest").unwrap_or_default());
    let net_ip = mankv.get("hy_net_ip").and_then(|s| parse_ipv4(s)).unwrap_or([10, 0, 2, 15]);
    let net_mask = mankv.get("hy_net_mask").and_then(|s| parse_ipv4(s)).unwrap_or([255, 255, 255, 0]);
    let net_gw = mankv.get("hy_net_gw").and_then(|s| parse_ipv4(s));
    if net_ifup("eth0", net_ip, net_mask) {
        eprintln!("NET UP eth0 {}.{}.{}.{} mask={}.{}.{}.{}", net_ip[0], net_ip[1], net_ip[2], net_ip[3], net_mask[0], net_mask[1], net_mask[2], net_mask[3]);
    } else {
        eprintln!("NET UP FAILED");
    }
    if let Some(gw) = net_gw {
        let gw_err = route_add_default_via("eth0", gw);
        if gw_err == 0 {
            eprintln!("NET GW via {}.{}.{}.{} (netlink onlink)", gw[0], gw[1], gw[2], gw[3]);
        } else {
            eprintln!("NET GW FAILED errno={}", gw_err);
        }
    }
    let cm = cmdline();
    // 密钥服务地址只认 VK_SIG 签名清单（cmdline 回退可被篡改；缺失即销毁，不回退测试地址）
    let srv = mankv.get("hy_srv").cloned().unwrap_or_default();
    // TLS 传输开关（签名清单 hy_tls=1；需二进制以 tls feature 编译）
    TLS_MODE.store(mankv.get("hy_tls").map(|v| v == "1").unwrap_or(false), std::sync::atomic::Ordering::Relaxed);
    eprintln!(
        "NET TLS={}",
        match (TLS_MODE.load(std::sync::atomic::Ordering::Relaxed), cfg!(feature = "tls")) {
            (true, true) => "ON",
            (true, false) => "REQUESTED_BUT_UNSUPPORTED",
            (false, _) => "off",
        }
    );
    let epoch: u64 = cm.get("hy_epoch").and_then(|v| v.parse().ok()).unwrap_or(0);
    if srv.is_empty() {
        eprintln!("MANIFEST_NO_SRV");
        destroy_all_and_off(&srv, genkeys::DID, epoch, "manifest-no-srv");
    }
    let grub_ver: u64 = cm.get("hy_ver").and_then(|v| v.parse().ok()).unwrap_or(0);
    let attest = cm.get("hy_attest").cloned().unwrap_or_default();
    let img_hex = cm.get("hy_img").cloned().unwrap_or_default();
    let did = genkeys::DID;

    let attest_bytes = match b64url_decode(&attest) {
        Some(v) if v.len() == 64 => v,
        _ => l2_wipe_app_and_off(&srv, did, epoch, "attest-format"),
    };
    let msg = format!("attest|{}|{}|{}", genkeys::GRUB_VER, epoch, img_hex);
    if ed25519_verify(&genkeys::DK_PUB, msg.as_bytes(), attest_bytes[..64].try_into().unwrap()).is_err() {
        l2_wipe_app_and_off(&srv, did, epoch, "attest-sig");
    }
    let sys = match verify_sig_file("/system.manifest", "/system.manifest.sig", &genkeys::VK_SIG) {
        Ok(m) => m,
        Err(_) => l2_wipe_app_and_off(&srv, did, epoch, "system-manifest"),
    };
    let pin_ver: u64 = sys.get("grub_pin_ver").and_then(|v| v.parse().ok()).unwrap_or(0);
    let pin_img = sys.get("grub_pin_img").cloned().unwrap_or_default();
    if grub_ver != genkeys::PINNED_GRUB_VER || grub_ver != pin_ver || img_hex != pin_img {
        l2_wipe_app_and_off(&srv, did, epoch, "grub-pin");
    }
    eprintln!("HYVERIFY GRUB-CHAIN OK");

    match ack(did, "grub_ok", epoch, &srv) {
        Ok((200, _)) => {}
        Ok((st, body)) => {
            eprintln!("GRUB_OK_HTTP {} body={}", st, &body[..body.len().min(120)]);
            l2_wipe_app_and_off(&srv, did, epoch, "grub_ok-refused");
        }
        Err(e) => {
            eprintln!("GRUB_OK_ERR {}", &e[..e.len().min(160)]);
            l2_wipe_app_and_off(&srv, did, epoch, "grub_ok-refused");
        }
    }
    let (st, body) = match ack(did, "sys_ok", epoch, &srv) {
        Ok(v) => v,
        Err(_) => l2_wipe_app_and_off(&srv, did, epoch, "sys_ok-err"),
    };
    if st != 200 {
        l2_wipe_app_and_off(&srv, did, epoch, "sys_ok-refused");
    }
    let ck_hex = json_str(&body, "ck").unwrap_or("").to_string();
    let mut ck = [0u8; 32];
    if hex_decode_into(&ck_hex, &mut ck).is_err() {
        l2_wipe_app_and_off(&srv, did, epoch, "ck-format");
    }

    let mut f = open_disk();
    let slotraw = match read_at(&mut f, P3_START, 1024) {
        Ok(v) => v,
        Err(_) => l2_wipe_app_and_off(&srv, did, epoch, "p3-read"),
    };
    let sa: [u8; 512] = slotraw[..512].try_into().unwrap();
    let sb: [u8; 512] = slotraw[512..].try_into().unwrap();
    let (hdr, wrap) = match select_slot(Some(&sa), Some(&sb), |e| kek_app(&genkeys::WK1_ROOT, e), &ck) {
        Ok(v) => v,
        Err(_) => l2_wipe_app_and_off(&srv, did, epoch, "p3-slots"),
    };
    // epoch 以加密槽头为准：cmdline 的 hy_epoch 仅作交叉校验，不一致即销毁
    if hdr.epoch != epoch {
        eprintln!("EPOCH_MISMATCH cmdline={} slot={}", epoch, hdr.epoch);
        l2_wipe_app_and_off(&srv, did, epoch, "epoch-mismatch");
    }
    let dek2 = match unwrap_dek(&kek_app(&genkeys::WK1_ROOT, hdr.epoch), hdr.epoch, &wrap) {
        Ok(d) => d,
        Err(_) => l2_wipe_app_and_off(&srv, did, epoch, "dek2"),
    };
    let mut payload = match read_at(&mut f, P3_START + PAYLOAD_OFF, hdr.payload_len as usize) {
        Ok(v) => v,
        Err(_) => l2_wipe_app_and_off(&srv, did, epoch, "p3-payload"),
    };
    let plen = payload.len();
    // aes-gcm decrypt 需要 密文||tag 一体输入（tag 为末 16B，已在 payload 内）
    let _ = plen;
    let pn = payload_nonce(&dek2);
    let pt = match aead_open(&dek2, &pn, &payload, b"hyos-payload") {
        Ok(p) => p,
        Err(_) => l2_wipe_app_and_off(&srv, did, epoch, "p3-tag"),
    };
    let img = hyproto::sha256(&pt);
    if img != hdr.img_sha256 {
        l2_wipe_app_and_off(&srv, did, epoch, "p3-hash");
    }

    let files = parse_cpio(&pt);
    let app_body = match files.get("apps/app.manifest") {
        Some(v) => v.clone(),
        None => l3_wipe(&srv, did, epoch, "no-manifest"),
    };
    let app_sig = match files.get("apps/app.manifest.sig") {
        Some(v) => v.clone(),
        None => l3_wipe(&srv, did, epoch, "no-sig"),
    };
    let _ = std::fs::write("/app.manifest", &app_body);
    let _ = std::fs::write("/app.manifest.sig", &app_sig);
    let app = match verify_sig_file("/app.manifest", "/app.manifest.sig", &genkeys::VK_SIG) {
        Ok(m) => m,
        Err(_) => l3_wipe(&srv, did, epoch, "app-manifest-sig"),
    };
    if app.get("os_pin").map(|s| s.as_str()) != sys.get("os_ver").map(|s| s.as_str()) {
        l3_wipe(&srv, did, epoch, "os-pin");
    }
    let hello = match files.get("apps/hello") {
        Some(v) => v.clone(),
        None => l3_wipe(&srv, did, epoch, "no-entry"),
    };
    let want = app.get("file_hello").cloned().unwrap_or_default();
    if hex_encode(&hyproto::sha256(&hello)) != want {
        l3_wipe(&srv, did, epoch, "entry-hash");
    }
    // M5：真应用包（hysteria2 + hyauth + 配置 + auth 机密 + TLS 证书），逐文件哈希校验
    let m5_files: Vec<(&str, &str)> = vec![
        ("apps/hysteria", "file_hysteria"),
        ("apps/hyauth", "file_hyauth"),
        ("apps/config.yaml", "file_config"),
        ("apps/auth.env", "file_authenv"),
        ("apps/tls/fullchain.pem", "file_tlscert"),
        ("apps/tls/key.pem", "file_tlskey"),
        ("apps/hyproxy", "file_pingora"),
        ("apps/proxy.conf", "file_proxyconf"),
        ("apps/porthop.conf", "file_porthopconf"),
        ("apps/iptables-restore", "file_iptables"),
        ("apps/ca.pem", "file_ca"),
    ];
    let mut m5: std::collections::BTreeMap<String, Vec<u8>> = std::collections::BTreeMap::new();
    for (cpio_name, manifest_key) in &m5_files {
        if let Some(want_hex) = app.get(*manifest_key) {
            let data = match files.get(*cpio_name) {
                Some(v) => v.clone(),
                None => l3_wipe(&srv, did, epoch, "m5-missing"),
            };
            if hex_encode(&hyproto::sha256(&data)) != *want_hex {
                l3_wipe(&srv, did, epoch, "m5-hash");
            }
            m5.insert((*cpio_name).to_string(), data);
        }
    }

    // 7) SELinux：加载策略并强制，应用写入 tmpfs 并标注
    //    未正确加载/未进入 enforcing/未落入受限域 → 立即销毁（清密钥与磁盘内容后断电）
    if !selinux_setup() {
        destroy_all_and_off(&srv, did, epoch, "selinux-policy");
    }
    let _ = std::fs::write("/run/apps/hello", &hello);
    let _ = std::fs::set_permissions(
        "/run/apps/hello",
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    );
    if !selinux_label("/run/apps/hello", "system_u:object_r:hyos_app_exec_t:s0") {
        eprintln!("SELINUX_LABEL_FAIL app_exec");
    }
    // M5：应用文件落地 tmpfs（在目录标注前写入，继承 exec_t —— hysteria/hyauth 可执行）
    if m5.contains_key("apps/hysteria") {
        let _ = std::fs::write("/run/apps/hysteria", &m5["apps/hysteria"]);
        let _ = std::fs::set_permissions(
            "/run/apps/hysteria",
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        );
        let _ = selinux_label("/run/apps/hysteria", "system_u:object_r:hyos_app_exec_t:s0");
        let _ = std::fs::write("/run/apps/hyauth", &m5["apps/hyauth"]);
        let _ = std::fs::set_permissions(
            "/run/apps/hyauth",
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        );
        let _ = selinux_label("/run/apps/hyauth", "system_u:object_r:hyos_app_exec_t:s0");
        let _ = std::fs::write("/run/apps/config.yaml", &m5["apps/config.yaml"]);
        let _ = std::fs::write("/run/apps/auth.env", &m5["apps/auth.env"]);
        let _ = std::fs::set_permissions(
            "/run/apps/auth.env",
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        );
        let _ = std::fs::create_dir_all("/run/apps/tls");
        let _ = std::fs::write("/run/apps/tls/fullchain.pem", &m5["apps/tls/fullchain.pem"]);
        let _ = std::fs::write("/run/apps/tls/key.pem", &m5["apps/tls/key.pem"]);
        if m5.contains_key("apps/hyproxy") {
            let _ = std::fs::write("/run/apps/hyproxy", &m5["apps/hyproxy"]);
            let _ = std::fs::set_permissions(
                "/run/apps/hyproxy",
                std::os::unix::fs::PermissionsExt::from_mode(0o755),
            );
            let _ = selinux_label("/run/apps/hyproxy", "system_u:object_r:hyos_app_exec_t:s0");
        }
        if m5.contains_key("apps/proxy.conf") {
            let _ = std::fs::write("/run/apps/proxy.conf", &m5["apps/proxy.conf"]);
            let _ = selinux_label("/run/apps/proxy.conf", "system_u:object_r:hyos_app_conf_t:s0");
        }
        if m5.contains_key("apps/ca.pem") {
            let _ = std::fs::write("/run/apps/ca.pem", &m5["apps/ca.pem"]);
            let _ = selinux_label("/run/apps/ca.pem", "system_u:object_r:hyos_app_conf_t:s0");
        }
        if m5.contains_key("apps/porthop.conf") {
            let _ = std::fs::write("/run/apps/porthop.conf", &m5["apps/porthop.conf"]);
            let _ = selinux_label("/run/apps/porthop.conf", "system_u:object_r:hyos_app_conf_t:s0");
        }
        if m5.contains_key("apps/iptables-restore") {
            let _ = std::fs::write("/run/iptables-restore", &m5["apps/iptables-restore"]);
            let _ = std::fs::set_permissions(
                "/run/iptables-restore",
                std::os::unix::fs::PermissionsExt::from_mode(0o755),
            );
            // iptables 需要 CAP_NET_ADMIN：以 supervisor 域（hyos_init_t）运行，不进应用域
            let _ = selinux_label("/run/iptables-restore", "system_u:object_r:hyos_init_exec_t:s0");
        }
        let _ = std::fs::set_permissions(
            "/run/apps/tls/key.pem",
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        );
        // 写入发生在目录标注前（新文件继承 tmpfs_t），逐项显式标注：
        //   hyos_app_conf_t  —— 配置（可读，不可执行）
        //   hyos_secret_t    —— 认证机密与 TLS 私钥（可读，不可执行；与可执行类型严格分离）
        let _ = selinux_label("/run/apps/config.yaml", "system_u:object_r:hyos_app_conf_t:s0");
        let _ = selinux_label("/run/apps/auth.env", "system_u:object_r:hyos_secret_t:s0");
        let _ = selinux_label("/run/apps/tls", "system_u:object_r:hyos_secret_t:s0");
        let _ = selinux_label("/run/apps/tls/fullchain.pem", "system_u:object_r:hyos_secret_t:s0");
        let _ = selinux_label("/run/apps/tls/key.pem", "system_u:object_r:hyos_secret_t:s0");
        eprintln!("M5_APP_FILES_WRITTEN");
    }
    let _ = selinux_label("/run/apps", "system_u:object_r:hyos_app_conf_t:s0");
    let _ = selinux_label("/run/hyos-tmp", "system_u:object_r:hyos_tmp_t:s0");
    // /etc/hysteria 已废弃（配置改由 /run/apps 提供，标注见 hyos_app_conf_t / hyos_secret_t）
    if let Some(e) = selinux_enforcing() {
        eprintln!("SELINUX_ENFORCE={}", e);
    }
    // 网络缓冲上限：hysteria2 需要大收发缓冲（避免授予应用 CAP_NET_ADMIN）
    let _ = std::fs::write("/proc/sys/net/core/rmem_max", "16777216");
    let _ = std::fs::write("/proc/sys/net/core/wmem_max", "16777216");
    // DNS：最小内核无自动 DNS 配置，Go 程序（hysteria2）需要 /etc/resolv.conf
    let _ = std::fs::write("/etc/resolv.conf", "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    // 应用需读 DNS 配置：标注为配置类型（root_t 不对应用开放）
    let _ = selinux_label("/etc/resolv.conf", "system_u:object_r:hyos_app_conf_t:s0");
    // 部署密钥：份额重组 → tmpfs（0600），仅运行期使用
    match materialize_git_key() {
        Some(len) => eprintln!("GITKEY_READY bytes={}", len),
        None => eprintln!("GITKEY_EMPTY"),
    }

    eprintln!("SYS_OK");
    // supervisor 落地到 tmpfs 并标注为 hyos_init_exec_t
    let sup_path = "/run/supervisor";
    if !supervisor_bytes.is_empty() {
        let _ = std::fs::write(sup_path, &supervisor_bytes);
        let _ = std::fs::set_permissions(
            sup_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        );
        if !selinux_label(sup_path, "system_u:object_r:hyos_init_exec_t:s0") {
            eprintln!("SELINUX_LABEL_FAIL supervisor");
        }
    } else {
        eprintln!("SUPERVISOR_READ_FAIL");
    }
    // 打开 AVC 审计输出（exec/域转换被拒时留证）
    let _ = std::fs::write("/proc/sys/kernel/printk", "7 4 1 7");
    let status = Command::new(sup_path)
        .arg("supervise")
        .arg(epoch.to_string())
        .arg(&srv)
        .env("HY_CK", hex_encode(&ck))
        .env("HY_DID", did)
        .env("HY_TLS", if TLS_MODE.load(std::sync::atomic::Ordering::Relaxed) { "1" } else { "0" })
        .env("HY_ACME_DOMAIN", mankv.get("hy_acme_domain").cloned().unwrap_or_default())
        .env("HY_ACME_STAGING", mankv.get("hy_acme_staging").cloned().unwrap_or_default())
        // 安全相关开关一律取签名清单，不取未认证 cmdline
        .env("HY_HB_MS", mankv.get("hy_hb_ms").cloned().unwrap_or_else(|| "300000".into()))
        .env("HY_TEST", mankv.get("hy_test").cloned().unwrap_or_default())
        .status();
    match status {
        Ok(s) if s.success() => poweroff(),
        Ok(s) => {
            eprintln!("SUPERVISOR_EXIT code={:?} signal={:?}", s.code(), std::os::unix::process::ExitStatusExt::signal(&s));
            l3_wipe(&srv, did, epoch, "supervisor-exit");
        }
        Err(e) => {
            eprintln!("SUPERVISOR_SPAWN_ERR kind={:?} errno={:?}", e.kind(), e.raw_os_error());
            l3_wipe(&srv, did, epoch, "supervisor-spawn");
        }
    }
}

// ---------- supervisor ----------

#[cfg(feature = "tls")]
fn issue_certs_to_tmpfs(acme_domain: &str, srv: &str, did: &str, dk_seed: &[u8; 32], epoch: u64, staging: bool) -> bool {
    {
    }
    #[cfg(feature = "tls")]
    {
    let wk1 = std::env::var("HY_WK1_ROOT").unwrap_or_default();
    let staging = std::env::var("HY_ACME_STAGING").map(|v| v == "1").unwrap_or(false);
    eprintln!("CERT_ISSUING domain={} staging={}", acme_domain, staging);
    let mut issued = false;
    for attempt in 1..=3 {
    let wk1_hex = hex_encode(&genkeys::WK1_ROOT);
    // srv 形如 "IP:PORT@host"——acme 需要 https URL：取 @ 后的 host（hyinit 已配 DNS）
    let acme_ks = match srv.split_once('@') {
    Some((_, h)) => format!("https://{}", h),
    None => format!("https://{}", srv),
    };
    match acme::issue(
    &acme_domain, &wk1_hex, &acme_ks, &did, &dk_seed_recombine(), staging, epoch,
    ) {
    Ok(cert) => {
    let _ = std::fs::write("/run/apps/tls/fullchain.pem", &cert.fullchain_pem);
    let _ = std::fs::write("/run/apps/tls/key.pem", &cert.key_pem);
    let _ = std::fs::set_permissions(
    "/run/apps/tls/key.pem",
    std::os::unix::fs::PermissionsExt::from_mode(0o600),
    );
    let _ = selinux_label("/run/apps/tls/fullchain.pem", "system_u:object_r:hyos_app_exec_t:s0");
    let _ = selinux_label("/run/apps/tls/key.pem", "system_u:object_r:hyos_app_exec_t:s0");
    eprintln!("CERT_ISSUED attempt={}", attempt);
    issued = true;
    break;
    }
    Err(e) => {
    eprintln!("CERT_FAIL attempt={} err={}", attempt, e);
    std::thread::sleep(std::time::Duration::from_secs(5));
    }
    }
    }
    if !issued {
    eprintln!("CERT_FAIL_FINAL（回落应用包内置证书，到期前需人工处理）");
    }
    }

    true
}

fn run_supervise(epoch: u64, srv: String) -> ! {
    // TLS 标志经环境继承（独立进程，静态变量不共享）
    TLS_MODE.store(std::env::var("HY_TLS").map(|v| v == "1").unwrap_or(false), std::sync::atomic::Ordering::Relaxed);
    // 放开内核日志级别：捕获 SELinux AVC 拒绝记录（诊断与审计）
    let _ = std::fs::write("/proc/sys/kernel/printk", "7 4 1 7");
    if let Ok(ctx) = std::fs::read_to_string("/proc/self/attr/current") {
        eprintln!("SELINUX_SUPERVISOR_DOMAIN={}", ctx.trim());
    }
    let did = std::env::var("HY_DID").unwrap_or_default();
    let ck_hex = std::env::var("HY_CK").unwrap_or_default();
    let mut ck = [0u8; 32];
    hex_decode_into(&ck_hex, &mut ck).expect("ck");
    let hb_ms: u64 = std::env::var("HY_HB_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(300000);
    let test_mode = std::env::var("HY_TEST").unwrap_or_default() == "1";

    // 应用 stdout/stderr 置空：避免与 supervisor 的串口标记交错，保持日志可判定
    // M5：hysteria 模式（应用包含 apps/hysteria 时）主应用切换为 hysteria2
    let hysteria_mode = std::path::Path::new("/run/apps/hysteria").exists();
    let app_path = if hysteria_mode {
        "/run/apps/hysteria"
    } else {
        "/run/apps/hello"
    };
    let mut proxy_child: Option<std::process::Child> = None;
    let mut proxy_child_started = false;
    if hysteria_mode {
        // porthop：端口跳跃 DNAT（规则来自签名清单文件；{{IFACE}} 由 hyinit 渲染占位）
        if std::path::Path::new("/run/iptables-restore").exists() && std::path::Path::new("/run/apps/porthop.conf").exists() {
            let rendered = std::fs::read_to_string("/run/apps/porthop.conf").unwrap_or_default()
                .replace("{{ IFACE }}", "eth0").replace("{{IFACE}}", "eth0");
            let _ = std::fs::write("/run/porthop.rules", &rendered);
            let _ = std::fs::set_permissions("/run/porthop.rules", std::os::unix::fs::PermissionsExt::from_mode(0o600));
            let _ = selinux_label("/run/porthop.rules", "system_u:object_r:hyos_app_exec_t:s0");
            match Command::new("/run/iptables-restore")
                .arg("/run/porthop.rules")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
            {
                Ok(st) if st.success() => eprintln!("PORTHOP_APPLIED"),
                _ => eprintln!("PORTHOP_FAIL（跳跃端口 20000-30000/40000-60000 将不通，443 主端口不受影响）"),
            }
        }
        // hyproxy（masquerade 反代）：hysteria 之前起，抢 80/443 TCP
        if std::path::Path::new("/run/apps/hyproxy").exists() {
            match Command::new("/run/apps/hyproxy")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(pc) => { eprintln!("HYPROXY_UP pid={}", pc.id()); proxy_child = Some(pc); proxy_child_started = true; }
                Err(e) => eprintln!("HYPROXY_ERR kind={:?} errno={:?}", e.kind(), e.raw_os_error()),
            }
        }
        // hyauth 先起（127.0.0.1:18080），hysteria 的 HTTP auth 依赖它
        let auth_env = std::fs::read_to_string("/run/apps/auth.env").unwrap_or_default();
        let get_env = |k: &str| -> String {
            auth_env
                .lines()
                .find(|l| l.starts_with(&format!("{}=", k)))
                .map(|l| l[k.len() + 1..].to_string())
                .unwrap_or_default()
        };
        match Command::new("/run/apps/hyauth")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .env("HYSTERIA_AUTH_SECRET", get_env("HYSTERIA_AUTH_SECRET"))
            .env("HYSTERIA_AUTH_ID", get_env("HYSTERIA_AUTH_ID"))
            .spawn()
        {
            Ok(hc) => eprintln!("HYAUTH_UP pid={}", hc.id()),
            Err(e) => {
                eprintln!("HYAUTH_ERR kind={:?} errno={:?}", e.kind(), e.raw_os_error());
                l3_wipe(&srv, &did, epoch, "spawn-hyauth");
            }
        }
        // 认证机密只经环境变量交付 hyauth：文件用后立即删除，磁盘/内存中不留可被其他应用读取的副本
        let _ = std::fs::remove_file("/run/apps/auth.env");
        if std::path::Path::new("/run/apps/auth.env").exists() {
            eprintln!("AUTHENV_UNLINK_FAIL");
        } else {
            eprintln!("AUTHENV_UNLINKED");
        }
        eprintln!("APP_MODE=hysteria2");
    }
    // 诊断：确认应用文件存在并暴露 spawn 失败原因
    match std::fs::metadata(app_path) {
        Ok(m) => eprintln!("APP_FILE_OK size={}", m.len()),
        Err(e) => eprintln!("APP_FILE_ERR errno={:?}", e.raw_os_error()),
    }
    // 诊断：读回应用文件实际生效的 SELinux 标签 + /run 挂载标志
    unsafe {
        let p = std::ffi::CString::new("/run/apps/hello").unwrap();
        let n = std::ffi::CString::new("security.selinux").unwrap();
        let mut buf = [0u8; 256];
        let r = libc::lgetxattr(p.as_ptr(), n.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        if r >= 0 {
            eprintln!("SELINUX_APP_LABEL={}", String::from_utf8_lossy(&buf[..r as usize]).trim_end_matches('\0'));
        } else {
            eprintln!("SELINUX_APP_LABEL=unreadable");
        }
    }
    if let Ok(m) = std::fs::read_to_string("/proc/mounts") {
        for line in m.lines() {
            if line.contains(" /run ") {
                eprintln!("RUN_MOUNT={}", line);
            }
        }
    }
    // 生产：应用不得写控制台（console_device_t/tty_device_t 可写已从策略移除）
    // 诊断统一由 supervisor（hyos_init_t）输出，应用 stdio 全部置空
    let mut child = match {
        let mut cmd = Command::new(app_path);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        if hysteria_mode {
            // M5.1 证书自动续期：ACME DNS-01 签发（写 /run/apps/tls/，失败回落应用包内置证书）
            let acme_domain = std::env::var("HY_ACME_DOMAIN").unwrap_or_default();
            #[cfg(feature = "tls")]
            {
                let staging = std::env::var("HY_ACME_STAGING").map(|v| v == "1").unwrap_or(false);
                let dk_seed = dk_seed_recombine();
                let issued = issue_certs_to_tmpfs(&acme_domain, &srv, &did, &dk_seed, epoch, staging);
                if issued { eprintln!("CERT_ISSUED"); } else { eprintln!("CERT_FAIL_FINAL（回落内置证书）"); }
            }
            #[cfg(not(feature = "tls"))]
            eprintln!("CERT_SKIP（非 TLS 构建，回落内置证书）");
            cmd.arg("server").arg("-c").arg("/run/apps/config.yaml");
            // 注意：hysteria2 server 子命令无任何 CLI flag，端口只认 config.yaml（渲染期已改 8443）
            // TCP 443/80 由 hyproxy 占用，UDP 跳跃区间由 porthop DNAT → 8443，互不冲突
        }
        cmd.spawn()
    } {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SPAWN_ERR kind={:?} errno={:?}", e.kind(), e.raw_os_error());
            l3_wipe(&srv, &did, epoch, "spawn");
        }
    };

    // SELinux 证据 1：应用进程所在域
    match std::fs::read_to_string(format!("/proc/{}/attr/current", child.id())) {
        Ok(ctx) => eprintln!("SELINUX_APP_DOMAIN={}", ctx.trim()),
        Err(_) => eprintln!("SELINUX_APP_DOMAIN=unreadable"),
    }
    // SELinux 证据 1b：立即复检进程存活（排除 pid 复用干扰）
    eprintln!("CHILD_ALIVE0={}", matches!(child.try_wait(), Ok(None)));
    // SELinux 证据 2：在受限域内探测（块设备/配置写应被拒绝，tmpfs 写应成功）
    // hysteria 模式跳过 probe（ hysteria CLI 不识别 --probe）
    let probe_res = if hysteria_mode {
        None
    } else {
        Some(Command::new(app_path).arg("--probe").stdin(std::process::Stdio::null()).output())
    };
    match probe_res {
        Some(Ok(o)) => {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                eprintln!("PROBE {}", line);
            }
        }
        Some(Err(_)) => eprintln!("PROBE spawn-failed"),
        None => eprintln!("PROBE skipped (hysteria mode)"),
    }

    match ack(&did, "app_ok", epoch, &srv) {
        Ok((200, body)) => {
            eprintln!("APP_OK sealed");
            let ws = json_str(&body, "wrapped_sys_next").unwrap_or("").to_string();
            let wa = json_str(&body, "wrapped_app_next").unwrap_or("").to_string();
            let ck_now = json_str(&body, "ck").unwrap_or("").to_string();
            let ck_next = json_str(&body, "ck_next").unwrap_or("").to_string();
            let use_ck = if ck_next.len() == 64 { ck_next } else { ck_now };
            advance_slots(epoch + 1, &ws, &wa, &use_ck);
        }
        _ => l3_wipe(&srv, &did, epoch, "app_ok-refused"),
    }

    let mut fails = 0u32;
    let mut oks = 0u32;
    // 证书运行期轮换：60 天（< LE 90 天有效期）后自动重签 + 热重启 hysteria
    #[cfg(feature = "tls")]
    let mut last_renew_attempt = std::time::Instant::now() - std::time::Duration::from_secs(60 * 86400 - 5 * 60); // 启动即视作"刚检查过"（boot 时已签发）
    // SELinux 证据 1c：心跳前复检应用域与存活（app_ok 之后）
    match std::fs::read_to_string(format!("/proc/{}/attr/current", child.id())) {
        Ok(ctx) => eprintln!("SELINUX_APP_DOMAIN2={}", ctx.trim()),
        Err(_) => eprintln!("SELINUX_APP_DOMAIN2=unreadable"),
    }
    match child.try_wait() {
        Ok(None) => eprintln!("CHILD_ALIVE1=true"),
        Ok(Some(s)) => eprintln!("CHILD_DEAD status={:?}", s),
        Err(e) => eprintln!("CHILD_WAIT_ERR {}", e),
    }
    loop {
        std::thread::sleep(std::time::Duration::from_millis(hb_ms));
        // 证书 60 天轮换检查（每心跳周期检查一次；失败 24h 后重试）
        #[cfg(feature = "tls")]
        if hysteria_mode && last_renew_attempt.elapsed() > std::time::Duration::from_secs(86400) {
            let acme_domain = std::env::var("HY_ACME_DOMAIN").unwrap_or_default();
            if !acme_domain.is_empty() {
                let dk_seed = dk_seed_recombine();
                let ok = issue_certs_to_tmpfs(&acme_domain, &srv, &did, &dk_seed, epoch, std::env::var("HY_ACME_STAGING").map(|v| v == "1").unwrap_or(false));
                if ok {
                    eprintln!("CERT_RENEWED runtime");
                    last_renew_attempt = std::time::Instant::now();
                    // 热重启 hysteria（现有 respawn 逻辑接管新证书进程）
                    let _ = child.kill();
                } else {
                    last_renew_attempt = std::time::Instant::now() - std::time::Duration::from_secs(86400 - 3600); // 1h 后重试
                }
            } else {
                last_renew_attempt = std::time::Instant::now();
            }
        }
        if let Ok((200, _)) = ack(&did, "alive", epoch, &srv) {
            fails = 0;
            oks += 1;
            // hyproxy watchdog：masquerade 进程崩溃则拉起（非安全路径，不触发销毁）
            if proxy_child_started {
                let alive = proxy_child.as_mut().map(|c| c.try_wait().map(|w| w.is_none()).unwrap_or(false)).unwrap_or(false);
                if !alive {
                    eprintln!("HYPROXY_DOWN respawn");
                    match Command::new("/run/apps/hyproxy")
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::inherit())
                        .spawn()
                    {
                        Ok(pc) => { proxy_child = Some(pc); eprintln!("HYPROXY_RESPAWNED pid={}", proxy_child.as_ref().unwrap().id()); }
                        Err(e) => eprintln!("HYPROXY_RESPAWN_ERR {:?}", e.kind()),
                    }
                }
            }
            if test_mode && oks >= 2 {
                eprintln!("HYOS E2E SUCCESS");
                poweroff();
            }
        } else {
            fails += 1;
            eprintln!("HB_FAIL {}", fails);
            if fails >= 3 {
                let _ = child.kill();
                l5_wipe_all_and_off();
            }
        }
        if let Ok(Some(_)) = child.try_wait() {
            child = match {
                let mut cmd = Command::new(app_path);
                cmd.stdin(std::process::Stdio::null());
                cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
                cmd.spawn()
            } {
                Ok(c) => c,
                Err(_) => l3_wipe(&srv, &did, epoch, "respawn"),
            };
        }
    }
}

fn advance_slots(e: u64, wrap_sys_b64: &str, wrap_app_b64: &str, ck_hex: &str) {
    let mut ck = [0u8; 32];
    if hex_decode_into(ck_hex, &mut ck).is_err() {
        eprintln!("ADVANCE ck-decode fail");
        return;
    }
    let ws = match b64url_decode(wrap_sys_b64) {
        Some(v) if v.len() == WRAP_LEN => v,
        _ => { eprintln!("ADVANCE wrap_sys bad"); return; }
    };
    let wa = match b64url_decode(wrap_app_b64) {
        Some(v) if v.len() == WRAP_LEN => v,
        _ => { eprintln!("ADVANCE wrap_app bad"); return; }
    };
    let mut f = open_disk();
    let a2 = match read_at(&mut f, P2_START, 512) { Ok(v) => v, Err(_) => return };
    let a3 = match read_at(&mut f, P3_START, 512) { Ok(v) => v, Err(_) => return };
    let r1 = mk_slot(&mut f, &a2, &ws, P2_START, e, &ck);
    let r2 = mk_slot(&mut f, &a3, &wa, P3_START, e, &ck);
    let ok = r1.is_ok()
        && r2.is_ok()
        && read_at(&mut f, P2_START + 1, 512)
            .map(|b| b[480..512] == hmac32(&ck, &b[..480]))
            .unwrap_or(false)
        && read_at(&mut f, P3_START + 1, 512)
            .map(|b| b[480..512] == hmac32(&ck, &b[..480]))
            .unwrap_or(false);
    if ok {
        eprintln!("ADVANCE OK seq={}", e);
    } else {
        eprintln!("ADVANCE FAIL (dual-slot tolerance, retry next boot)");
    }
    hyproto::wipe(&mut ck);
}

fn mk_slot(f: &mut File, slot_a: &[u8], wrap: &[u8], base: u64, e: u64, ck: &[u8; 32]) -> std::io::Result<()> {
    let mut buf = vec![0u8; 512];
    buf[..8].copy_from_slice(b"HYOSLOT1");
    buf[8] = 1; // slot B
    buf[9..17].copy_from_slice(&e.to_be_bytes());
    buf[17..25].copy_from_slice(&e.to_be_bytes());
    buf[25..85].copy_from_slice(wrap);
    buf[85..117].copy_from_slice(&slot_a[85..117]);
    buf[117..125].copy_from_slice(&slot_a[117..125]);
    let mac = hmac32(ck, &buf[..480]);
    buf[480..512].copy_from_slice(&mac);
    write_at(f, base + 1, &buf)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "supervise" {
        let epoch: u64 = args[2].parse().unwrap_or(1);
        let srv = args.get(3).cloned().unwrap_or_else(|| "10.0.2.2:80".into());
        run_supervise(epoch, srv);
    } else {
        run_verify();
    }
}