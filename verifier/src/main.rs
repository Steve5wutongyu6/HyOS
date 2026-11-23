//! HyOS initramfs verifier (PID1) + app supervisor
//! Same binary: no args = verifier (init); argv[1]=="supervise" = supervisor.
//! Static linked (x86_64 gnu + crt-static), no shell dependency.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;

mod genkeys;

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


fn net_ifup(name: &str, ip: [u8; 4], mask: [u8; 4]) -> bool {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 { return false; }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        let nb = name.as_bytes();
        let n = nb.len().min(15);
        for i in 0..n { ifr.ifr_name[i] = nb[i] as libc::c_char; }
        let sin_of = |ifr: &mut libc::ifreq| -> *mut libc::sockaddr_in {
            &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in
        };
        {
            let sin = sin_of(&mut ifr);
            (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
            (*sin).sin_port = 0;
            (*sin).sin_addr.s_addr = u32::from_ne_bytes(ip);
            if libc::ioctl(sock, libc::SIOCSIFADDR, &ifr) < 0 { libc::close(sock); return false; }
        }
        {
            let sin = sin_of(&mut ifr);
            (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
            (*sin).sin_port = 0;
            (*sin).sin_addr.s_addr = u32::from_ne_bytes(mask);
            if libc::ioctl(sock, libc::SIOCSIFNETMASK, &ifr) < 0 { libc::close(sock); return false; }
        }
        if libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) < 0 { libc::close(sock); return false; }
        let flags = unsafe { ifr.ifr_ifru.ifru_flags };
        unsafe { ifr.ifr_ifru.ifru_flags = flags | (libc::IFF_UP as libc::c_short) | (libc::IFF_RUNNING as libc::c_short); }
        if libc::ioctl(sock, libc::SIOCSIFFLAGS, &mut ifr) < 0 { libc::close(sock); return false; }
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

fn http_post(srv: &str, path: &str, body: &str) -> Result<(u16, String), String> {
    use std::net::TcpStream;
    let mut s = TcpStream::connect(srv).map_err(|e| e.to_string())?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: hyos\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        path, body.len(), body
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

fn ack(did: &str, stage: &str, epoch: u64, srv: &str) -> Result<(u16, String), String> {
    let nonce = hyproto::sha256(format!("{}|{}", stage, std::process::id()).as_bytes());
    let nonce_b64 = b64url_encode(&nonce);
    let msg = format!("{}|{}|{}|{}", did, stage, epoch, nonce_b64);
    let sig = dk_sign(&msg);
    let sig_hex = hex_encode(&sig); // 服务端按 hex 解析签名
    let body = format!(
        "{{\"did\":\"{}\",\"stage\":\"{}\",\"epoch\":{},\"nonce\":\"{}\",\"sig\":\"{}\"}}",
        did, stage, epoch, nonce_b64, sig_hex
    );
    http_post(srv, "/v1/ack", &body)
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
    let _ = ack(did, stage, epoch, srv);
    poweroff();
}

fn l5_wipe_all_and_off() -> ! {
    eprintln!("HYOS L5 WIPE");
    let mut f = open_disk();
    wipe_sectors(&mut f, P2_START, 2 + 16);
    wipe_sectors(&mut f, P3_START, 2 + 16);
    poweroff();
}

fn l3_wipe(srv: &str, did: &str, epoch: u64, tag: &str) -> ! {
    eprintln!("HYOS DESTROY[{}] wiping p3 (L3)", tag);
    let mut f = open_disk();
    wipe_sectors(&mut f, P3_START, 2 + 16);
    let _ = ack(did, "app_fail", epoch, srv);
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

fn run_verify() -> ! {
    mounts();
    // 降低内核控制台日志级别：避免 printk 与关键判定消息在串口交错，保证可审计性
    let _ = std::fs::write("/proc/sys/kernel/printk", "1 4 1 7");
    if net_ifup("eth0", [10, 0, 2, 15], [255, 255, 255, 0]) {
        eprintln!("NET UP eth0 10.0.2.15/24");
    } else {
        eprintln!("NET UP FAILED");
    }
    let cm = cmdline();
    let srv = cm.get("hy_srv").cloned().unwrap_or_else(|| "10.0.2.2:80".into());
    let epoch: u64 = cm.get("hy_epoch").and_then(|v| v.parse().ok()).unwrap_or(0);
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
        _ => l2_wipe_app_and_off(&srv, did, epoch, "grub_ok-refused"),
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

    let _ = std::fs::create_dir_all("/apps");
    let _ = std::fs::write("/apps/hello", &hello);
    let _ = std::fs::set_permissions("/apps/hello", std::os::unix::fs::PermissionsExt::from_mode(0o755));

    eprintln!("SYS_OK");
    let status = Command::new("/supervisor")
        .arg("supervise")
        .arg(epoch.to_string())
        .arg(&srv)
        .env("HY_CK", hex_encode(&ck))
        .env("HY_DID", did)
        .env("HY_HB_MS", cm.get("hy_hb_ms").cloned().unwrap_or_else(|| "300000".into()))
        .env("HY_TEST", cm.get("hy_test").cloned().unwrap_or_default())
        .status();
    match status {
        Ok(s) if s.success() => poweroff(),
        _ => l3_wipe(&srv, did, epoch, "supervisor-failed"),
    }
}

// ---------- supervisor ----------

fn run_supervise(epoch: u64, srv: String) -> ! {
    let did = std::env::var("HY_DID").unwrap_or_default();
    let ck_hex = std::env::var("HY_CK").unwrap_or_default();
    let mut ck = [0u8; 32];
    hex_decode_into(&ck_hex, &mut ck).expect("ck");
    let hb_ms: u64 = std::env::var("HY_HB_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(300000);
    let test_mode = std::env::var("HY_TEST").unwrap_or_default() == "1";

    // 应用 stdout/stderr 置空：避免与 supervisor 的串口标记交错，保持日志可判定
    let mut child = Command::new("/apps/hello")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|_| l3_wipe(&srv, &did, epoch, "spawn"));

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
    loop {
        std::thread::sleep(std::time::Duration::from_millis(hb_ms));
        if let Ok((200, _)) = ack(&did, "alive", epoch, &srv) {
            fails = 0;
            oks += 1;
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
            child = match Command::new("/apps/hello").spawn() {
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