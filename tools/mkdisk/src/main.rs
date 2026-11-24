//! mkdisk —— HyOS 部署镜像组装（manifest 生成 / 白盒份额补丁 / 分区装配）
//! 用法：
//!   mkdisk manifest --core <core.img> --keys <fixture.json> --out-dir <dir>
//!   mkdisk disk --core <core.img> --vmlinuz <vmlinuz> --initrd <initrd.img>
//!               --hello <hello.bin> --keys <fixture.json> --grubtree <grub-2.12 源树>
//!               --work <临时目录> --out <deploy.img> [--app-pin-mismatch]

use hyproto::{
    aead_seal, ed25519_sign, hkdf_sha256_raw, kek_app, kek_sys, sha256,
    SlotHeader, WRAP_LEN,
};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Keys {
    #[allow(dead_code)]
    did: String,
    sig_seed_hex: String,
    wk0_root: String,
    wk1_root: String,
    dek_sys: String,
    dek_app: String,
}

/// 极简 JSON 字段提取（fixture 结构固定，值均为字符串）
fn json_field(json: &str, key: &str) -> String {
    let pat = format!("\"{}\": \"", key);
    let pat2 = format!("\"{}\":\"", key);
    let idx = json.find(&pat).map(|i| i + pat.len())
        .or_else(|| json.find(&pat2).map(|i| i + pat2.len()));
    let start = idx.expect("missing key in fixture");
    let rest = &json[start..];
    let end = rest.find('"').expect("unterminated value");
    rest[..end].to_string()
}

const P1_START: u64 = 2048;
const P2_START: u64 = 4096;
const P3_START: u64 = 36864;
const P4_START: u64 = 136864; // app 分区扩容（hysteria 25MB）后挪
const DISK_SECTORS: u64 = 137088; // 66.9 MiB（P3 扩至 ~49MB 容纳 hysteria 应用包）
const SECTOR: u64 = 512;
const PAYLOAD_OFF: u64 = 8;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn hex_enc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn load_keys(p: &Path) -> Keys {
    let txt = std::fs::read_to_string(p).expect("keys file");
    Keys {
        did: json_field(&txt, "did"),
        sig_seed_hex: json_field(&txt, "sig_seed_hex"),
        wk0_root: json_field(&txt, "wk0_root"),
        wk1_root: json_field(&txt, "wk1_root"),
        dek_sys: json_field(&txt, "dek_sys"),
        dek_app: json_field(&txt, "dek_app"),
    }
}

fn run(cmd: &mut Command) {
    let st = cmd.status().expect("spawn");
    if !st.success() {
        panic!("command failed: {:?}", cmd);
    }
}

/// cpio newc 打包
fn cpio_newc(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ino = 1u32;
    for (name, data) in files {
        let mut hdr = String::new();
        let fields: Vec<String> = vec![
            format!("{:08X}", ino),
            format!("{:08X}", 0o100755), // mode: regular executable
            format!("{:08X}", 0),
            format!("{:08X}", 1),
            format!("{:08X}", 0),
            format!("{:08X}", 0),
            format!("{:08X}", data.len()),
            format!("{:08X}", 0),
            format!("{:08X}", 0),
            format!("{:08X}", 0),
            format!("{:08X}", 0),
            format!("{:08X}", name.len() + 1),
            format!("{:08X}", 0),
        ];
        hdr.push_str("070701");
        for f in fields {
            hdr.push_str(&f);
        }
        out.extend_from_slice(hdr.as_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        ino += 1;
    }
    let trailer = b"TRAILER!!!";
    // newc 头:magic + 13 个 8 位字段(ino mode uid gid nlink mtime filesize devmajor devminor rdevmajor rdevminor namesize check)
    let mut hdr = String::from("070701");
    for _ in 0..11 {
        hdr.push_str("00000000");
    }
    hdr.push_str(&format!("{:08X}", trailer.len() + 1)); // namesize
    hdr.push_str("00000000"); // check
    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(trailer);
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn ck_of(keys: &Keys, epoch: u64) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&hex(&keys.wk0_root));
    buf.extend_from_slice(&hex(&keys.wk1_root));
    buf.push((epoch & 0xff) as u8);
    sha256(&buf)
}

fn payload_seal(dek: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let nonce = {
        let mut info = Vec::with_capacity(13);
        info.extend_from_slice(b"payload-nonce");
        hkdf_sha256_raw(dek, &info)
    };
    let mut nonce12 = [0u8; 12];
    nonce12.copy_from_slice(&nonce[..12]);
    aead_seal(dek, &nonce12, pt, b"hyos-payload")
}

fn write_slot_a(img: &mut [u8], base: u64, seq: u64, epoch: u64, pt_sha: [u8; 32], ct_len: u64,
                kek: [u8; 32], dek: [u8; 32], ck: [u8; 32]) {
    let h = SlotHeader { slot_id: 0, seq, epoch, img_sha256: pt_sha, payload_len: ct_len };
    let buf = h.encode(&kek, &dek, &ck);
    let off = (base as usize) * 512;
    img[off..off + 512].copy_from_slice(&buf);
}

fn build_sys_fat(work: &Path, vmlinuz: &Path, initrd: &Path) -> Vec<u8> {
    let fat = work.join("sysfat.img");
    let _ = std::fs::remove_file(&fat);
    std::fs::write(&fat, vec![0u8; 32704 * 512]).expect("fat size");
    run(Command::new("mformat").args([
        "-i", fat.to_str().unwrap(), "-C", "-t", "8176", "-h", "4", "-s", "1", "::",
    ]));
    run(Command::new("mmd").args([
        "-i", fat.to_str().unwrap(), "::/boot",
    ]));
    run(Command::new("mcopy").args([
        "-i", fat.to_str().unwrap(), vmlinuz.to_str().unwrap(), "::/boot/vmlinuz",
    ]));
    run(Command::new("mcopy").args([
        "-i", fat.to_str().unwrap(), initrd.to_str().unwrap(), "::/boot/initrd.img",
    ]));
    std::fs::read(&fat).expect("sysfat read")
}

fn build_p1_fat(work: &Path, grub_cfg: &Path, grub_manifest: &Path) -> Vec<u8> {
    let fat = work.join("p1fat.img");
    let _ = std::fs::remove_file(&fat);
    std::fs::write(&fat, vec![0u8; 2048 * 512]).expect("p1 size");
    run(Command::new("mformat").args([
        "-i", fat.to_str().unwrap(), "-C", "-t", "128", "-h", "4", "-s", "4", "::",
    ]));
    run(Command::new("mmd").args([
        "-i", fat.to_str().unwrap(), "::/boot",
    ]));
    run(Command::new("mmd").args([
        "-i", fat.to_str().unwrap(), "::/boot/grub",
    ]));
    run(Command::new("mcopy").args([
        "-i", fat.to_str().unwrap(), grub_cfg.to_str().unwrap(), "::/boot/grub/grub.cfg",
    ]));
    run(Command::new("mcopy").args([
        "-i", fat.to_str().unwrap(), grub_manifest.to_str().unwrap(), "::/grub.manifest",
    ]));
    std::fs::read(&fat).expect("p1 read")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args[1].clone();

    if mode == "manifest" {
        // mkdisk manifest --core core.img --keys keys.json --out-dir dir
        let core = PathBuf::from(&args[3]);
        let keys_p = PathBuf::from(&args[5]);
        let out_dir = PathBuf::from(&args[7]);
        let keys = load_keys(&keys_p);
        let _ = keys;
        let mut core_bytes = std::fs::read(&core).expect("core.img");
        // 与部署时一致的块列表补丁（保证窗口哈希与实际镜像一致）
        let core_sectors_m = ((core_bytes.len() + 511) / 512) as u64;
        let rest_m = core_sectors_m - 1;
        core_bytes[0x1F4..0x1FC].copy_from_slice(&2u64.to_le_bytes());
        core_bytes[0x1FC..0x1FE].copy_from_slice(&(rest_m as u16).to_le_bytes());
        core_bytes[0x1FE..0x200].copy_from_slice(&0x0820u16.to_le_bytes());
        // 窗口 = LBA1..2047（core + 零填充）
        let mut window = core_bytes;
        window.resize((2047 * 512) as usize, 0);
        let window_sha = sha256(&window);
        let mut body = String::new();
        body.push_str("os_ver=0.1
");
        body.push_str("grub_pin_ver=1
");
        body.push_str(&format!("grub_pin_img={}
", hex_enc(&window_sha)));
        // 目标参数注入（一机一镜像）：网络与密钥服务地址进签名清单，防篡改
        let getv = |name: &str| -> Option<String> {
            args.iter().position(|a| a == name).map(|i| args[i + 1].clone())
        };
        if let Some(v) = getv("--net-ip") {
            body.push_str(&format!("hy_net_ip={}
", v));
        }
        if let Some(v) = getv("--net-mask") {
            body.push_str(&format!("hy_net_mask={}
", v));
        }
        if let Some(v) = getv("--net-gw") {
            body.push_str(&format!("hy_net_gw={}
", v));
        }
        if let Some(v) = getv("--srv") {
            body.push_str(&format!("hy_srv={}
", v));
        }
        if let Some(v) = getv("--srv-host") {
            body.push_str(&format!("hy_srv_host={}
", v));
        }
        if args.iter().any(|a| a == "--tls") {
            body.push_str("hy_tls=1
");
        }
        if let Some(i) = args.iter().position(|a| a == "--acme-domain") {
            body.push_str(&format!("hy_acme_domain={}
", args[i + 1]));
        }
        if args.iter().any(|a| a == "--acme-staging") {
            body.push_str("hy_acme_staging=1
");
        }
        if let Some(v) = getv("--srv-host") {
            body.push_str(&format!("hy_srv_host={}
", v));
        }
        std::fs::create_dir_all(&out_dir).ok();
        let body_p = out_dir.join("system.manifest");
        std::fs::write(&body_p, &body).expect("write manifest");
        let seed = hex(&keys.sig_seed_hex);
        let mut seed32 = [0u8; 32];
        seed32.copy_from_slice(&seed);
        let sig = ed25519_sign(&seed32, body.as_bytes());
        std::fs::write(out_dir.join("system.manifest.sig"), sig).expect("write sig");
        println!("MANIFEST OK {}", body_p.display());
        return;
    }

    if mode != "disk" {
        panic!("usage: mkdisk manifest|disk ...");
    }
    // mkdisk disk --core X --vmlinuz V --initrd I --hello H --keys K --grubtree G --work W --out O [--app-pin-mismatch]
    let get = |name: &str| -> PathBuf {
        let i = args.iter().position(|a| a == name).expect(name);
        PathBuf::from(&args[i + 1])
    };
    let app_pin_mismatch = args.iter().any(|a| a == "--app-pin-mismatch");
    let core = get("--core");
    let vmlinuz = get("--vmlinuz");
    let initrd = get("--initrd");
    let hello = get("--hello");
    let keys_p = get("--keys");
    let grubtree = get("--grubtree");
    let work = get("--work");
    let out = get("--out");
    // 可选应用文件（M5：真 hysteria2 应用包；缺省保持 stubapp-only 兼容）
    let opt = |name: &str| -> Option<PathBuf> {
        args.iter().position(|a| a == name).map(|i| PathBuf::from(&args[i + 1]))
    };
    let hysteria = opt("--hysteria");
    let hyauth = opt("--hyauth");
    let app_config = opt("--app-config");
    let auth_env = opt("--auth-env");
    let tls_cert = opt("--tls-cert");
    let tls_key = opt("--tls-key");

    let keys = load_keys(&keys_p);
    std::fs::create_dir_all(&work).ok();

    // ---- 应用 cpio ----
    let hello_bytes = std::fs::read(&hello).expect("hello");
    let mut app_body = String::new();
    app_body.push_str("app_ver=0.1
");
    if app_pin_mismatch {
        app_body.push_str("os_pin=0.2
"); // 故意不匹配 → L3 注入
    } else {
        app_body.push_str("os_pin=0.1
");
    }
    if hysteria.is_some() {
        app_body.push_str("entry=hysteria
");
    } else {
        app_body.push_str("entry=hello
");
    }
    app_body.push_str(&format!("file_hello={}
", hex_enc(&sha256(&hello_bytes))));
    let hysteria_bytes = hysteria.as_ref().map(|p| std::fs::read(p).expect("hysteria bin"));
    let hyauth_bytes = hyauth.as_ref().map(|p| std::fs::read(p).expect("hyauth bin"));
    let config_bytes = app_config.as_ref().map(|p| std::fs::read(p).expect("app config"));
    if let Some(b) = &hysteria_bytes {
        app_body.push_str(&format!("file_hysteria={}
", hex_enc(&sha256(b))));
    }
    if let Some(b) = &hyauth_bytes {
        app_body.push_str(&format!("file_hyauth={}
", hex_enc(&sha256(b))));
    }
    if let Some(b) = &config_bytes {
        app_body.push_str(&format!("file_config={}
", hex_enc(&sha256(b))));
    }
    let authenv_bytes = auth_env.as_ref().map(|p| std::fs::read(p).expect("auth env"));
    let tlscert_bytes = tls_cert.as_ref().map(|p| std::fs::read(p).expect("tls cert"));
    let tlskey_bytes = tls_key.as_ref().map(|p| std::fs::read(p).expect("tls key"));
    if let Some(b) = &authenv_bytes {
        app_body.push_str(&format!("file_authenv={}
", hex_enc(&sha256(b))));
    }
    if let Some(b) = &tlscert_bytes {
        app_body.push_str(&format!("file_tlscert={}
", hex_enc(&sha256(b))));
    }
    if let Some(b) = &tlskey_bytes {
        app_body.push_str(&format!("file_tlskey={}
", hex_enc(&sha256(b))));
    }
    let seed = hex(&keys.sig_seed_hex);
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(&seed);
    let app_sig = ed25519_sign(&seed32, app_body.as_bytes());
    let mut app_files: Vec<(&str, Vec<u8>)> = vec![
        ("apps/app.manifest", app_body.into_bytes()),
        ("apps/app.manifest.sig", app_sig.to_vec()),
        ("apps/hello", hello_bytes),
    ];
    if let Some(b) = &hysteria_bytes {
        app_files.push(("apps/hysteria", b.clone()));
    }
    if let Some(b) = &hyauth_bytes {
        app_files.push(("apps/hyauth", b.clone()));
    }
    if let Some(b) = &config_bytes {
        app_files.push(("apps/config.yaml", b.clone()));
    }
    if let Some(b) = &authenv_bytes {
        app_files.push(("apps/auth.env", b.clone()));
    }
    if let Some(b) = &tlscert_bytes {
        app_files.push(("apps/tls/fullchain.pem", b.clone()));
    }
    if let Some(b) = &tlskey_bytes {
        app_files.push(("apps/tls/key.pem", b.clone()));
    }
    let cpio = cpio_newc(&app_files);

    // ---- 载荷加密 ----
    let dek_sys: [u8; 32] = hex(&keys.dek_sys).try_into().unwrap();
    let dek_app: [u8; 32] = hex(&keys.dek_app).try_into().unwrap();
    let sysfat = build_sys_fat(&work, &vmlinuz, &initrd);
    let sys_sha = sha256(&sysfat);
    let sys_ct = payload_seal(&dek_sys, &sysfat);
    let app_sha = sha256(&cpio);
    let app_ct = payload_seal(&dek_app, &cpio);
    assert!(sys_ct.len() <= (32760 * 512) as usize, "sys payload too big");
    assert!(app_ct.len() <= (99000 * 512) as usize, "app payload too big");

    // ---- 组装镜像 ----
    let mut img = vec![0u8; (DISK_SECTORS * SECTOR) as usize];
    // MBR 分区表
    let part = |img: &mut Vec<u8>, idx: usize, boot: bool, lba: u64, n: u64, ty: u8| {
        let off = 0x1BE + idx * 16;
        img[off] = if boot { 0x80 } else { 0x00 };
        img[off + 4] = ty;
        // CHS 起始随便填合法值（BIOS/grub 用 LBA）
        img[off + 1] = 0xFE; img[off + 2] = 0xFF; img[off + 3] = 0xFF;
        img[off + 8..off + 12].copy_from_slice(&(lba as u32).to_le_bytes());
        img[off + 12..off + 16].copy_from_slice(&((n) as u32).to_le_bytes());
    };
    part(&mut img, 0, true, P1_START, 4095 - P1_START + 1, 0x0C);
    part(&mut img, 1, false, P2_START, 36863 - P2_START + 1, 0xDA);
    part(&mut img, 2, false, P3_START, 45055 - P3_START + 1, 0xDA);
    part(&mut img, 3, false, P4_START, 63, 0xDA);
    img[510] = 0x55;
    img[511] = 0xAA;
    // ---- 手动嵌入 GRUB（boot.img + diskboot 块列表 patch，确定性安装）----
    let boot_img = std::fs::read(grubtree.join("grub-core/boot.img")).expect("boot.img");
    assert_eq!(boot_img.len(), 512);
    let mut core_patched = std::fs::read(&core).expect("core.img");
    let core_sectors = ((core_patched.len() + 511) / 512) as u64;
    assert!(core_sectors <= 2046, "core.img too big for MBR gap");
    let rest = core_sectors - 1;
    core_patched[0x1F4..0x1FC].copy_from_slice(&2u64.to_le_bytes());
    core_patched[0x1FC..0x1FE].copy_from_slice(&(rest as u16).to_le_bytes());
    core_patched[0x1FE..0x200].copy_from_slice(&0x0820u16.to_le_bytes());
    img[0..446].copy_from_slice(&boot_img[..446]);
    let core_end = 512 + core_patched.len();
    assert!(core_end <= 2047 * 512, "core does not fit in gap");
    img[512..core_end].copy_from_slice(&core_patched);
    std::fs::write(&out, &img).expect("img write");
    println!("MANUAL EMBED OK core_sectors={}", core_sectors);

    // ---- 窗口哈希（LBA1..2047，含已嵌入的 core）----
    let mut window = img[512..(2048 * 512) as usize].to_vec();
    window.resize((2047 * 512) as usize, 0);
    let window_sha = sha256(&window);

    // ---- 写分区内容 ----
    let mut img_mut = img;
    // p1 fat（含 grub.cfg 与 grub.manifest；manifest 绑定 window_sha）
    let cfg = match args.iter().position(|a| a == "--cfg") {
        Some(i) => PathBuf::from(&args[i + 1]),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../grub/grub.cfg"),
    };
    // p1 grub.manifest：hyverify 自校验用的二进制格式
    // [0..8)="HYGRUB1\0" [8..12)=grub_ver [12..44)=window_sha [44..64)=0 [64..128)=sig(bytes[0..64))
    let mut man = vec![0u8; 64];
    man[..8].copy_from_slice(b"HYGRUB1\0");
    man[8..12].copy_from_slice(&1u32.to_be_bytes());
    man[12..44].copy_from_slice(&window_sha);
    let sig = ed25519_sign(&seed32, &man);
    man.extend_from_slice(&sig);
    let man_p = work.join("grub.manifest");
    std::fs::write(&man_p, &man).expect("grub.manifest");
    let p1 = build_p1_fat(&work, &cfg, &man_p);
    let off1 = (P1_START * 512) as usize;
    img_mut[off1..off1 + p1.len()].copy_from_slice(&p1);

    // p2：槽 A + 加密系统载荷
    let ck = ck_of(&keys, 1);
    write_slot_a(&mut img_mut, P2_START, 1, 1, sys_sha, sys_ct.len() as u64,
                 kek_sys(&hex(&keys.wk0_root).try_into().unwrap(), 1), dek_sys, ck);
    let off2 = ((P2_START + PAYLOAD_OFF) * 512) as usize;
    img_mut[off2..off2 + sys_ct.len()].copy_from_slice(&sys_ct);
    // p3：槽 A + 加密应用 cpio
    write_slot_a(&mut img_mut, P3_START, 1, 1, app_sha, app_ct.len() as u64,
                 kek_app(&hex(&keys.wk1_root).try_into().unwrap(), 1), dek_app, ck);
    let off3 = ((P3_START + PAYLOAD_OFF) * 512) as usize;
    img_mut[off3..off3 + app_ct.len()].copy_from_slice(&app_ct);
    // p4：构建指纹
    let fp = format!("HYOS-BUILD {}
", hex_enc(&sha256(&img_mut[..(2048 * 512) as usize])));
    let off4 = (P4_START * 512) as usize;
    img_mut[off4..off4 + fp.len()].copy_from_slice(fp.as_bytes());

    std::fs::write(&out, &img_mut).expect("final write");
    println!("DISK OK {} sys_ct={} app_ct={}", out.display(), sys_ct.len(), app_ct.len());
}