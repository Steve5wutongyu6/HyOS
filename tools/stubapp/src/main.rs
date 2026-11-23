// 联调用 stub 应用：--probe 在受限域内做权限探测；否则输出心跳（M5 换裁剪版 hysteria2）

fn try_open(path: &str) -> String {
    match std::fs::File::open(path) {
        Ok(_) => "ALLOWED".to_string(),
        Err(e) => format!("DENIED({})", e.raw_os_error().unwrap_or(-1)),
    }
}

fn try_write(path: &str) -> String {
    match std::fs::write(path, b"hyos-probe") {
        Ok(_) => "ALLOWED".to_string(),
        Err(e) => format!("DENIED({})", e.raw_os_error().unwrap_or(-1)),
    }
}

fn probe() {
    println!("BLKDEV_OPEN={}", try_open("/dev/sda"));
    println!("CONFIG_WRITE={}", try_write("/etc/hysteria/evil"));
    println!("TMP_WRITE={}", try_write("/run/hyos-tmp/scratch"));
    println!("ETC_WRITE={}", try_write("/etc/evil"));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--probe" {
        probe();
        return;
    }
    loop {
        println!("APP ALIVE");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}