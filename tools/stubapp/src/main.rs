// 联调用 stub 应用：每 500ms 打印心跳（M5 换裁剪版 hysteria2）
fn main() {
    loop {
        println!("APP ALIVE");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
