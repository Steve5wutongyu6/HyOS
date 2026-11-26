// HyOS masquerade 反代（Pingora 裁剪版）
// 只保留：TLS 终结(443) + 明文(80) → 单一 HTTPS 上游
// 裁剪掉：负载均衡 / 健康检查 / 限流与计数 / 前置连接过滤 / 生命周期钩子(Filters)
// 参数来自 /run/apps/proxy.conf（KEY=VALUE），由配置仓库渲染注入
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::upstreams::peer::HttpPeer;

struct Masq {
    upstream_addr: String, // 连接地址 host:port（可用 IP，避免依赖 DNS）
    upstream_sni: String,  // 上游 SNI / Host 头
}

#[async_trait]
impl ProxyHttp for Masq {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, _s: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let peer = HttpPeer::new(self.upstream_addr.clone(), true, self.upstream_sni.clone());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.insert_header("Host", &self.upstream_sni)?;
        Ok(())
    }
}

fn load_conf(path: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Ok(s) = std::fs::read_to_string(path) {
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                m.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    m
}

/// 应用日志/pid/socket 落在私有 tmpfs（应用域只对 /run/hyos-tmp 有写权限）
const RUN_DIR: &str = "/run/hyos-tmp";

fn main() {
    let conf = load_conf("/run/apps/proxy.conf");
    // 应用层参数全部来自 HysteriaConfig 渲染出的 proxy.conf；缺失即失败（不留隐藏默认值）
    let req = |k: &str| -> String {
        match conf.get(k) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => {
                eprintln!("HYPROXY_CONF_MISSING {}", k);
                std::process::exit(3);
            }
        }
    };
    let upstream = req("UPSTREAM_URL");
    let sni = req("UPSTREAM_HOST");
    let addr = req("UPSTREAM_ADDR");
    let http_addr = req("LISTEN_HTTP");
    let https_addr = req("LISTEN_HTTPS");
    let cert = req("TLS_CERT");
    let key = req("TLS_KEY");
    let ca_bundle = req("CA_BUNDLE");

    let _ = std::fs::create_dir_all(RUN_DIR);

    // Pingora 默认把 pid/upgrade socket 放 /tmp（应用域不可写 rootfs）→ 改到私有 tmpfs
    let mut sc = ServerConf::default();
    sc.daemon = false;
    sc.pid_file = format!("{}/hyproxy.pid", RUN_DIR);
    sc.upgrade_sock = format!("{}/hyproxy_upgrade.sock", RUN_DIR);
    sc.threads = 2;
    // 上游 TLS 校验使用镜像内置 CA 包（最小镜像无系统证书库）
    if std::path::Path::new(&ca_bundle).exists() {
        sc.ca_file = Some(ca_bundle.clone());
    }

    let app = Masq { upstream_addr: addr.clone(), upstream_sni: sni.clone() };
    let mut server = Server::new_with_opt_and_conf(None::<Opt>, sc);
    server.bootstrap();

    // 生效的 CA 配置（诊断：确认是否真的用上了内置 CA 包）
    eprintln!(
        "HYPROXY_UP http={} https={} upstream={} addr={} sni={} ca={}",
        http_addr,
        https_addr,
        upstream,
        addr,
        sni,
        server.configuration.ca_file.clone().unwrap_or_else(|| "(none)".into())
    );

    let mut service = http_proxy_service(&server.configuration, app);
    service.add_tcp(&http_addr);
    let tls = TlsSettings::intermediate(&cert, &key).expect("tls settings load");
    service.add_tls_with_settings(&https_addr, None, tls);
    server.add_service(service);
    server.run_forever();
}
