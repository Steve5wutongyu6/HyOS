// HyOS masquerade 反代（Pingora 裁剪版）
// 只保留：TLS 终结(443) + 明文(80) → 单一 HTTPS 上游
// 裁剪掉：负载均衡 / 健康检查 / 限流与计数 / 前置连接过滤 / 生命周期钩子(Filters)
// 参数来自 /run/apps/proxy.conf（KEY=VALUE），由配置仓库渲染注入
use async_trait::async_trait;
use std::collections::HashMap;

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;

struct Masq {
    upstream_addr: String, // host:port
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
                m.insert(k.to_string(), v.to_string());
            }
        }
    }
    m
}

fn main() {
    let conf = load_conf("/run/apps/proxy.conf");
    let upstream = conf.get("UPSTREAM_URL").cloned().unwrap_or_else(|| "https://nanachi.cloud".into());
    let sni = conf.get("UPSTREAM_HOST").cloned().unwrap_or_else(|| "nanachi.cloud".into());
    let http_addr = conf.get("LISTEN_HTTP").cloned().unwrap_or_else(|| "0.0.0.0:80".into());
    let https_addr = conf.get("LISTEN_HTTPS").cloned().unwrap_or_else(|| "0.0.0.0:443".into());
    let cert = conf.get("TLS_CERT").cloned().unwrap_or_else(|| "/run/apps/tls/fullchain.pem".into());
    let key = conf.get("TLS_KEY").cloned().unwrap_or_else(|| "/run/apps/tls/key.pem".into());

    // UPSTREAM_URL = https://host[:port] → HttpPeer 需要 host:port
    let addr = upstream
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(&sni)
        .to_string();
    let addr = if addr.contains(':') { addr } else { format!("{}:443", addr) };

    let app = Masq { upstream_addr: addr, upstream_sni: sni };
    let mut server = Server::new(None).expect("server init");
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, app);
    service.add_tcp(&http_addr);
    let tls = TlsSettings::intermediate(&cert, &key).expect("tls settings load");
    service.add_tls_with_settings(&https_addr, None, tls);
    server.add_service(service);
    eprintln!("HYPROXY_UP http={} https={} upstream={}", http_addr, https_addr, upstream);
    server.run_forever();
}
