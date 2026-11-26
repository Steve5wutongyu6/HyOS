# 生产部署 runbook

## 当前部署

- 设备：did=devaa6301ce84
- 镜像：build/dist/deploy-vmiss-gz-01.img（70189056 字节，sha256=a5e088ce4b4ecc43050667693fd94d5a101854ad3147243255857c69e50d998c）

## 镜像安全机制

- 引导配置存于 p2 加密载荷（AES-256-GCM 加载荷哈希），P1 分区无明文；配置由 hyverify_boot 从 hyram 内存盘读取执行，被篡改时校验失败并销毁。
- SELinux 始终 enforcing：enforce 写入后回读校验，挂载、策略加载、回读任一失败即清盘断电，无 permissive 开关。
- cmdline 开关 hy_test / hy_hb_ms / hy_srv 只认 VK_SIG 签名清单；epoch 以加密槽头为准，cmdline 值与之不一致即销毁。
- ACK 帧携带随机一次性 nonce，服务端对 (did, nonce) 单次消费，重放返回 409 err:replay；响应带 Ed25519 签名并按固定 SRV_PUB 校验，ACME DNS 通道同规则。
- supervisor 运行于独立的 hyos_init_t 域；机密（hyos_secret_t）、配置（hyos_app_conf_t）、可执行（hyos_app_exec_t）三类标签互相隔离，auth.env 交付后立即 unlink。
- 日志统一由 supervisor 输出，应用不可写 console/tty；iptables 所需的 CAP_NET_ADMIN 由 supervisor 域持有。
- hyproxy 上游 TLS 校验使用镜像内置 CA 包（/run/apps/ca.pem）；上游地址烘焙为 CF 边缘 IP（UPSTREAM_ADDR=104.21.0.204:443，SNI 为 nanachi.cloud），运行期不依赖 DNS。Pingora 的 pid/socket 位于 /run/hyos-tmp；内核 console 含 tty0，VNC 可见内核与 supervisor 日志。
- 服务端 ACME_DOMAIN 未配置时拒绝请求，不放行任意域名。

## 运行期 ACME

- Worker 机密：CF_DNS_TOKEN（仅 nanachi.cloud 的 DNS:Edit 权限）、CF_DNS_ZONE_ID=bd13257e9a4fd8951b7a23513539298a、ACME_DOMAIN=oa.nanachi.cloud。
- POST /v1/acme-dns 空体返回 400 bad_request，表示通道启用且白名单生效。
- 设备侧证书 60 天到期自动重签（DNS-01 经 Worker 代理），签发或续期失败回落内置证书。

## 部署与恢复流程

1. VMISS 面板重装 Debian 13。
2. scp 镜像与 scripts/deploy-v8.sh 到 /tmp。
3. bash /tmp/deploy-v8.sh /tmp/hyos.img /dev/vda 6ae35184abef360adf2ba8f80c40dbfbf39a0be3a6b04a259f9d0215845aa1a7
4. 约 90 秒后查询 D1 events，应看到设备依次经过 grub_ok → sys_ok → app_ok → alive。
5. 外部验证：TCP 80/443（hyproxy → nanachi.cloud）；UDP 443 与跳跃区间（Shadowrocket）。
6. 需要更换设备时，撤销旧设备，为新机器重新构建镜像并走一遍上述流程。
