# 生产部署 runbook（v12：安全加固 + masquerade 修复）

本轮部署的设备与镜像：

- 设备：did=devaa6301ce84
- 镜像：build/dist/deploy-vmiss-gz-01.img（70189056 字节，sha256=a5e088ce4b4ecc43050667693fd94d5a101854ad3147243255857c69e50d998c）

## 本轮安全修复（对应评审 8 项）

1. **grub.cfg 加密校验**。引导配置移入 p2 加密载荷（AES-256-GCM 加附带载荷哈希），P1 分区不再有任何明文内容。配置由 hyverify_boot 从 hyram 内存盘读取执行；配置遭到篡改时 GCM 或哈希校验会失败，随后进入销毁流程。
2. **SELinux 强制无后门**。删除了 hy_enforce=0 的 permissive 后门；enforce 写入后会回读校验结果。挂载、策略加载、回读三者任何一个失败都会触发清盘断电。
3. **未认证 cmdline 开关全部废弃**。hy_test / hy_hb_ms / hy_srv 此后只认 VK_SIG 签名清单；epoch 以加密槽头为准，cmdline 里的值与之不一致即销毁。
4. **ACK 帧加固**。请求携带随机一次性 nonce，服务端对 (did, nonce) 单次消费，重放返回 409 err:replay；响应带 Ed25519 签名并按固定 SRV_PUB 校验。伪造或重放的帧不再生效，ACME DNS 通道采用同样规则。
5. **supervisor 独立受限域**。exec 时通过 type_transition 进入 hyos_init_t（此前一直运行在 kernel_t）。
6. **机密/配置/可执行类型分离**。hyos_secret_t（auth.env、TLS 私钥）、hyos_app_conf_t（配置）、hyos_app_exec_t（二进制）三类标签互相隔离，neverallow 禁止机密与配置作为可执行入口；auth.env 交付后立即 unlink。
7. **权限面收口**。删除应用到 supervisor 的 fd/fifo 写通道；应用不再能写 console/tty（日志统一由 supervisor 输出）；应用不持有 net_admin/sys_admin（iptables 所需的 CAP_NET_ADMIN 由 supervisor 域执行）。
8. **服务端 ACME_DOMAIN 未配置时拒绝**，不再隐式放行任意域名。

## v12 相对 v10 的变更

- hyproxy 上游 TLS 校验改用镜像内置 CA 包（/run/apps/ca.pem，构建期从构建机复制）。最小镜像没有系统证书库，此前上游握手因此失败，伪装页面返回 502。
- 上游连接地址在构建期烘焙为 CF 边缘 IP（UPSTREAM_ADDR=104.21.0.204:443，SNI 仍为 nanachi.cloud），运行期不再依赖 DNS。
- Pingora 的 pid/upgrade socket 移到 /run/hyos-tmp（应用域不可写 rootfs 的 /tmp）。
- 内核 console 增加 tty0，VNC 现在能看到内核与 supervisor 日志（此前只有 ttyS0 串口）。

## 部署步骤

1. VMISS 面板重装 Debian 13。
2. scp 镜像与 scripts/deploy-v8.sh 到 /tmp。
3. 执行 bash /tmp/deploy-v8.sh /tmp/hyos.img /dev/vda 6ae35184abef360adf2ba8f80c40dbfbf39a0be3a6b04a259f9d0215845aa1a7
4. 约 90 秒后查询 D1 events，应看到 deva7d15dad6d 依次经过 grub_ok → sys_ok → app_ok → alive。
5. 外部验证：TCP 80/443（hyproxy → nanachi.cloud）；UDP 443 与跳跃区间（Shadowrocket）。
6. 撤销旧设备 dev99bd01fc1a。

## 运行期 ACME（2026-11-26 补齐）

- Worker 机密已设置：CF_DNS_TOKEN（新建的最小权限 token，权限仅 nanachi.cloud 的 DNS:Edit，未复用账户级令牌）、CF_DNS_ZONE_ID=bd13257e9a4fd8951b7a23513539298a、ACME_DOMAIN=oa.nanachi.cloud。
- 端到端验证：向 POST /v1/acme-dns 发送空体现在返回 400 bad_request（此前为 501 disabled），说明通道已启用且白名单生效。
- 设备侧：证书 60 天到期自动重签（DNS-01 经 Worker 代理），签发或续期失败时回落内置证书。

## 恢复工作（下次继续）

1. 在 VMISS 面板重装 Debian 13。
2. 执行与 deploy-to-vps.sh 等价的流程：把 build/dist/deploy-vmiss-gz-01.img（sha256 6ae35184…a1a7）与 scripts/deploy-v8.sh 传到 VPS，然后 bash deploy-v8.sh /tmp/hyos.img /dev/vda 6ae35184abef360adf2ba8f80c40dbfbf39a0be3a6b04a259f9d0215845aa1a7。
3. 约 90 秒后 D1 事件应为 deva7d15dad6d provisioned → grub_ok → sys_ok → app_ok（status active）。
4. 外部验证：TCP 80/443 → nanachi.cloud；UDP 443 / 20000-30000 / 40000-60000 → hysteria2(:8443)。
5. 旧设备 dev99bd01fc1a 撤销（已确认不再关注）。
