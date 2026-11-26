# 生产部署 runbook — v12（安全加固 + masquerade 修复）
# did=devaa6301ce84  sha256=a5e088ce4b4ecc43050667693fd94d5a101854ad3147243255857c69e50d998c
# 镜像：build/dist/deploy-vmiss-gz-01.img（70189056 B）

## 本轮安全修复（对应评审 8 项）
1. grub.cfg 加密校验：引导配置移入 p2 加密载荷（AES-256-GCM + 载荷哈希），P1 不再有明文；
   由 hyverify_boot 从 (hyram) 读取执行，篡改即 GCM/哈希失败→销毁。
2. SELinux 强制无后门：删除 hy_enforce=0 的 permissive 后门；enforce 写入结果校验回读，
   挂载/策略/回读任一失败 → destroy_all_and_off（清 p2+p3 头后断电）。
3. 未认证 cmdline 开关全部废弃：hy_test / hy_hb_ms / hy_srv 只认 VK_SIG 签名清单；
   epoch 以加密槽头为准（cmdline 值不一致即销毁）。
4. ACK 帧加固：随机一次性 nonce + 服务端 (did,nonce) 单次消费（重放→409 err:replay）
   + 响应 Ed25519 签名（固定 SRV_PUB 校验，伪造/重放帧不再生效）；ACME DNS 通道同规则。
5. supervisor 独立受限域：exec 时 type_transition 进入 hyos_init_t（此前一直以 kernel_t 运行）。
6. 机密/配置/可执行类型分离：hyos_secret_t（auth.env、TLS 私钥）/ hyos_app_conf_t（配置）
   / hyos_app_exec_t（二进制），neverallow 机密与配置作为可执行入口；auth.env 交付后立即 unlink。
7. 权限面收口：删除 app→supervisor 的 fd/fifo 写；禁用应用写 console/tty（日志只由 supervisor 输出）；
   应用不得 net_admin/sys_admin（iptables 需 CAP_NET_ADMIN，故在 supervisor 域执行）。
8. 服务端 ACME_DOMAIN 未配置时拒绝（不再隐式放行任意域名）。

## v12 变更（相对 v10）
- hyproxy 上游 TLS 校验改用镜像内置 CA 包（/run/apps/ca.pem，构建期从构建机复制）——
  最小镜像无系统证书库，此前导致上游握手失败 → 伪装页面 502
- 上游连接地址构建期烘焙为 CF 边缘 IP（UPSTREAM_ADDR=104.21.0.204:443，SNI 仍为 nanachi.cloud），
  不依赖运行期 DNS
- Pingora 的 pid/upgrade socket 改到 /run/hyos-tmp（应用域不可写 rootfs /tmp）
- 内核 console 增加 tty0：VNC 现在能看到内核与 supervisor 日志（此前只有 ttyS0 串口）

## 部署步骤
1. VMISS 面板重装 Debian 13
2. scp 镜像 + scripts/deploy-v8.sh 到 /tmp
3. bash /tmp/deploy-v8.sh /tmp/hyos.img /dev/vda 6ae35184abef360adf2ba8f80c40dbfbf39a0be3a6b04a259f9d0215845aa1a7
4. ~90s 后查 D1 events：deva7d15dad6d → grub_ok → sys_ok → app_ok → alive
5. 外部验证：TCP 80/443（hyproxy→nanachi.cloud）；UDP 443/跳跃区间（Shadowrocket）
6. 撤销旧设备 dev99bd01fc1a

## 运行期 ACME（本轮已补齐，2026-11-26）
- Worker 机密已设置：`CF_DNS_TOKEN`（**新建最小权限 token：仅 nanachi.cloud 的 DNS:Edit**，未复用账户级 cfat 令牌）、
  `CF_DNS_ZONE_ID`=`bd13257e9a4fd8951b7a23513539298a`、`ACME_DOMAIN`=`oa.nanachi.cloud`
- 端到端验证：POST /v1/acme-dns 空体返回 400 bad_request（此前为 501 disabled）→ 通道已启用且白名单生效
- 设备侧：60 天到期自动重签（DNS-01 经 Worker 代理），签发/续期失败回落内置证书

## 恢复工作（下次继续）
1. 用户在 VMISS 面板重装 Debian 13
2. `bash /tmp/deploy-to-vps.sh` 等价流程：
   - scp `build/dist/deploy-vmiss-gz-01.img`（sha256 6ae35184…a1a7）与 `scripts/deploy-v8.sh` 到 VPS
   - `bash deploy-v8.sh /tmp/hyos.img /dev/vda 6ae35184abef360adf2ba8f80c40dbfbf39a0be3a6b04a259f9d0215845aa1a7`
3. ~90 s 后 D1 事件应为：`deva7d15dad6d` provisioned → grub_ok → sys_ok → app_ok（status active）
4. 外部验证：TCP 80/443 → nanachi.cloud；UDP 443 / 20000-30000 / 40000-60000 → hysteria2(:8443)
5. 旧设备 `dev99bd01fc1a` 撤销（按用户要求已不再关注）
