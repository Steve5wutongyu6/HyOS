# 生产部署 runbook — v10（安全加固版）
# did=deva7d15dad6d  sha256=6ae35184abef360adf2ba8f80c40dbfbf39a0be3a6b04a259f9d0215845aa1a7
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

## 部署步骤
1. VMISS 面板重装 Debian 13
2. scp 镜像 + scripts/deploy-v8.sh 到 /tmp
3. bash /tmp/deploy-v8.sh /tmp/hyos.img /dev/vda 6ae35184abef360adf2ba8f80c40dbfbf39a0be3a6b04a259f9d0215845aa1a7
4. ~90s 后查 D1 events：deva7d15dad6d → grub_ok → sys_ok → app_ok → alive
5. 外部验证：TCP 80/443（hyproxy→nanachi.cloud）；UDP 443/跳跃区间（Shadowrocket）
6. 撤销旧设备 dev99bd01fc1a
