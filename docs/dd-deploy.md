# HyOS DD 部署手册（BIOS 云主机）

> 前提阅读：《Lima 联调验证报告》§8（SELinux）§9（内核裁剪/部署注入/TLS）。

## 1. 核心约束（违反即设备自毁）

| 约束 | 原因 |
|---|---|
| **一机一镜像** | 镜像内含设备专属密钥与 epoch；同一镜像写入第二台机器，epoch 回滚 → L3 销毁 |
| 目标机 **BIOS/Legacy 引导** | GRUB 为 i386-pc 构建，UEFI 未支持 |
| `--srv` 的 CF 边缘 IP **必须有效** | IP 退役 → 密钥服务不可达 → L5 销毁（fail-closed） |
| CMOS 电池正常 | TLS 证书校验依赖 RTC 真实时间，时钟停摆 → 握手失败 → 销毁 |
| 明确知道自己在做什么 | 任何验证失败都是销毁，没有"重试"——这是设计而非缺陷 |

## 2. 构建目标镜像（每台机器一次）

在 Lima 客机（hyos-dev）执行：

```bash
cd /mnt/vmiss/hyos-build
CI_TOKEN=$(grep '^CI_TOKEN=' /mnt/vmiss/hyos-prod-secrets.env | cut -d= -f2-) \
bash scripts/build-for-target.sh \
  --name vmiss-gz-01 \
  --net-ip   <VPS 公网 IP> \
  --net-mask <掩码，通常 255.255.255.0 或运营商给定> \
  --net-gw   <网关，通常 x.x.x.1 或运营商给定> \
  --srv      "104.21.0.204:443@hyos.nanachi.cloud" \
  --tls
```

脚本自动完成：全新设备密钥生成 → 生产库注册 → 用户态/GRUB 重建（绑定新密钥）→ 清单签名注入（网络参数 + TLS 开关）→ 镜像组装 → **R2 上传 + sha256 远端校验**。

产出（部署单）：

```
target=vmiss-gz-01 did=devXXXXXXXXXX
img=build/dist/deploy-vmiss-gz-01.img
sha256=...
r2=hyos-artifacts/hyos/targets/vmiss-gz-01/deploy-devXXXXXXXXXX.img
```

> `--srv` 的边缘 IP：`dig @1.1.1.1 +short hyos.nanachi.cloud` 查询（勿用本地 resolver，可能返回 fake-ip）。IP 由 Cloudflare 分配，需定期核验有效性（见 §5）。不要加 `--test-mode`（那是 2s 心跳的验证构建）；生产心跳 5 分钟。

## 3. 写入目标机（DD）

VPS 救援模式/官方 DD 脚本均可，核心是一条命令：

```bash
# 方式 A：wrangler 拉取后写盘（本地有 node 环境）
npx wrangler@3.114.17 r2 object get "hyos-artifacts/hyos/targets/vmiss-gz-01/deploy-devXXX.img" -f deploy.img
scp deploy.img root@<VPS>:/tmp/
ssh root@<VPS> 'dd if=/tmp/deploy.img of=/dev/vda bs=4M conv=fsync status=progress && reboot'
```

```bash
# 方式 B：目标机直接流式（救援系统需有 curl；需 Worker 已实现 R2 拉取端点）
curl -sS -H "Authorization: Bearer $OWNER_TOKEN" \
  "https://hyos.nanachi.cloud/v1/image/hyos/targets/vmiss-gz-01/deploy-devXXX.img" \
  | dd of=/dev/vda bs=4M conv=fsync && reboot
```

> 写盘对象是**整个磁盘**（/dev/vda），不是分区——镜像含 MBR + p1(GRUB) + p2(加密系统) + p3(槽)。

## 4. 首启预期

串口/控制台依次出现：

```
HYOS grub.cfg entered → HYOS SELFTEST OK → HYOS BOOT-CHAIN OK epoch=1
HYVERIFY GRUB-CHAIN OK
NET UP eth0 <ip>/<mask> → NET GW via <gw> → NET TLS=ON
SELINUX_ENFORCE=1 → GITKEY_READY bytes=464 → SYS_OK
SELINUX_APP_DOMAIN=system_u:system_r:hyos_app_t:s0
APP_OK sealed → ADVANCE OK seq=2
```

缺任何一项即触发对应等级销毁（串口会有 `HYOS DESTROY[原因]`）。

## 5. 运维操作

| 操作 | 方式 | 效果 |
|---|---|---|
| 吊销设备 | `POST /v1/revoke {did}`（OWNER_TOKEN） | 下次任何验证即销毁 |
| 重置启动 | `POST /v1/rearm`（OWNER_TOKEN） | 允许旧磁盘头再启动 |
| 查设备 | wrangler d1 execute（SELECT did,status,created_at FROM devices） | 台账 |
| 边缘 IP 核验 | dig @1.1.1.1 +short 对比镜像内烘焙 IP | IP 变更需重构建 |
| 拉取镜像 | wrangler@3.114.17（务必钉版本） | 4.x 默认写本地模拟器 |

## 6. 已知限制（按优先级）

1. **镜像拉取端点未实现**（方式 B）：Worker 加 R2 binding + OWNER_TOKEN 鉴权流式端点即可
2. **CF 边缘 IP 烘焙**：CF 更换解析 IP 时需重建镜像；长期方案是 hyinit 内置 DoH 或多 IP 轮询
3. RTC 依赖 CMOS 硬件电池；明文回退已禁（fail-closed）
4. TLS 不校验客户端证书（服务端不知谁在连）——设备身份由 DK 签名保证
