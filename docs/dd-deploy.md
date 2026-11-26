# HyOS DD 部署手册（BIOS 云主机）

本手册描述把一台 BIOS 引导的云主机部署为 HyOS 设备的完整流程

## 部署方式概述

HyOS 为每台目标机器单独构建镜像。构建脚本会生成全新的设备密钥并在生产库注册，随后重建用户态与 GRUB 使其与新密钥绑定，把网络参数和密钥服务地址写入签名清单，最后组装镜像并上传到对象存储，同时输出含镜像路径、sha256 与对象路径的部署单。

## 第一步：构建目标镜像

在 Lima 客机（hyos-dev）中执行：

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

其中 `--srv` 的边缘 IP 用下面的命令查询：

```bash
dig @1.1.1.1 +short hyos.nanachi.cloud
```

构建完成后脚本会输出部署单，形如：

```
target=vmiss-gz-01 did=devXXXXXXXXXX
img=build/dist/deploy-vmiss-gz-01.img
sha256=...
r2=hyos-artifacts/hyos/targets/vmiss-gz-01/deploy-devXXXXXXXXXX.img
```

## 第二步：写入目标机

方式 A：本地拉取镜像后传到目标机写盘，需要本地有 node 环境：

```bash
npx wrangler@3.114.17 r2 object get "hyos-artifacts/hyos/targets/vmiss-gz-01/deploy-devXXX.img" -f deploy.img
scp deploy.img root@<VPS>:/tmp/
ssh root@<VPS> 'dd if=/tmp/deploy.img of=/dev/vda bs=4M conv=fsync status=progress && reboot'
```

方式 B：目标机在救援系统中直接流式拉取并写盘，需要 curl：

```bash
curl -sS -H "Authorization: Bearer $OWNER_TOKEN" \
  "https://hyos.nanachi.cloud/v1/image/hyos/targets/vmiss-gz-01/deploy-devXXX.img" \
  | dd of=/dev/vda bs=4M conv=fsync && reboot
```

## 首次启动

写入完成并重启后，串口或控制台会依次出现下面的日志：

```
HYOS grub.cfg entered → HYOS SELFTEST OK → HYOS BOOT-CHAIN OK epoch=1
HYVERIFY GRUB-CHAIN OK
NET UP eth0 <ip>/<mask> → NET GW via <gw> → NET TLS=ON
SELINUX_ENFORCE=1 → GITKEY_READY bytes=464 → SYS_OK
SELINUX_APP_DOMAIN=system_u:system_r:hyos_app_t:s0
APP_OK sealed → ADVANCE OK seq=2
```

这些标记全部按顺序出现，部署就成功了。

## 日常运维

运维围绕密钥服务的几个接口展开：

- **吊销设备**：向 `/v1/revoke` 提交设备 ID，该设备之后启动时会立即销毁。
- **重置启动**：向 `/v1/rearm` 发起请求，允许一块旧磁盘再次启动，用于重新部署前的准备。
- **查看设备**：通过 `wrangler d1 execute` 查询 devices 表，可以看到每台设备的 ID、状态与创建时间。

Cloudflare 分配的边缘 IP 可能随时间变化。定期用上面的 dig 命令对比镜像内记录的 IP；如果已经变化，为该机器重新构建一次镜像即可。
