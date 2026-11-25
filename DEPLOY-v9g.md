# 生产部署操作序列（v9g 镜像 = hyproxy + porthop + hysteria2:8443）
# did=dev80e08bd12f sha256=9cc078cad488b65ee75aeea9f37fc47e4a4b80b6827f858705b481ad880f40a3

## 0. 前置核对
- dig @1.1.1.1 +short hyos.nanachi.cloud  → 应与 104.21.0.204 同段（CF edge IP，若变了需重构建）
- VMISS 面板重装 Debian 13（密码 bHAaJ7NR8mkYZjDJ）

## 1. SSH 注入镜像（从 Mac 直传，避开 VM 中转）
sshpass -p 'bHAaJ7NR8mkYZjDJ' scp hyos-build/build/dist/deploy-vmiss-gz-01.img root@38.47.124.239:/tmp/

## 2. 活系统内 v8 部署（用仓库 scripts/deploy-v8.sh）
# 先上传脚本，再：
ssh root@38.47.124.239 'bash /tmp/deploy-v8.sh /tmp/deploy-vmiss-gz-01.img /dev/vda 9cc078ca...'

## 3. reboot -f 后（等 ~90s）
- D1 events 应出现：did=dev80e08bd12f activated=true + grub_ok + app_ok
- keyserver 心跳开始

## 4. 部署成功后清理
- 撤销旧设备：UPDATE devices SET status='revoked' WHERE did='dev99bd01fc1a'
- 撤销本次失败的 provisioned 占位（dev18c39e77d8/dev3d5fd56286/dev4b5504fd27 保留最新 dev80e08bd12f）

## 5. 外部验证（check-host.net 多点）
- TCP 80/443 → hyproxy 应答（HTTP 请求应代理到 nanachi.cloud 内容）
- UDP 443/20000-30000/40000-60000 → hysteria2（Shadowrocket 实测）
