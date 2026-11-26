# AGENTS.md

本文件面向在本仓库工作的自动化代理，集中收录 HyOS 项目的约束性规则、边界声明与补充说明。修改代码、脚本、构建配置或文档之前，请先阅读对应条目。面向人的项目介绍见 README.md。

---

## 1. 平台支持约束

- HyOS 仅支持 x86_64（x64）平台，不含任何其他指令集的目标构建。
- 内核：`ARCH=x86_64` + `CONFIG_64BIT=y`（bzImage）。构建期反向断言禁止 32 位指令集兼容回拉：`X86_32` / `IA32_EMULATION` / `COMPAT` / `X86_X32_ABI` 任一为 y 即构建失败（见 `scripts/kernel-minimal.config` 与 `scripts/build-kernel.sh`）。
- 引导：GRUB i386-pc（BIOS/Legacy）。i386-pc 是 x64 平台 BIOS 引导的 GRUB 目标形态（实模式→保护模式→长模式过渡），**不是** i386 平台支持；UEFI 未支持（configure `--disable-efiemu`，无 x86_64-efi 目标）。
- 用户态：hyinit / stubapp / hyproxy 显式 `--target x86_64-unknown-linux-gnu` 静态编译；hysteria2 `GOARCH=amd64`。
- CI：x86_64 ubuntu runner 原生构建，无多架构矩阵。
- 边界声明：`lima/hyos-dev.yaml` 的 aarch64 客机仅为**构建宿主**（Apple Silicon 上原生速度交叉编译 x64 产物），镜像内全部二进制均为 x86_64；`mkdisk` 为构建机本地工具（不进镜像），其架构随构建宿主，不属于产品平台支持。

---

## 2. 安全架构主线与销毁体系

围绕三条安全主线构建：**安全启动自校验**、**双层加密**、**失败即自动销毁**。

分层机制速查（完整设计见《HyOS 安全启动与自动销毁设计方案》）：

| 层次 | 机制 |
|---|---|
| GRUB (S1) | 上电自校验(窗口哈希 + Ed25519 签名 + 白盒常量) → 双槽解析 → 用白盒 KEK 解槽内 wrap → AES-256-GCM 解密系统镜像入内存 → 注册 hyram 内存盘 → 引导内核 |
| 内核/initramfs (S2) | 反向校验 GRUB(版本/镜像哈希/DK 签名钉扎) → 校验系统清单 → 解密应用包(DEK2)入 tmpfs → 校验 app.manifest |
| 内核最小化 | allnoconfig + 白名单 + EXPERT/反向断言(816 项/0 模块)，bzImage 3.86MB：仅串口/SELinux/IPv4+网卡/块设备/ACPI/netfilter-DNAT；HID/USB/无线/文件系统等全部不编入（`scripts/kernel-minimal.config`） |
| 应用层 (S3) | 反向校验系统(rootfs 哈希 + 密钥一致性) → 短时令牌拉取私有 Git 配置(仅内存) → 按清单启动服务 |
| SELinux (S3+) | enforcing 最小权限：应用锁定 `hyos_app_t` 域（块设备/危险能力/ptrace 编译期 neverallow），仅 `/run/hyos-tmp` 可写，配置只读；策略单块离线合成、构建期嵌入 |
| 运行期 (S4) | 签名 ack 心跳、epoch 推进、失联即销毁 |
| DD 部署 | 一机一镜像：目标网络/密钥服务地址经 **签名 manifest** 注入（篡改即销毁），`scripts/build-for-target.sh` 按目标构建+注册+R2 分发；hyinit 经 netlink(onlink) 装默认路由，直连 CF 边缘 IP（Host 头路由） |
| 证书续期 | 内置 ACME DNS-01 客户端（LE staging 实测通过）：DNS 挑战经密钥服务代理（设备 DK 签名鉴权，设备永不持有 CF 凭据），证书每签发随机新密钥、仅存 tmpfs；失败回落内置证书 |
| 传输加密 | 密钥服务通信用 **rustls TLS**（webpki 公共根校验 + CMOS RTC 真实时间），防中间人伪造拒绝导致的强制销毁；本地联调可回退明文 |
| 应用层 | 真 hysteria2 v2.14.0（Go 静态）+ hyauth（Rust 认证后端）打包进加密应用包；客户端 obfs+TLS+auth 全链路实测 200 |

**销毁等级**：L0 GRUB 自毁 / L1 镜像区 / L2 应用包 / L3 应用自毁 / L4 未签名执行(待 IMA 落地) / L5 运行期失联全盘。

**密钥体系**：`WK0_root`(GRUB 白盒) → `WK0[e]` → `wrap(DEK1)`；`WK1_root`(验证器白盒) → `WK1[e]` → `wrap(DEK2)`；设备身份 `DK` 用于双向证明。每次成功启动推进 epoch 并由服务端签发下一轮 KEK。

失败分支速查：

```
GRUB 自身被改     → GRUB 自校验 → L0 毁 p2/p3 头 → halt
签名错(镜像)      → GRUB → L1 毁镜像区 → halt
密钥错(DEK1)      → GRUB → L1 同上
GRUB 假/旧        → 系统 → L2 毁应用包 → 回报 → poweroff
DEK2/应用清单错   → 系统 → L2' 毁 p3 → 回报 → poweroff
系统假/旧         → 应用 → L3 毁 p3+tmpfs → 拒拉配置 → poweroff
未签名执行        → 内核 → 删文件；×3 → L3
服务端判异常      → quarantine → 拒发钥匙 → 端上按策略销毁/锁定
引导期不可达      → 3 次快速重试 → L1 销毁（re-arm + 重新 dd 重建）
运行期持续离线    → 心跳×3 失败 → L5 全盘销毁 → poweroff
```

---

## 3. 设计边界（诚实边界）

- 本设计防的是"拿走磁盘/镜像文件的人"，不防"控制宿主的人"：KVM 宿主可 dump 虚机内存，内存中已解密的镜像、密钥、运行进程对宿主无防护。需要对抗宿主必须引入 vTPM/SEV-SNP 一类硬件隔离（本环境云厂商不提供，v1.2 决议：TPM/vTPM 彻底移出范围）。
- 白盒 ≠ 不可逆：编译进 GRUB 的密钥材料可被足够资源和时间的攻击者动态分析提取。兜底是**服务端轮换 + 吊销闭环**：泄漏的静态根离开服务端的 epoch 授权只能解出"已被撤销 epoch"的包装。
- **无应急恢复通道**（v1.1 决议）：端上不存在任何口令、开关或隐藏菜单能改写钉扎、复位销毁或复活设备。任何致命状态 = 砖，唯一恢复路径是**重新 dd 部署 + 服务端 re-arm**。
- **离线即销毁**（v1.2 决议，owner 已接受）：引导期取钥不可达（3 次快速重试）、运行期心跳连续失败（15 分钟）与密码学校验失败同等对待，立即销毁。一次足够长的 Cloudflare 全球性故障也可能触发销毁；DoS 对手无法解密但可让机器反复离线，服务端侧 quarantine 兜底，损失上限 = 一台机。
- 部署密钥的保护属于纵深防御：密钥在构建期以份额拆分 + 运行期重组（与 GRUB 白盒同机制）嵌入镜像，运行期仅用于在内存中拉取私有配置，配置文件不落盘；真正的边界是镜像本身的加密与访问控制。
- TLS 通道不校验客户端证书（服务端不知道谁在连），设备身份由 DK 签名保证。
- 明文回退已禁用（fail-closed）：`hy_tls=1` 但二进制不支持 TLS 时拒绝回退明文，按服务器不可达销毁。
- 无 SSH/shell 的排障边界：运行期故障只能看串口内核日志（只读）与 D1 events；需要交互调试必须重新部署 debug 变体。这是"未签名执行即拒绝 + 无 shell"设计的必然代价。
- 未认证 cmdline 开关已全部废弃：`hy_test` / `hy_hb_ms` / `hy_srv` 只认 VK_SIG 签名清单；epoch 以加密槽头为准（cmdline 值不一致即销毁）。
- `hy_enforce=0` permissive 后门已移除：未认证 cmdline 开关可让 SELinux 策略退化为 permissive，与"宁毁勿漏"相悖；enforce 写入结果校验回读，挂载/策略/回读任一失败即销毁。
- 自动销毁机制运行在供应商磁盘上，删除的是自己的数据分区，无越权行为；建议留存设计文档以便申诉时说明性质。
- 每设备独立构建是安全与运维成本并存的取舍（DK/白盒逐设备）；设备数量多时需要构建工厂化（当前单台无压力）。
- GRUB 内 http 明文取钥的安全性由响应签名 + WK 包装保证，不依赖 TLS；若在意"取钥行为被链路观察"，备选 GRUB 预取模式（关机前系统把下一轮 wrap 写槽，GRUB 纯离线），代价是断网容忍度绑定槽推进——列为可配置项。

---

## 4. 部署与运维约束

### 4.1 DD 部署硬约束（违反即设备自毁）

| 约束 | 原因 |
|---|---|
| **一机一镜像** | 镜像内含设备专属密钥与 epoch；同一镜像写入第二台机器，epoch 回滚 → L3 销毁 |
| 目标机 **BIOS/Legacy 引导** | GRUB 为 i386-pc 构建，UEFI 未支持 |
| `--srv` 的 CF 边缘 IP **必须有效** | IP 退役 → 密钥服务不可达 → L5 销毁（fail-closed） |
| CMOS 电池正常 | TLS 证书校验依赖 RTC 真实时间，时钟停摆 → 握手失败 → 销毁 |
| 明确知道自己在做什么 | 任何验证失败都是销毁，没有"重试"——这是设计而非缺陷 |

### 4.2 操作规则

- `--srv` 边缘 IP 用 `dig @1.1.1.1 +short hyos.nanachi.cloud` 查询，勿用本地 resolver（可能返回 fake-ip）。IP 由 Cloudflare 分配，需定期核验，变更即重建镜像。
- 不要给生产构建加 `--test-mode`（那是 2s 心跳的验证构建）；生产心跳 5 分钟。
- 拉取 R2 镜像务必钉版本 `wrangler@3.114.17`（4.x 默认写本地模拟器）。
- boot 失败后再引导：服务端状态机拒绝重复 grub_ok → 必须 OWNER_TOKEN rearm 后再 boot（防回滚设计）。
- 证书兜底：ACME 签发/续期失败 3 次重试后回落应用包内置证书（现役证书有效至 2027-02-08）。

### 4.3 运维接口

| 操作 | 方式 | 效果 |
|---|---|---|
| 吊销设备 | `POST /v1/revoke {did}`（OWNER_TOKEN） | 下次任何验证即销毁 |
| 重置启动 | `POST /v1/rearm`（OWNER_TOKEN） | 允许旧磁盘头再启动 |
| 查设备 | `wrangler d1 execute`（SELECT did,status,created_at FROM devices） | 台账 |
| 边缘 IP 核验 | `dig @1.1.1.1 +short` 对比镜像内烘焙 IP | IP 变更需重构建 |

### 4.4 验收口径

dd 部署从写盘到首次启动之间**不允许出现任何需要人工输入的环节**（CI 测试矩阵用空串输入断言）。

---

## 5. 生产环境资源与机密

### 5.1 资源

| 组件 | 值 |
|---|---|
| 密钥服务 | Cloudflare Worker `hyos-keyserver`，生产地址 https://hyos.nanachi.cloud（custom domain，自动 DNS/证书） |
| 数据库 | Cloudflare D1 `hyos`（`schema.sql` 已应用） |
| 制品存储 | R2/S3 私有桶 `hyos-artifacts` |
| ACME | `oa.nanachi.cloud`（DNS-01 经 Worker `/v1/acme-dns` 代理，DK 签名鉴权）；Worker 机密：`CF_DNS_TOKEN`（仅 nanachi.cloud 的 DNS:Edit 最小权限 token）、`CF_DNS_ZONE_ID`=`bd13257e9a4fd8951b7a23513539298a`、`ACME_DOMAIN`=`oa.nanachi.cloud` |
| CI 联动 | GH Actions 变量 `WORKER_URL` + Secret `HYOS_CI_TOKEN` → 构建尾自动 enroll 新设备 |

### 5.2 Secrets 清单

| Secret | 用途 |
|---|---|
| `HYOS_GIT_SSH_KEY` | 读取私有配置仓库(HysteriaConfig)的**只读 Deploy Key** |
| `HYOS_GIT_SSH_PASSPHRASE` | 上述密钥口令 |
| `S3_AK` / `S3_SK` | 制品上传(S3 私有桶) |
| `S3_ENDPOINT` / `S3_REGION` / `S3_BUCKET` | 对象存储定位 |
| `CF_API_TOKEN` / `CF_ACCOUNT_ID` | 发布 D1 清单与 Worker |
| `HYOS_SIGNING_KEY` | 镜像/清单签名私钥(离线保管，仅 CI 使用) |
| `CI_TOKEN` / `OWNER_TOKEN` / `SRV_SK_PKCS8` | 经 `wrangler secret` 注入；生成器 `scripts/gen-prod-secrets.mjs`，产物存仓库外 |

### 5.3 机密管理规则

- 所有机密均通过 GitHub Secrets 注入，**仓库内不含任何明文凭据**。
- 测试密钥 fixture 不入库：`server/tests/fixtures/` 下任何含 `dk_priv_pkcs8_hex` / `srv_seed_hex` / `tk_master` / `wk*_root` / `dek_*` 的文件不得提交；需要时在仓库根执行 `node scripts/gen-dev-keys.mjs` 现场生成（.gitignore 已排除，pre-commit 钩子 + `scripts/secret-scan.sh` 会拦截）。
- HysteriaConfig（私有配置仓库）规则：所有机密字段必须 SOPS+age 加密；**解密密钥不进仓库**，由 Cloudflare Worker 随短时令牌下发。端上路径 `/run/configs`、`/etc/hysteria` 均为 tmpfs，任何持久文件系统挂载都会触发启动期审计失败。版本钉扎：端上按 `pin` 声明的提交哈希校验，未获批准的新提交不会被采用。
- 部署密钥（读私有配置仓库的只读 Deploy Key）构建期以 8 组 XOR 份额嵌入 `verifier/src/genkeys.rs`（来自 CI Secret `HYOS_GIT_SSH_KEY_B64`，产物不入库），运行期重组写入 `/run/secrets/git_deploy_key`(0600)。
- 设备级密钥（DK/DEK）在 runner 内存生成，不进 Secrets、不落盘；私钥明文只在构建内存中存在，构建结束即焚。
- 签名私钥信任边界包含 GitHub（v1.2 决议，SK_sig 托管 GitHub Secrets）；可选增强是 CI 仅产出待签摘要、owner 本地签名回传。
- 提交前跑 `scripts/secret-scan.sh`（pre-commit 已挂钩）。

---

## 6. 测试与验证现状

- 最近一次全量结果：**9/9 引导场景通过，契约 21/21；SELinux enforcing 模式 E2E SUCCESS**（应用域隔离 + 最小权限探测矩阵，详见 `docs/lima-验证报告.md` §8）。
- `tests/e2e.sh` 场景覆盖：清场 → 生成设备密钥 → 启动本地 Worker（wrangler dev + 本地 D1）→ Worker 契约测试 → 全量构建（GRUB core.img / hyinit / initrd / 磁盘镜像）→ 9 个引导场景断言（正常启动、epoch 推进、re-arm、L0–L5 销毁）。
- CI（`.github/workflows/build.yml`）：单元测试 6/6、Worker 契约 21/21；镜像 job 执行内核/GRUB/用户态/SELinux 全量构建并上传制品。

---

## 7. 文档索引

| 文档 | 内容 |
|---|---|
| 《HyOS 安全启动与自动销毁设计方案》（工作区根，v1.3） | 总体设计：威胁模型、密钥体系、启动流程、销毁机制、服务端设计 |
| `docs/lima-验证报告.md` | Lima 联调验证记录（§8 SELinux、§9 内核裁剪/部署注入/TLS/ACME） |
| `docs/dd-deploy.md` | DD 部署手册（BIOS 云主机） |
| `DEPLOY-v9g.md` | 生产部署 runbook（v12 安全加固 + masquerade 修复） |
| 工作区 `HyOS-生产部署记录.md` | 生产 dd 实战记录与教训 |
| 工作区 `DD-交接清单.md` | 一次 DD 交接的操作清单 |
| 工作区 `hysteria2-带宽测量与定时切换报告.md` | 带宽测量与 BBR/Brutal 切换、QoS 排障记录 |
| 工作区 `HysteriaConfig/README.md` | 私有配置仓库结构与变更流程 |
| 工作区 `substore-cloudflare-backup/DEPLOYMENT.md` | SubStore Workers 部署记录 |
| `server/tests/fixtures/README.md` | 测试密钥 fixture 说明 |

---

## 8. 内核裁剪配置陷阱（改内核配置前必读）

| 陷阱 | 说明 |
|---|---|
| SELinux 依赖链 | `SECURITY_SELINUX` depends on `AUDIT && SECURITY_NETWORK && NET && INET`，缺一被 olddefconfig 静默丢弃 → 必须断言校验 |
| `NETFILTER_XT_TARGET_DNAT` 已并入 | 6.14 中 DNAT 目标由 `IP_NF_NAT` 自动 select 的 `XT_NAT` 提供，独立符号不存在 |
| STACKPROTECTOR 父子项 | `STACKPROTECTOR_STRONG` 依赖 `STACKPROTECTOR`（默认 y 但 allnoconfig 全关） |
| KASLR/IOAPIC | `RANDOMIZE_BASE` 依赖 `RELOCATABLE`；`X86_IO_APIC` 为 def_bool（显式写 `CONFIG_IO_APIC=y` 无效符号） |
| devtmpfs 必显式 | allnoconfig 下 `DEVTMPFS(_MOUNT)` 默认关，缺了 hyinit 无法挂载 /dev → spawn 失败 |
| EXPERT 陷阱 | `EXPERT` 关闭时 VT/PPS 等符号无提示，`default y` 绕过 unset 静默生效（VT→select INPUT→touchscreen.o）→ 开 `CONFIG_EXPERT=y` 让 unset 行生效 |
| select 链 ① | `WLAN`(default y) `select WIRELESS` → 需 unset **WLAN 断链头**（select 会覆盖显式 unset） |
| select 链 ② | `PTP_1588_CLOCK` default ETHERNET 且 `select PPS` → 需 unset **PTP_1588_CLOCK**（e1000 不依赖它，无 select 反拉） |
| 语法陷阱 | kconfig unset 行必须精确 `# CONFIG_X is not set`——行尾带注释文字则整行被当注释丢弃 |
| 关键选项断言 | 依赖缺失会被 olddefconfig 静默丢弃，必须显式校验（`scripts/build-kernel.sh` 的 MISSING/PRESENT 断言） |

---

## 9. 联调与排障要点

### 9.1 构建与联调环境

- 9p/virtiofs 缓存：宿主改源码后客机构建可能读到陈旧产物（密钥/源码代次错配，症状随机）→ 构建前 `sync` + `drop_caches`（build-for-target 已内置）；密钥生成器自检（私钥↔公钥）+ 原子写入。
- final-verify 重新生成密钥后**必须重启 wrangler**，否则内存中 SRV_SK_PKCS8 仍是旧值 → 契约仅 `server ed25519 sig` 挂。
- test-mode 关机窗口：E2E SUCCESS 后 2s 断电 → 客户端测试必须用生产 cfg（VM 常驻）。
- wrangler/wrangler 日志/串口文件 root 所有权 → `sudo rm`。
- CI 镜像 job 依赖：runner 需装 `selinux-policy-default`（提供基座策略商店）；apt 用 `--no-install-recommends`；`expand-check=0` 写入 semanage.conf 加速合并；`set -euo pipefail` 下对可能不存在的路径加 `|| true` 守卫（曾因 `ls` 零输出 exit 2 经 pipefail 传播静默终止脚本）。

### 9.2 GRUB 模块构建规范（实测教训）

1. 自研 GRUB 模块必须经 GRUB 构建树 `genmod.sh` 产出 `.mod`；`grub-mkimage` 不接受裸 ELF。
2. 模块若调用 `grub_disk_write`，必须显式链接 **`disk` 模块**（内核中该符号为 weak，实体在 `disk.module`）。
3. `syminfo.lst` 必须以 `kernel_syms.lst` 开头并由 `gensyminfo.sh` 逐模块生成；`moddep.lst` 必须 `sort` 后过 `genmoddep.awk`。
4. 验证器启动即把 `/proc/sys/kernel/printk` 降到 1，避免内核日志与安全判定消息在串口交错（影响审计可判定性）。

### 9.3 生产 dd 写盘（VMISS 实战教训）

VMISS 存储层会吞掉 guest 直接 dd 的部分写入——**页缓存回读一致 ≠ 磁盘真身正确**。可靠方案 v8（必须遵守）：

1. `dd oflag=direct bs=1M`（直写穿透）；
2. 每 4MB 块 O_DIRECT 回读 sha256 比对，失败重试；
3. 整盘 O_DIRECT 终验 vs 源文件哈希；
4. 全绿后才 `reboot -f`（热重启，QEMU 进程不死）。

已验证的失败模式（勿重蹈）：

- mini-initramfs dd：guest 内回读全对 → 面板强制重启杀 QEMU → 宿主缓存丢失 → 部分持久化 → payload-tag 自毁；
- `exec >/dev/console` 放在 devtmpfs 挂载前 + cpio 无 console 节点 → init 秒退 panic；
- `kexec -e` 放后台（nohup/&）→ SSH 会话退出即被杀，从未执行。

### 9.4 ACME（LE）调试要点

- LE 接口返回格式化 JSON（冒号带空格）→ JSON 提取需空白容忍；状态轮询匹配同理。
- PKCS#9 extensionRequest 属性值 = SET{Extensions-SEQ}（Go/OpenSSL 事实标准，无 OCTET 包装）。
- PEM 私钥必须标准 base64（非 url）；CSR 公钥 ≠ 账户公钥。

### 9.5 Hysteria2 服务端配置要点

- v2.9.x obfs 配置键为嵌套结构：`obfs.type: salamander` + `obfs.salamander.password`；扁平 `obfs.password` 或文档写法 `obfs.obfsPassword` 均会 FATAL 崩溃循环（`PSK must be at least 4 bytes`）。官方 Go client JSON 同理需嵌套。
- 上线任何服务端配置变更后必须确认 `systemctl is-active` + 端口监听，不能只看命令是否执行完。
- 大流量测速/iperf 探测一律停止——会自己触发运营商对 QUIC 特征的 QoS 管控。
- 客户端 mport/端口跳跃必须与服务端监听/DNAT 范围一致；每次改 mport 前先确认服务器已覆盖对应区间（死端口会让客户端周期性跳进黑洞）。
- QUIC 缓冲：`net.core.rmem_max/wmem_max` 建议 16MB（官方要求）；`keepAlivePeriod: 15s` 保住移动网 CGNAT 的 UDP 映射。

### 9.6 SubStore（Cloudflare Workers）

- 下载授权 token 为精确匹配：手动复制漏掉末字符会得到 403，授权验证用程序化比对才可靠。
- `oa.nanachi.cloud` 是 hy2 节点本身的域名，与 SubStore 无关，不要混入 SubStore 的域名配置。

---

## 10. 已知限制与未实现项

- 镜像拉取端点未实现（Worker 加 R2 binding + OWNER_TOKEN 鉴权流式端点即可）。
- CF 边缘 IP 烘焙进镜像：CF 更换解析 IP 时需重建镜像；长期方案是 hyinit 内置 DoH 或多 IP 轮询。
- 未实现的 v1.2 条目（顺延后续里程碑）：内核 IMA appraisal + eBPF LSM（执行前验签、拒绝即删，M3）；白盒化"微型 VM 重组 + 控制流平坦化"（当前仅 XOR 8 份额，加固项）；prod 变体裁剪断言（M4）。L4（未签名执行）待 IMA 落地后验证。
- GRUB 取钥为**离线槽解密**（BIOS 下 GRUB 无原生网卡驱动，`e1000.mod` 不存在，仅 PXE 栈可用）；防回滚由验证器 ack 阶段的服务端校验 + L5 兜底承担；`/v1/boot/challenge` 在 BIOS 变体中为可选（EFI 变体或增加网卡驱动后可恢复在线取钥）。

---

## 11. 第三方组件与许可

- 本项目代码：见 `LICENSE`。
- `grub/tweetnacl.c`：TweetNaCl（public domain）；`grub/aes.c`：tiny-AES-c（MIT）。
- GRUB 与 Linux 内核为运行期从官方源下载的独立项目，遵循其各自许可（GPL）。
- 语言基线（v1.2 决议）：自研代码一律 C/C++/Rust（GRUB 模块 C；工具/验证器 Rust musl 静态）；例外仅两类——上游程序本体（hysteria2 = Go strip 构建）与 Cloudflare Worker（TypeScript，D1 平台约束）。
- HyOS 不包含 Docker/containerd；ipmysql-server 不迁移（连同容器运行时移出范围）。
