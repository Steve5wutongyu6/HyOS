# HyOS Lima 联调验证报告

| 项 | 内容 |
|---|---|
| 日期 | 2026-11-22 |
| 结论 | **E2E ALL PASS（9/9 场景通过，契约测试 21/21）** |
| 环境 | macOS 宿主 + Lima 2.3.0；客机 aarch64 Debian 13（6 vCPU / 12 GiB） |
| 目标平台 | x86_64 BIOS 虚机（qemu-system-x86_64，TCG 软件模拟） |
| 内核 | Linux 6.12.1（交叉编译 bzImage，12.6 MiB） |
| 引导器 | GRUB 2.12 i386-pc（交叉编译，集成自研 hyverify 模块，core.img 162 KB） |
| 代码 | proto（Rust 密码学核心）/ verifier（Rust initramfs 验证器+supervisor）/ grub（C 模块）/ tools/mkdisk（Rust 镜像组装）/ server（Cloudflare Worker + 本地 D1） |

---

## 1. 验证方法

全流程脚本化、可复跑：

```bash
limactl shell hyos-dev -- bash /mnt/vmiss/hyos-build/tests/e2e.sh
```

`tests/e2e.sh` 依次执行：清场 → 生成设备密钥（自检+原子写入）→ 启动本地 Worker（wrangler dev + 本地 D1）→ 契约测试 → 设备 rearm → 全量构建（GRUB core.img / hyinit / initrd / 3 张磁盘镜像）→ 9 个场景逐个 qemu 引导并断言串口标记。

---

## 2. 场景与结果

| 场景 | 验证目标 | 结果 | 关键串口证据 |
|---|---|---|---|
| E1 | 正常启动全链路 + epoch 推进 | ✅ | `HYOS SELFTEST OK` → `HYOS BOOT-CHAIN OK epoch=1` → `HYVERIFY GRUB-CHAIN OK` → `SYS_OK` → `APP_OK sealed` → `ADVANCE OK seq=2` → `HYOS E2E SUCCESS` |
| E7 | 重启后使用推进后的 epoch | ✅ | `HYOS BOOT-CHAIN OK epoch=2` → `ADVANCE OK seq=3` |
| E8 | 服务端 rearm 后旧磁盘头可再启动 | ✅ | `HYOS BOOT-CHAIN OK epoch=3` → `ADVANCE OK seq=4` |
| E2 | **L0**：窗口区被篡改 → GRUB 自校验失败 | ✅ | `HYOS DESTROY[window-hash]` → `HYOS WIPED. power off.`（并打印 computed vs manifest 哈希） |
| E3 | **L1**：加密系统载荷被篡改 → GCM tag 失败 | ✅ | `HYOS DESTROY[payload-tag]` → `HYOS WIPED` |
| E4 | 设备不可用（revoked）→ 取钥/ack 被拒 → 立即销毁 | ✅ | `HYVERIFY GRUB-CHAIN OK` → `HYOS DESTROY[grub_ok-refused]` |
| E5 | **L2**：系统清单签名被破坏（假系统） | ✅ | `HYOS DESTROY[system-manifest]` → 断电 |
| E6 | **L3**：应用→系统钉扎不匹配（os_pin 0.2 vs 0.1） | ✅ | `HYVERIFY GRUB-CHAIN OK` → `HYOS DESTROY[os-pin] wiping p3 (L3)` |
| E9 | **L5**：运行期失联 → 心跳连续失败 → 全盘销毁 | ✅ | `APP_OK sealed` → `HB_FAIL 1/2/3` → `HYOS L5 WIPE` |
| 契约 | Worker 密钥服务全端点 | ✅ 21/21 | enroll / challenge / 信封互操作 / ack 状态机 / 回滚 quarantine / rearm / revoke |

---

## 3. 已验证的关键安全属性

1. **GRUB 自校验生效**：窗口哈希（LBA1..2047）与 `grub.manifest`（Ed25519 签名）比对，篡改即销毁（E2）。
2. **双层加密独立生效**：系统镜像层（DEK1/AES-256-GCM）与应用包层（DEK2）分别认证，任一失败各自触发对应等级销毁（E3 / E6）。
3. **互验环闭环**：GRUB 用 DK 私钥签署 attestation → 验证器用 DK 公钥验签并钉扎 GRUB 版本/镜像哈希（E4 破坏该环节时被拒）。
4. **epoch 单调推进与防回滚**：每次成功启动推进槽 seq/epoch（E1→E7→E8），服务端只接受 `epoch >= last_acked`，回滚请求返回 403 并 quarantine（契约测试覆盖）。
5. **离线即销毁**：设备被吊销/隔离后无法取得 ack → 验证器立即销毁（E4）；运行期失联 3 次心跳 → L5 全盘销毁（E9）。
6. **署名 ack 与事件分离**：`grub_ok/sys_ok/app_ok` 参与状态机，`alive/exec_deny/grub_bad/app_fail` 仅记录（`grub_bad/app_fail` 触发 quarantine）。

---

## 4. 联调中发现并修复的真实缺陷（11 项）

这些问题在纯设计阶段无法发现，均为实测暴露：

| # | 缺陷 | 影响 | 修复 |
|---|---|---|---|
| 1 | `grub-mkimage` 只接受经 `genmod.sh` 处理的 `.mod`，不接受裸 ELF | 自研模块永远无法进入 core.img | 模块纳入 GRUB 构建树，用 Makefile 规则产出 `.module` → `.mod` |
| 2 | 内核中 `grub_disk_write` 是 **weak 符号**，实体在 `disk.module` | 模块加载时符号解析失败 → grub_fatal 静默死机 | 显式链接 `disk` 模块（moddep 自动闭包） |
| 3 | `syminfo.lst`/`moddep.lst` 必须按 Makefile 规则生成（含 `kernel_syms.lst` 与 `sort`） | 依赖表破损 → 加载顺序错乱 | 严格复刻 Makefile 规则重建 |
| 4 | 自研 SHA-256 的填充逻辑用 `memset` 覆盖了刚写入的 `0x80` | 所有哈希错误 → 自校验/槽校验全失败 | 删除破坏性 memset |
| 5 | 自研 GCM 的 GHASH 方向错误（加密前/解密后取数据） | 自测自洽但与 Node/Rust 互操作必失败 | GHASH 严格作用于密文 |
| 6 | HKDF 空盐被当作 1 字节 0x00 | 与 RFC5869/Node/Rust 不一致 → KEK 不同 | 空盐使用 32 字节全零 |
| 7 | tweetnacl 的 `sk` 布局是 `seed‖pk`，实现写成 `pk‖seed` | 签名私钥错误 → attestation 验签失败 | 修正布局 |
| 8 | 验证器发送 ack 签名用 base64url，服务端按 hex 解析 | 全部 ack 403 → 误触发销毁 | 统一为 hex |
| 9 | mkdisk 的 cpio newc 头把 ino 写成 6 位（应 8 位），TRAILER 多一字段 | 归档非法 → 找不到 app.manifest | 修正字段宽度与字段数 |
| 10 | Rust `aead_open` 传入剥离了 tag 的密文（aes-gcm 需 `密文‖tag`） | 应用包解密恒失败 | 传完整密文 |
| 11 | 9p 挂载缓存导致客机读到陈旧产物（密钥/源码） | 产物与密钥代次错配，症状随机 | 构建前 `sync`+`drop_caches`，生成器自检+原子写入 |

另有两项工程性修正：
- **服务端把 `alive` 心跳当非法 stage 返回 400**，导致验证器误判失联并触发 L5 销毁（E1 首跑即暴露）→ 事件型 ack 单独处理。
- **内核 printk 与串口关键标记交错**，使 `HYOS DESTROY[system-manifest]` 被拆断 → 验证器启动即把 printk 级别降到 1，保证审计日志可判定。

---

## 5. 与设计文档的偏差（需同步 v1.3）

| 项 | 设计（v1.2） | 实测实现 | 原因与影响 |
|---|---|---|---|
| GRUB 取钥 | HTTP + 应用层信封加密在线取钥 | **离线槽解密**（GRUB 直接用白盒 WK0 解槽内 wrap） | BIOS 下 GRUB 无原生网卡驱动（`e1000.mod` 不存在），仅 PXE 栈可用。防回滚改由 **验证器 ack 阶段的服务端校验 + L5 兜底** 承担；GRUB 层仍保留签名/哈希/槽完整性校验。设计文档需明确该取舍 |
| 应用执行强制 | IMA appraisal + eBPF LSM | **未实现**（本次仅验证到 supervisor 启动） | 属 M3 剩余项，需内核 IMA/LSM 配置与逐文件签名写入 |
| 白盒化 | XOR 份额 + 微型 VM 重组 + 控制流平坦化 | 仅 **XOR 8 份额**（运行期重组） | VM 化/平坦化属加固项，不影响功能验证 |
| prod 变体裁剪（无 SSH/shell） | CI 断言强制 | 未验证（当前 debug 变体含 busybox 依赖面） | M4 项 |
| GitHub Actions + S3 上传 | 流水线 | 未接入（本地 Lima 内构建） | M5 项 |

---

## 6. 复现与产物

| 产物 | 路径 |
|---|---|
| 一键 E2E | `tests/e2e.sh`（日志 `build/logs/e*.log`、`build/logs/contract.txt`） |
| 定制 GRUB core.img | `build/core/core.img` |
| 验证器/supervisor | `build/hyinit`（x86-64 静态） |
| initramfs | `build/initrd.img` |
| 磁盘镜像 | `build/deploy-happy.img` / `deploy-test.img`（含 hy_test 快速心跳）/ `deploy-l3.img` |
| 密钥 fixture | `tests/fixtures/dev-keys.json`（联调专用，含自检） |

---

## 7. 后续工作

1. **M3 收尾**：内核 IMA appraisal + eBPF LSM（执行前验签、拒绝即删）。
2. **设计文档 v1.3**：写入“GRUB 离线取钥”的最终取舍与威胁模型影响；补充 `disk` 模块依赖、printk 静默等实现约束。
3. **白盒化加固**：份额拆分 + 微型 VM 重组 + 控制流平坦化，并做一次 strings/IDA 抽查。
4. **prod 变体**：裁剪 shell/SSH，加入 CI 断言（构建产物扫描即失败）。
5. **CI**：GitHub Actions 构建 + 签名 + S3 上传 + D1 清单发布；dd 全自动部署演练。
6. **性能回归**：在 TCG 之外用 KVM 硬件加速复测启动时间与 hysteria2 吞吐。

---

## 8. SELinux 强制访问控制联调（2026-11-23 补充轮）

| 项 | 内容 |
|---|---|
| 结论 | **enforcing 模式 E2E SUCCESS**：应用域隔离 + 探测矩阵 + 全链路启动均按预期 |
| 内核 | Linux 6.14.11（x86_64 交叉编译，原生 SELinux，策略版本上限 v33/POLICYDB_VERSION_COND_XPERMS） |
| 策略 | `selinux/hyos.te`（单块模块，Debian selinux-policy-dev 工具链离线合成，合入基座后版本自动对齐 34→33） |
| 验证脚本 | `selinux/final-verify.sh`（策略→密钥→用户态→GRUB→镜像→Worker 契约→rearm→引导→证据） |

### 8.1 运行时实现

- hyinit 在 enforcing **之前**向 selinuxfs 单次写入加载单块策略，随后 `setenforce 1`；任何失败即 L3 销毁。
- `/run` 挂载独立 tmpfs 作为应用运行区；运行期把应用标注为 `hyos_app_exec_t`、supervisor 标注为 `hyos_init_exec_t`（execute_no_trans，驻留 kernel_t）、配置为 `hyos_config_t`、应用私有临时区为 `hyos_tmp_t`。
- 域转换：`kernel_t --(执行 hyos_app_exec_t)--> hyos_app_t`；`neverallow` 编译期断言块设备读写、危险能力、内核模块加载、同域 ptrace。
- 部署密钥（读私有配置仓库的 Deploy Key）以 **8 组 XOR 份额**构建期嵌入 `verifier/src/genkeys.rs`（来自 CI Secret `HYOS_GIT_SSH_KEY_B64`，产物不入库），运行期重组写入 `/run/secrets/git_deploy_key`(0600)，`GITKEY_READY bytes=464` 实证。

### 8.2 联调暴露并修复的缺陷（7 项）

| # | 缺陷 | 症状 | 修复 |
|---|---|---|---|
| 1 | `gen-hykeys.mjs` 多行 Rust 片段被写成普通双引号 JS 字符串 | SyntaxError，构建链第 2 步起全断 | 改为模板字面量 |
| 2 | 部署密钥份额 Rust 类型写成 `[[u8; 58]; 8]`（字数），实际每份额为整长 464 字节 | hyinit 编译 E0308 | 类型改为 `[[u8; GIT_KEY_LEN]; 8]`，空密钥回退为 8 组空行 |
| 3 | final-verify 重新生成密钥后**不重启 wrangler**，内存中 SRV_SK_PKCS8 仍是旧值 | 契约 20/21（仅 `server ed25519 sig` 挂） | 步骤 5 强制重启 Worker 再跑契约 → 21/21 |
| 4 | **type_transition 目标类型未授权给父角色**（缺 `role system_r types hyos_app_t;`） | `type=1401 security_compute_sid invalid_context` → execve EACCES，且基座 dontaudit 掩蔽（permissive 下同样无 avc） | 模块内补 `role system_r/unconfined_r types hyos_app_t;` |
| 5 | 应用域 fd/管道/`/dev/null` 继承链缺权限（supervisor `Stdio::null` 打开 `/dev/null`、探测输出管道、SIGCHLD、getsched） | enforcing 下 spawn EACCES（静默） | 补 `event_device_t`、`fd use`、`fifo_file write`、`sigchld`、`getsched` 显式 allow，并将应用 stdin 一并置空 |
| 6 | tmpfs 挂载根 `/run` 为 `tmpfs_t`，应用无 search 权 → 进不了 `/run/hyos-tmp` | 探测 `TMP_WRITE=DENIED`（应 ALLOWED） | 补 `allow hyos_app_t tmpfs_t:dir { search getattr };` |
| 7 | CI 镜像 job `apt-get install` 在 ubuntu-24.04 失败（`awscli` 无候选 + Recommends 依赖损坏链，`-qq` 掩蔽细节） | GitHub Actions 构建依赖步骤 exit 100 | 移除 `awscli`（runner 自带 v2）、改 `--no-install-recommends` 并加逐包定位输出 |

### 8.3 enforcing 模式验证证据（deploy-test.img，QEMU x86_64 TCG）

```
SELINUX_POLICY_BYTES=1715650 / SELINUX_SETUP mounted=true policy_loaded=true / SELINUX_ENFORCE=1
GITKEY_READY bytes=464
SELINUX_SUPERVISOR_DOMAIN=system_u:system_r:kernel_t:s0
SELINUX_APP_LABEL=system_u:object_r:hyos_app_exec_t:s0
SELINUX_APP_DOMAIN=system_u:system_r:hyos_app_t:s0   (+ 复检 CHILD_ALIVE0/1=true, DOMAIN2=hyos_app_t)
PROBE BLKDEV_OPEN=DENIED(13)    # 块设备读取被拒（neverallow 断言）
PROBE CONFIG_WRITE=DENIED(13)   # /etc/hysteria 写被拒
PROBE TMP_WRITE=ALLOWED         # 仅 /run/hyos-tmp 私有区可写
PROBE ETC_WRITE=DENIED(13)      # /etc 写被拒
APP_OK sealed → ADVANCE OK seq=2 → HYOS E2E SUCCESS
```

诊断手段：内核参数 `hy_enforce=0` 可进 permissive 复跑（拒绝仍放行并留痕）；运行期回读文件 xattr 与 `/proc/mounts`；`type=1401 invalid_context` 事件是本轮定位角色授权缺失的关键线索。

### 8.4 CI 状态

- GitHub Actions（Steve5wutongyu6/HyOS）：单元测试 6/6 ✅、Worker 契约 21/21 ✅（Secrets 注入 + 本地 D1）；镜像 job 在依赖安装修复后执行内核/GRUB/用户态/SELinux/制品全量构建并上传 S3。

---

## 9. 内核最小化裁剪（2026-11-23 补充轮）

| 项 | 裁剪前 | 裁剪后 |
|---|---|---|
| 配置基线 | x86_64 `defconfig`（全量驱动 + 模块） | `allnoconfig` + 白名单合并（`scripts/kernel-minimal.config`） |
| bzImage | 13.4 MB | **4.35 MB（3.1 倍缩减）** |
| 可配置项 | ~2500 项 =y | **851 项 =y，0 模块** |
| 构建校验 | 无 | 47 项关键选项断言 + MODULES 必关断言（缺一即构建失败） |

### 9.1 保留清单（应用层运行所需）

| 类别 | 组件 | 用途 |
|---|---|---|
| 核心 | printk/epoll/futex/timer/membarrier/BINFMT_ELF/procfs/sysfs/tmpfs/devtmpfs | Rust 用户态 + supervisor 运行基座 |
| 控制台 | SERIAL_8250(+CONSOLE) | 串口审计标记（E2E 判定依据） |
| 块设备 | ATA/ATA_PIIX/SATA_AHCI/SCSI/BLK_DEV_SD + VIRTIO_BLK | 测试 QEMU IDE / 生产 KVM virtio；销毁写盘与镜像读取 |
| 网络 | IPv4/UNIX/CUBIC + E1000 + VIRTIO_NET | hysteria2(UDP/443) 与密钥服务通信 |
| netfilter | NF_CONNTRACK/NF_NAT/IP_NF_* + XT_NAT(DNAT) | 端口跳跃（20000:60000 → 443 DNAT） |
| 安全 | SELinux(+AUDIT/SECURITY_NETWORK 依赖链)、STACKPROTECTOR(+STRONG)、KASLR | 强制访问控制与硬化 |
| 平台 | ACPI/PCI/MSI/IOAPIC/KVM_GUEST/PARAVIRT/RELOCATABLE | BIOS/KVM 引导与 S5 断电（L5 销毁） |
| 随机源 | HW_RANDOM(+VIRTIO) | GCM/Ed25519 熵源 |

### 9.2 显式移除（实测不再编入）

HID/USB/Wireless/Bluetooth/声音/DRM/Framebuffer/RTC/Watchdog/Thermal/I2C/SPI/MMC/GPIO/EFI/Microcode、IPv6、全部磁盘文件系统(ext4/btrfs/xfs/9p/fuse)、Modules/Kexec/Hibernation/Swap/SysVIPC/io_uring/seccomp/kallsyms/namespaces/cgroups/perf/audit 以外审计组件。

### 9.3 过程中暴露的配置陷阱（对后续内核升级有参考价值）

| 陷阱 | 说明 |
|---|---|
| SELinux 依赖链 | `SECURITY_SELINUX` depends on `AUDIT && SECURITY_NETWORK && NET && INET`，缺一被 olddefconfig 静默丢弃 → 必须断言校验 |
| `NETFILTER_XT_TARGET_DNAT` 已并入 | 6.14 中 DNAT 目标由 `IP_NF_NAT` 自动 select 的 `XT_NAT` 提供，独立符号不存在 |
| STACKPROTECTOR 父子项 | `STACKPROTECTOR_STRONG` 依赖 `STACKPROTECTOR`（默认 y 但 allnoconfig 全关） |
| KASLR/IOAPIC | `RANDOMIZE_BASE` 依赖 `RELOCATABLE`；`X86_IO_APIC` 为 def_bool（显式写 `CONFIG_IO_APIC=y` 无效符号） |
| devtmpfs 必显式 | allnoconfig 下 `DEVTMPFS(_MOUNT)` 默认关，缺了 hyinit 无法挂载 /dev → spawn 失败 |

### 9.4 裁剪内核回归验证（本地 Lima，一次性提交前全绿）

- `final-verify.sh`：策略 1715650B → enforcing → GITKEY_READY 464B → 探测矩阵（块设备/配置/tmpfs//etc）→ APP_OK sealed → ADVANCE OK → **E2E SUCCESS**；契约 **21/21**。
- `tests/e2e.sh` 全量 9 场景：e1/e7/e8 `E2E SUCCESS`；e2/e3/e4/e5/e6 销毁标记齐全（L0/L1/grub_ok-refused/L2/L3）；e9 `L5 WIPE` → **E2E ALL PASS**。
- 构建脚本同时修复：用户态统一显式 `--target x86_64`（修复 CI proc-macro 单元异常；`crt-static` 仅经 CARGO_TARGET_* 注入，proc-macro 宿主工件不受污染）。

### 9.5 CI 镜像 job 第 5 步失败根因（2026-11-23 追加）

| 项 | 内容 |
|---|---|
| 症状 | runner 上 `build-policy.sh` 180ms 内静默退出，exit code 2，零输出（内核/用户态均已构建成功） |
| 根因 | `set -euo pipefail` 下 `POL=$(ls /etc/selinux/default/policy/policy.* 2>/dev/null | sort -V | tail -1)`——Ubuntu runner 无 SELinux 策略商店，`ls` 退出码 2，pipefail 经命令替换传播直接终止脚本（Debian VM 有基座商店故本地不可复现） |
| 复现 | VM 中移走 `/etc/selinux/default` 后运行脚本 → 完全复现（exit 2 / 零输出） |
| 修复 | ① `ls` 加 `|| true` 守卫 + 缺商店时显式报错退出 1；② CI apt 增加 `selinux-policy-default`（提供基座策略，runner 与 VM 同构）；③ `expand-check=0` 写入 semanage.conf（对齐 VM，加速 semodule 合并） |
| 验证 | 本地：有商店 `SELINUX_POLICY_OK bytes=1715650` ✓；无商店显式报错 exit 1 ✓；purge+重装包后 postinst 重建商店路径与 runner 全新装包一致 ✓ |

### 9.6 二次收紧（EXPERT 陷阱与 select 链，2026-11-23 追加）

| 项 | 内容 |
|---|---|
| 结果 | 816 项 =y（-35），bzImage **4.35 → 3.86 MB**（累计 13.4 → 3.86，3.5 倍） |
| EXPERT 陷阱 | `EXPERT` 关闭时 VT/PPS 等符号**无提示**，`default y` 绕过 unset 静默生效（VT→select INPUT→touchscreen.o）→ 开 `CONFIG_EXPERT=y` 让 unset 行生效 |
| select 链 ① | `WLAN`(default y) `select WIRELESS` → 需 unset **WLAN 断链头**（select 会覆盖显式 unset） |
| select 链 ② | `PTP_1588_CLOCK` **default ETHERNET** 且 `select PPS` → 需 unset **PTP_1588_CLOCK**（e1000 不依赖它，无 select 反拉） |
| 语法陷阱 | kconfig unset 行必须精确 `# CONFIG_X is not set`——行尾带注释文字则整行被当注释丢弃 |
| 反向断言 | build-kernel.sh 增加 VT/INPUT/TOUCHSCREEN/PPS/WIRELESS/USB/HID/SOUND/DRM/IPV6 十项"不得为 y"校验 |
| 回归 | contract 21/21 ✓ enforcing 引导 E2E SUCCESS ✓ 探测矩阵 ✓ |

### 9.7 CI 制品分发切换 R2（2026-11-23）

- S3（Bitiful cn-east-1）跨境上传慢 → 改 **Cloudflare R2**（同账号 API Token，`wrangler r2 object put`，无需 AWS 凭据；桶 `hyos-artifacts`，对象路径布局不变 `hyos/YYYYMMDD/deploy-<did>.img`）
- roundtrip 实测 put/get/delete 全通；工作流同步移除 awscli 依赖与 S3_* Secrets 注入（GH Secrets 中的 S3_* 保留但不再使用）

### 9.8 生产参数注入 + 一机一镜像（2026-11-23 追加）

| 项 | 内容 |
|---|---|
| 目标 | DD 部署前必须解决的三个生产阻塞：网络参数硬编码（QEMU 值/无网关）、hyinit 无 DNS、一机一镜像 |
| 注入通道 | `system.manifest`（**Ed25519 签名**）新增 `hy_net_ip/hy_net_mask/hy_net_gw/hy_srv/hy_srv_host` 字段 —— 篡改即验签失败触发销毁 |
| hyinit 改造 | ① 网络参数从签名清单读取（缺省回落 QEMU 联调值）；② 新增 `route_add_default_via`（netlink RTM_NEWROUTE + RTNH_F_ONLINK + RTA_OIF，ifindex 取自 sysfs）；③ HTTP Host 头可配（`hy_srv=IP:PORT@域名`，CF 边缘 IP 直连按 Host 路由，hyinit 无 DNS） |
| ioctl 路线废弃原因 | SIOCADDRT 在裁剪内核上 fib_check_nh_v4_gw 网关 fib_lookup 失败（ENETUNREACH/errno 101，非 SELinux——宿主内核同序列复现成功），netlink ONLINK 分支无此依赖 |
| 一机一镜像 | `scripts/build-for-target.sh --name X --net-ip/--net-mask/--net-gw/--srv [--test-mode]`：全新设备密钥 → 注册生产 → 用户态/GRUB 重建（**VK/WK0 必须绑定新密钥**，跳过即销毁）→ 清单注入 → initrd/镜像 → R2 `hyos/targets/<名称>/` |
| 验证 | 注入镜像 QEMU 引导：`NET UP 10.0.2.15/24` + `NET GW via 10.0.2.2 (netlink onlink)` + APP_OK sealed + **E2E SUCCESS**；默认路径回归：契约 21/21 + E2E SUCCESS |
| 部署约束 | 目标机必须 BIOS 引导；一机一镜像（共享镜像第二台触发 epoch 回滚销毁）；hy_srv 用 CF 边缘 IP + Host 头（明文 HTTP 传输有中间人风险，TLS 属后续 M 项） |

### 9.9 TLS 化（2026-11-23 追加）

| 项 | 内容 |
|---|---|
| 动机 | 明文 HTTP 下中间人可伪造 403 拒绝 ack → 强制销毁（on-path DoS）；TLS 服务器证书校验彻底关闭该攻击面 |
| 方案 | rustls 0.23（ring 后端，静态链接）+ webpki-roots 内嵌公共 CA；cargo feature `tls` 可选——本地 QEMU 联调走明文 HTTP（本地 worker 无 TLS），生产构建启用 |
| 时间依赖 | TLS 证书校验需要真实时间 → 内核启用 RTC_CLASS/HCTOSYS/RTC_DRV_CMOS（CMOS 硬件时钟 → 系统时钟），bzImage 3.86→3.88MB |
| hyinit 改造 | TLS_MODE 静态开关（清单 hy_tls=1）→ http_post 双模式（TCP/rustls）；SNI 与 HTTP Host 同取 hy_srv_host；**supervisor 为独立进程，TLS 标志经 HY_TLS 环境继承**（曾因静态变量不共享导致 supervisor 明文回退被 CF 拒绝销毁） |
| 失败语义 | hy_tls=1 但二进制不支持 → 拒绝明文回退 → 按服务器不可达销毁（fail-closed，符合宁毁勿漏） |
| 体积 | hyinit 静态二进制 1.6→2.84MB（+1.2MB TLS 栈） |
| 生产级验证 | QEMU 客机 → SLIRP NAT → 公网 → CF 边缘 IP:443 → TLS（SNI=hyos.nanachi.cloud，webpki 根校验，真实时间）→ grub_ok/sys_ok/app_ok/alive 全链路加密 ack → **E2E SUCCESS（Q_EXIT=0）** |
| 回归 | 明文路径 e2e 9/9 ALL PASS（TLS 改造无副作用）；CI 三 job 全绿 |
| 注意 | CF 边缘 IP 烘焙进镜像：IP 若退役设备将不可达 → 按设计销毁；运维需定期核验烘焙 IP；CMOS 电池失效同样触发 fail-closed |
