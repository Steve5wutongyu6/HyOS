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
