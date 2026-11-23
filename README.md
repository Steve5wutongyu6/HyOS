# HyOS

**HyOS** 是一个专用于运行 Hysteria2 的裁剪 Linux 发行版，围绕三条安全主线构建：**安全启动自校验**、**双层加密**、**失败即自动销毁**。

配套设计文档：《HyOS 安全启动与自动销毁设计方案》(v1.3) 与《Lima 联调验证报告》(见 `docs/`)。

---

## 设计要点

| 层次 | 机制 |
|---|---|
| GRUB (S1) | 上电自校验(窗口哈希 + Ed25519 签名 + 白盒常量) → 双槽解析 → 用白盒 KEK 解槽内 wrap → AES-256-GCM 解密系统镜像入内存 → 注册 hyram 内存盘 → 引导内核 |
| 内核/initramfs (S2) | 反向校验 GRUB(版本/镜像哈希/DK 签名钉扎) → 校验系统清单 → 解密应用包(DEK2)入 tmpfs → 校验 app.manifest |
| 应用层 (S3) | 反向校验系统(rootfs 哈希 + 密钥一致性) → 短时令牌拉取私有 Git 配置(仅内存) → 按清单启动服务 |
| SELinux (S3+) | enforcing 最小权限：应用锁定 `hyos_app_t` 域（块设备/危险能力/ptrace 编译期 neverallow），仅 `/run/hyos-tmp` 可写，配置只读；策略单块离线合成、构建期嵌入 |
| 运行期 (S4) | 签名 ack 心跳、epoch 推进、失联即销毁 |

**销毁等级**：L0 GRUB 自毁 / L1 镜像区 / L2 应用包 / L3 应用自毁 / L4 未签名执行(待 IMA 落地) / L5 运行期失联全盘。

**密钥体系**：`WK0_root`(GRUB 白盒) → `WK0[e]` → `wrap(DEK1)`；`WK1_root`(验证器白盒) → `WK1[e]` → `wrap(DEK2)`；设备身份 `DK` 用于双向证明。每次成功启动推进 epoch 并由服务端签发下一轮 KEK。

---

## 目录结构

```
grub/       定制 GRUB 模块 hyverify(C)：自校验、槽解析、GCM 解密、销毁写盘
proto/      Rust 密码学核心：HKDF/KEK、AES-256-GCM、Ed25519、双槽头、信封
verifier/   Rust initramfs 验证器 + 应用 supervisor(静态 x86_64)
tools/      mkdisk(镜像组装/签名)、stubapp(联调占位应用)
scripts/    构建脚本：内核、GRUB、用户态、initrd、密钥生成
server/     Cloudflare Worker 密钥服务(本地 D1 可离线联调)
tests/      e2e.sh / contract.mjs 与 devtools/(诊断工具)
selinux/    SELinux 强制访问控制策略(用户态最小权限)
lima/       本地 Lima 联调环境定义
docs/       验证报告等技术文档
```

---

## 本地联调(Lima)

```bash
limactl start ./lima/hyos-dev.yaml --name hyos-dev
limactl shell hyos-dev -- bash /mnt/vmiss/hyos-build/tests/e2e.sh
```

`tests/e2e.sh` 会依次完成：清场 → 生成设备密钥 → 启动本地 Worker(wrangler dev + 本地 D1) → Worker 契约测试 → 全量构建(GRUB core.img / hyinit / initrd / 磁盘镜像) → 9 个引导场景断言(正常启动、epoch 推进、re-arm、L0–L5 销毁)。

最近一次结果：**9/9 场景通过，契约 21/21；SELinux enforcing 模式 E2E SUCCESS**（应用域隔离 + 最小权限探测矩阵，见 `docs/lima-验证报告.md` §8）。

---

## CI(GitHub Actions)

工作流见 `.github/workflows/build.yml`。所有机密均通过 **GitHub Secrets** 注入，仓库内不含任何明文凭据。

## 生产部署

| 组件 | 值 |
|---|---|
| 密钥服务 | Cloudflare Worker `hyos-keyserver`，生产地址 **https://hyos.nanachi.cloud**（custom domain，自动 DNS/证书） |
| 数据库 | Cloudflare D1 `hyos`（`schema.sql` 已应用） |
| Secrets | `CI_TOKEN` / `OWNER_TOKEN` / `SRV_SK_PKCS8` 经 `wrangler secret` 注入（生成器：`scripts/gen-prod-secrets.mjs`，产物存仓库外） |
| CI 联动 | GH Actions 变量 `WORKER_URL` + Secret `HYOS_CI_TOKEN` → 构建尾自动 enroll 新设备；产物上传 S3 私有桶 |

运维操作：`OWNER_TOKEN` 用于 `/v1/rearm`（允许旧磁盘头再启动）与 `/v1/revoke`（立即吊销，下次启动即销毁）。

| Secret | 用途 |
|---|---|
| `HYOS_GIT_SSH_KEY` | 读取私有配置仓库(HysteriaConfig)的**只读 Deploy Key** |
| `HYOS_GIT_SSH_PASSPHRASE` | 上述密钥口令 |
| `S3_AK` / `S3_SK` | 制品上传(S3 私有桶) |
| `S3_ENDPOINT` / `S3_REGION` / `S3_BUCKET` | 对象存储定位 |
| `CF_API_TOKEN` / `CF_ACCOUNT_ID` | 发布 D1 清单与 Worker |
| `HYOS_SIGNING_KEY` | 镜像/清单签名私钥(离线保管，仅 CI 使用) |

> 部署密钥在构建期以**份额拆分 + 运行期重组**(与 GRUB 白盒同机制)嵌入镜像，运行期仅用于在内存中拉取私有配置，配置文件不落盘。该保护属于纵深防御：真正的边界是镜像本身的加密与访问控制。

---

## 许可与第三方

- 本项目代码：见 `LICENSE`。
- `grub/tweetnacl.c`：TweetNaCl(public domain)。
- `grub/aes.c`：tiny-AES-c(MIT)。
- GRUB / Linux 内核为运行期从官方源下载的独立项目，遵循其各自许可(GPL)。
