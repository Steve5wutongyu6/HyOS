# HyOS

HyOS 是一个运行 Hysteria2 的裁剪版 Linux 发行版。

## 工作原理
1. **引导层**。GRUB 上电后比对内存中的镜像与磁盘上的原始字节，确认自身完整后，用内置密钥解开磁盘上的系统镜像，载入内存并引导内核。
2. **系统层**。内核反向校验 GRUB 的版本与签名，解密应用包，交给应用 supervisor。
3. **应用层**。服务启动前再次反向校验系统，随后从私有配置仓库拉取配置（仅存内存），启动 Hysteria2 与配套服务。
4. **运行期**。设备通过签名心跳与密钥服务保持联系；每次成功启动推进一代密钥，旧密钥随之作废。

## 本地开发与验证
我们建议通过Lima在本地进行构建和测试：
```bash
limactl start ./lima/hyos-dev.yaml --name hyos-dev
limactl shell hyos-dev -- bash /mnt/vmiss/hyos-build/tests/e2e.sh
```

## 许可证

见 [LICENSE](LICENSE)。
