# server/tests fixtures

本目录下的密钥 fixture **不纳入版本库**（见根 .gitignore 的 `server/tests/fixtures/`）。

需要时在仓库根执行：

```bash
node scripts/gen-dev-keys.mjs   # 生成 tests/fixtures/dev-keys.json（已 gitignore）
```

切勿把任何含 `dk_priv_pkcs8_hex` / `srv_seed_hex` / `tk_master` / `wk*_root` / `dek_*`
的文件提交到仓库。
