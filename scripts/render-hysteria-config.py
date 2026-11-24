# 渲染 HysteriaConfig 模板 → HyOS 应用包配置（机密从 SOPS 解密注入）
# 前置：sops 已解密 users.yaml.sops 到 /tmp/users.dec.yaml；SOPS_AGE_KEY_FILE 已设置
# 输出：/tmp/app-config.yaml（hysteria2 服务端配置）与 /tmp/app-auth.env（hyauth 机密）
import re

users = open("/tmp/users.dec.yaml").read()
psk_m = re.search(r"psk:\s*\"?([A-Za-z0-9_-]+)\"?", users)
secret_m = re.search(r"password:\s*\"?([A-Za-z0-9_-]+)\"?", users)
id_m = re.search(r"id:\s*\"?([A-Za-z0-9_-]+)\"?", users)
if not (psk_m and secret_m and id_m):
    raise SystemExit("users.yaml 机密字段缺失")
psk, secret, uid = psk_m.group(1), secret_m.group(1), id_m.group(1)

tpl = open("/mnt/vmiss/HysteriaConfig/hysteria/config.yaml.j2").read()
if "{{ hysteria.obfs_psk }}" not in tpl:
    raise SystemExit("模板占位符异常")
cfg = tpl.replace("{{ hysteria.obfs_psk }}", psk)
cfg = cfg.replace("/etc/hysteria/tls/fullchain.pem", "/run/apps/tls/fullchain.pem")
cfg = cfg.replace("/etc/hysteria/tls/key.pem", "/run/apps/tls/key.pem")
open("/tmp/app-config.yaml", "w").write(cfg)

env = "HYSTERIA_AUTH_SECRET=" + secret + "\nHYSTERIA_AUTH_ID=" + uid + "\n"
open("/tmp/app-auth.env", "w").write(env)
print("RENDER_OK psk_len=%d secret_len=%d id=%s" % (len(psk), len(secret), uid))
