import os
import re
import shutil

# 渲染 HysteriaConfig 模板 → HyOS 应用包配置（机密从 SOPS 解密注入）
# 前置：sops 已解密 users.yaml.sops 到 /tmp/users.dec.yaml；SOPS_AGE_KEY_FILE 已设置
# 输出：/tmp/app-config.yaml（hysteria2 配置）/tmp/app-auth.env（hyauth 机密）
#       /tmp/bft-proxy.conf（hyproxy 参数）/tmp/bft-porthop.conf（DNAT 规则）

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
# masquerade 移交 hyproxy（Pingora）：hysteria 只做 UDP 隧道，去掉内置 masquerade 段
cfg = re.sub(r"masquerade:\n(?:  .*\n)+", "", cfg)
# listen 高位端口（TCP 443/80 让给 hyproxy；跳跃区间 UDP 由 porthop DNAT 转发到本端口）
cfg = cfg.replace("listen: :443", "listen: :8443")
open("/tmp/app-config.yaml", "w").write(cfg)

# hyproxy 配置：透传配置仓库模板（KEY=VALUE 定值；改参数改仓库重构建）
_pc = "/mnt/vmiss/HysteriaConfig/masquerade/proxy.conf.j2"
if os.path.exists(_pc):
    shutil.copy(_pc, "/tmp/bft-proxy.conf")
else:
    open("/tmp/bft-proxy.conf", "w").write("UPSTREAM_URL=https://nanachi.cloud\nUPSTREAM_HOST=nanachi.cloud\n")

# porthop.conf：DNAT 目标 443 → hysteria2 新监听端口 8443
_ph = "/mnt/vmiss/HysteriaConfig/firewall/porthop.conf"
if os.path.exists(_ph):
    pt = open(_ph).read().replace("--to-ports 443", "--to-ports 8443")
    open("/tmp/bft-porthop.conf", "w").write(pt)

env = "HYSTERIA_AUTH_SECRET=" + secret + "\nHYSTERIA_AUTH_ID=" + uid + "\n"
open("/tmp/app-auth.env", "w").write(env)
print("RENDER_OK psk_len=%d secret_len=%d id=%s hy2_port=8443" % (len(psk), len(secret), uid))
