import os
import re
import shutil

# 渲染 HysteriaConfig 模板 → HyOS 应用包配置
# 原则：应用层参数（端口/路径/上游/规则/DNS）**只在 HysteriaConfig 定义**，
#       本脚本仅做「机密注入」与「文件搬运」，不改写任何语义字段。
# 输入：/tmp/users.dec.yaml（sops 解密后的明文）
# 输出：/tmp/bft-app-config.yaml /tmp/bft-app-auth.env /tmp/bft-proxy.conf
#       /tmp/bft-porthop.conf /tmp/bft-resolv.conf

HC = os.environ.get("HYSTERIA_CONFIG_DIR", "/mnt/vmiss/HysteriaConfig")
users = open("/tmp/users.dec.yaml").read()

def field(pattern, what):
    m = re.search(pattern, users)
    if not m:
        raise SystemExit("users.yaml 缺少字段: " + what)
    return m.group(1)

psk = field(r"psk:\s*\"?([A-Za-z0-9_\-]+)\"?", "obfs.psk")
secret = field(r"password:\s*\"?([A-Za-z0-9_\-]+)\"?", "users[0].password")
uid = field(r"id:\s*\"?([A-Za-z0-9_\-]+)\"?", "users[0].id")
listen = field(r"listen:\s*\"?([0-9.:\[\]a-zA-Z_\-]+)\"?", "auth.listen")

# ---- hysteria2 服务端配置：仅替换机密与认证地址占位符 ----
tpl = open(os.path.join(HC, "hysteria/config.yaml.j2")).read()
if "{{ hysteria.obfs_psk }}" not in tpl:
    raise SystemExit("config.yaml.j2 缺少 obfs 占位符")
cfg = tpl.replace("{{ hysteria.obfs_psk }}", psk).replace("{{ auth.listen }}", listen)
open("/tmp/bft-app-config.yaml", "w").write(cfg)

# ---- hyauth 凭据与监听地址（经环境变量交付，文件用后即删）----
env = "HYSTERIA_AUTH_SECRET=" + secret + "\nHYSTERIA_AUTH_ID=" + uid + "\nHYSTERIA_AUTH_LISTEN=" + listen + "\n"
open("/tmp/bft-app-auth.env", "w").write(env)

# ---- hyproxy 伪装反代参数（上游连接地址由构建期烘焙，避免运行期 DNS）----
_up_ip = os.environ.get("HY_UPSTREAM_IP", "")
_up_addr = (_up_ip + ":443") if _up_ip else ""
_pc = os.path.join(HC, "masquerade/proxy.conf.j2")
if not os.path.exists(_pc):
    raise SystemExit("缺少 masquerade/proxy.conf.j2")
_pt = open(_pc).read().replace("{{ upstream_addr }}", _up_addr)
open("/tmp/bft-proxy.conf", "w").write(_pt)

# ---- port hopping 规则（模板即最终值）----
_ph = os.path.join(HC, "firewall/porthop.conf")
if not os.path.exists(_ph):
    raise SystemExit("缺少 firewall/porthop.conf")
shutil.copy(_ph, "/tmp/bft-porthop.conf")

# ---- DNS ----
_rs = os.path.join(HC, "network/resolv.conf")
if not os.path.exists(_rs):
    raise SystemExit("缺少 network/resolv.conf")
shutil.copy(_rs, "/tmp/bft-resolv.conf")

print("RENDER_OK psk_len=%d secret_len=%d id=%s auth_listen=%s upstream=%s"
      % (len(psk), len(secret), uid, listen, _up_addr))
