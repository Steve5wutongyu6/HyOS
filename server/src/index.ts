// HyOS Key Server（Cloudflare Worker + D1）
// 设计文档 v1.2 §11。联调：wrangler dev --local；生产：wrangler deploy。
// 协议要点：
//   challenge: GET ?did&epoch&grub_ver&nc&sig （sig = DK_Ed25519("did|epoch|grub_ver|nc") hex）
//     响应 JSON { ns, nonce, ct, sig_srv }；SK_s = HKDF(TK_master, info="envelope"||nc||ns)
//     ct = AES-256-GCM(SK_s, payload_json, aad=nc||ns)，payload = {epoch, wrap_sys, ck}
//     sig_srv = Ed25519(SRV_SK, ct || nc || ns)
//   发钥规则: 仅 epoch >= last_acked；状态机 pending→grub_ok→sys_ok→app_ok→sealed

export interface Env {
  DB: D1Database;
  CI_TOKEN?: string;
  CF_DNS_TOKEN?: string;
  CF_DNS_ZONE_ID?: string;
  ACME_DOMAIN?: string;
  OWNER_TOKEN?: string;
  SRV_SK_PKCS8?: string; // hex of PKCS8 Ed25519 private key
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function hex(b: ArrayBuffer | Uint8Array): string {
  const u = b instanceof Uint8Array ? b : new Uint8Array(b);
  return [...u].map(x => x.toString(16).padStart(2, "0")).join("");
}
function unhex(s: string): Uint8Array {
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
function b64urlToBytes(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return new Uint8Array([...b].map(c => c.charCodeAt(0)));
}
function bytesToB64url(u: Uint8Array): string {
  return btoa(String.fromCharCode(...u)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as unknown as BufferSource));
}
function concat(...arrs: Uint8Array[]): Uint8Array {
  const len = arrs.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

async function srvSignKey(env: Env): Promise<CryptoKey> {
  const raw = unhex(env.SRV_SK_PKCS8 || "");
  return crypto.subtle.importKey("pkcs8", raw as unknown as BufferSource,
    { name: "Ed25519" }, false, ["sign"]);
}

async function deriveKek(root: Uint8Array, layer: Uint8Array, epochBe8: Uint8Array): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", root as unknown as BufferSource, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
    info: concat(layer, epochBe8) as unknown as BufferSource,
  }, base, 256);
  return new Uint8Array(bits);
}

async function hkdfEnvelope(tk: Uint8Array, nc: Uint8Array, ns: Uint8Array): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", tk as unknown as BufferSource, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
    info: concat(enc.encode("envelope"), nc, ns) as unknown as BufferSource,
  }, base, 256);
  return new Uint8Array(bits);
}

async function envelopeSeal(tk: Uint8Array, nc: Uint8Array, plaintext: Uint8Array) {
  const ns = crypto.getRandomValues(new Uint8Array(32));
  const sk = await hkdfEnvelope(tk, nc, ns);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", sk as unknown as BufferSource, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce as unknown as BufferSource,
      additionalData: concat(nc, ns) as unknown as BufferSource },
    key, plaintext as unknown as BufferSource));
  return { ns, nonce, ct };
}

async function dkVerify(dkPubHex: string, msg: Uint8Array, sigHex: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", unhex(dkPubHex) as unknown as BufferSource,
      { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key,
      unhex(sigHex) as unknown as BufferSource, msg as unknown as BufferSource);
  } catch { return false; }
}

function j(resp: unknown, status = 200) {
  return new Response(JSON.stringify(resp), { status, headers: { "content-type": "application/json" } });
}

// ---------- 响应鉴权与重放防护 ----------
// 设备侧固定服务端公钥校验签名；outcome 绑定请求一次性 nonce，跨次重放无效。
async function signOutcome(env: Env, msg: string): Promise<string> {
  const k = await srvSignKey(env);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, k, enc.encode(msg) as unknown as BufferSource));
  return hex(sig);
}

/// 返回带签名的应答：outcome 为单令牌（ok|state|event:xxx|err:xxx），msg 与设备侧拼装一致
async function jSigned(env: Env, status: number, outcome: string, msg: string, extra: Record<string, unknown> = {}) {
  const sig = await signOutcome(env, msg);
  return j({ ...extra, outcome, sig }, status);
}

/// 一次性 nonce 消费：重复即重放（返回 false）
async function consumeNonce(env: Env, did: string, nonce: string): Promise<boolean> {
  const r = await env.DB.prepare(
    "INSERT INTO nonces (did, nonce, ts) VALUES (?1,?2,?3) ON CONFLICT(did,nonce) DO NOTHING"
  ).bind(did, nonce, Date.now()).run();
  const changed = (r as any)?.meta?.changes ?? 0;
  // 机会式清理：保留 7 天内 nonce
  if (Math.random() < 0.02) {
    await env.DB.prepare("DELETE FROM nonces WHERE ts < ?1").bind(Date.now() - 7 * 86400000).run();
  }
  return changed > 0;
}

async function logEvent(env: Env, did: string, stage: string, epoch: number, evidence: string) {
  await env.DB.prepare("INSERT INTO events (did, stage, epoch, ip, ts, evidence) VALUES (?1,?2,?3,?4,?5,?6)")
    .bind(did, stage, epoch, "", Date.now(), evidence).run();
}

async function getDevice(env: Env, did: string) {
  return env.DB.prepare("SELECT * FROM devices WHERE did = ?1").bind(did).first<Record<string, any>>();
}

async function ensureEpoch(env: Env, did: string, epoch: number) {
  const row = await env.DB.prepare("SELECT * FROM epochs WHERE did=?1 AND epoch=?2").bind(did, epoch).first();
  if (!row) {
    const cur = await env.DB.prepare("SELECT COALESCE(MAX(last_acked_epoch),0) AS la FROM epochs WHERE did=?1").bind(did).first<{la:number}>();
    await env.DB.prepare("INSERT INTO epochs (did, epoch, state, last_acked_epoch, created_at) VALUES (?1,?2,'pending',?3,?4)")
      .bind(did, epoch, cur?.la ?? 0, Date.now()).run();
  }
  return env.DB.prepare("SELECT * FROM epochs WHERE did=?1 AND epoch=?2").bind(did, epoch).first<Record<string, any>>();
}

async function lastAcked(env: Env, did: string): Promise<number> {
  const r = await env.DB.prepare("SELECT COALESCE(MAX(last_acked_epoch),0) AS la FROM epochs WHERE did=?1").bind(did).first<{la:number}>();
  return r?.la ?? 0;
}

// ---------- challenge（GET，GRUB http 仅 GET） ----------
async function handleChallenge(env: Env, url: URL): Promise<Response> {
  const q = url.searchParams;
  const did = q.get("did") || "";
  const epoch = parseInt(q.get("epoch") || "0", 10);
  const grubVer = parseInt(q.get("grub_ver") || "0", 10);
  const ncB64 = q.get("nc") || "";
  const sig = q.get("sig") || "";
  if (!did || !(Number.isInteger(epoch) && epoch >= 1) || !ncB64 || !sig) return j({ error: "bad_request" }, 400);

  const dev = await getDevice(env, did);
  if (!dev) return j({ error: "unknown_device" }, 404);
  if (dev.status === "revoked" || dev.status === "quarantine") {
    await logEvent(env, did, "challenge_denied", epoch, "status=" + dev.status);
    return j({ error: "denied", status: dev.status }, 403);
  }
  if (grubVer > dev.grub_ver_max) {
    await logEvent(env, did, "challenge_denied", epoch, "grub_ver=" + grubVer);
    return j({ error: "grub_ver_rejected" }, 403);
  }
  const la = await lastAcked(env, did);
  if (epoch < la) {
    await logEvent(env, did, "epoch_regression", epoch, "last_acked=" + la);
    await env.DB.prepare("UPDATE devices SET status='quarantine' WHERE did=?1").bind(did).run();
    return j({ error: "epoch_regression" }, 403);
  }
  const nc = b64urlToBytes(ncB64);
  // DK 签名消息与 Rust proto/GNU 端一致：did|epoch|grub_ver|nc_b64url
  const m = enc.encode(did + "|" + epoch + "|" + grubVer + "|" + bytesToB64url(nc));
  const ok = await dkVerify(dev.dk_pub, m, sig);
  if (!ok) { await logEvent(env, did, "challenge_denied", epoch, "bad_dk_sig"); return j({ error: "bad_sig" }, 403); }

  await ensureEpoch(env, did, epoch);
  // ck = HMAC 不引入（联调阶段以 DK 签名 + ck 随负载下发占位）
  const ck = hex(await sha256(concat(unhex(dev.wk0_root), unhex(dev.wk1_root), new Uint8Array([epoch & 0xff]))));
  // wrap_sys = wrap(WK0[epoch], DEK1)：KEK 与 Rust kek() 同构 —— HKDF(ikm=wk_root, info="sys"+epoch_be8, salt=空)
  // 注：info 用 epoch 的 8B 大端而不是十进制字符串，保证与 proto/src/lib.rs::kek() 逐字节一致
  const e8info = new Uint8Array(8); new DataView(e8info.buffer).setBigUint64(0, BigInt(epoch));
  const kek0 = await deriveKek(unhex(dev.wk0_root), enc.encode("sys"), e8info);
  const nonceD = crypto.getRandomValues(new Uint8Array(12));
  const kek0Key = await crypto.subtle.importKey("raw", kek0 as unknown as BufferSource, "AES-GCM", false, ["encrypt"]);
  const e8 = new Uint8Array(8); new DataView(e8.buffer).setBigUint64(0, BigInt(epoch));
  const ctD = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonceD as unknown as BufferSource,
      additionalData: concat(enc.encode("hyos-dek"), e8) as unknown as BufferSource },
    kek0Key, unhex(dev.dek_sys) as unknown as BufferSource));
  const wrapSys = bytesToB64url(concat(nonceD, ctD));

  const payload = enc.encode(JSON.stringify({ epoch, wrap_sys: wrapSys, ck }));
  const { ns, nonce, ct } = await envelopeSeal(unhex(dev.tk_master), nc, payload);
  const skKey = await srvSignKey(env);
  const sigSrv = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, skKey,
    concat(ct, nc, ns) as unknown as BufferSource));
  await logEvent(env, did, "challenge", epoch, "ok");
  return j({ ns: bytesToB64url(ns), nonce: bytesToB64url(nonce), ct: bytesToB64url(ct), sig_srv: hex(sigSrv) });
}

// ---------- ack（POST JSON {did, stage, epoch, nonce, sig}） ----------
// 加固：一次性随机 nonce 消费（防重放）+ 响应 Ed25519 签名（防伪造/非法来源）
async function handleAck(env: Env, req: Request): Promise<Response> {
  const body = await req.json() as any;
  const { did, stage, epoch, nonce, sig } = body || {};
  if (!did || !stage || !epoch) return j({ error: "bad_request" }, 400);
  const nb = String(nonce || "");
  const om = (o: string) => did + "|" + stage + "|" + epoch + "|" + nb + "|" + o;

  const dev = await getDevice(env, did);
  if (!dev) return jSigned(env, 404, "err:unknown_device", om("err:unknown_device"));
  if (dev.status === "revoked" || dev.status === "quarantine")
    return jSigned(env, 403, "err:denied", om("err:denied"), { state: dev.status });

  const m = enc.encode(did + "|" + stage + "|" + epoch + "|" + nb);
  if (!nb || !(await dkVerify(dev.dk_pub, m, sig || "")))
    return jSigned(env, 403, "err:bad_sig", om("err:bad_sig"));

  // 重放防护：同一 (did, nonce) 只能成功消费一次
  if (!(await consumeNonce(env, did, nb))) {
    await logEvent(env, did, "ack_replay", epoch, stage);
    return jSigned(env, 409, "err:replay", om("err:replay"));
  }

  await ensureEpoch(env, did, epoch);
  const er = await env.DB.prepare("SELECT * FROM epochs WHERE did=?1 AND epoch=?2").bind(did, epoch).first<Record<string, any>>();
  const la = await lastAcked(env, did);
  if (epoch < la) return jSigned(env, 403, "err:epoch_regression", om("err:epoch_regression"));

  // 事件型 ack（不参与状态机推进）：心跳与安全事件
  const EVENT_ONLY = ["alive", "exec_deny", "grub_bad", "app_fail"];
  if (EVENT_ONLY.includes(stage)) {
    await logEvent(env, did, stage, epoch, String(nonce || ""));
    if (stage === "grub_bad" || stage === "app_fail") {
      await env.DB.prepare("UPDATE devices SET status='quarantine' WHERE did=?1").bind(did).run();
    }
    return jSigned(env, 200, "event:" + stage, om("event:" + stage), { ok: true, event: stage });
  }

  const order = ["pending", "grub_ok", "sys_ok", "app_ok", "sealed"];
  const curIdx = order.indexOf(er.state as string);
  const next = stage; // grub_ok|sys_ok|app_ok
  if (!order.slice(0, 4).includes(next))
    return jSigned(env, 400, "err:bad_stage", om("err:bad_stage"));
  if (order.indexOf(next) !== curIdx + 1)
    return jSigned(env, 409, "err:bad_transition", om("err:bad_transition"), { state: er.state });

  const ckHex = hex(await sha256(concat(unhex(dev.wk0_root), unhex(dev.wk1_root), new Uint8Array([epoch & 0xff]))));
  let extra: Record<string, string> = { ck: ckHex };
  if (next === "app_ok") {
    const eNext = epoch + 1;
    const e8n = new Uint8Array(8); new DataView(e8n.buffer).setBigUint64(0, BigInt(eNext));
    const kek0n = await deriveKek(unhex(dev.wk0_root), enc.encode("sys"), e8n);
    const kek1n = await deriveKek(unhex(dev.wk1_root), enc.encode("app"), e8n);
    const mk = async (kek: Uint8Array, dekHex: string) => {
      const k = await crypto.subtle.importKey("raw", kek as unknown as BufferSource, "AES-GCM", false, ["encrypt"]);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const e8 = new Uint8Array(8); new DataView(e8.buffer).setBigUint64(0, BigInt(eNext));
      const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as unknown as BufferSource,
          additionalData: concat(enc.encode("hyos-dek"), e8) as unknown as BufferSource },
        k, unhex(dekHex) as unknown as BufferSource));
      return bytesToB64url(concat(iv, ct));
    };
    const ckNext = hex(await sha256(concat(
      unhex(dev.wk0_root), unhex(dev.wk1_root), new Uint8Array([(eNext) & 0xff]))));
    extra = {
      wrapped_sys_next: await mk(kek0n, dev.dek_sys),
      wrapped_app_next: await mk(kek1n, dev.dek_app),
      ck_next: ckNext,
    };
  }

  const newState = next === "app_ok" ? "sealed" : next;
  if (next === "app_ok") {
    await env.DB.prepare("UPDATE epochs SET state='sealed', sealed_at=?3, last_acked_epoch=?2 WHERE did=?1 AND epoch=?2")
      .bind(did, epoch, Date.now()).run();
    await env.DB.prepare("UPDATE devices SET status='active', activated_at=COALESCE(activated_at,?2) WHERE did=?1")
      .bind(did, Date.now()).run();
  } else {
    await env.DB.prepare("UPDATE epochs SET state=?3 WHERE did=?1 AND epoch=?2").bind(did, epoch, next).run();
  }
  await logEvent(env, did, stage, epoch, "ok");
  return jSigned(env, 200, "state:" + newState, om("state:" + newState), { ok: true, state: newState, ...extra });
}

// ---------- enroll（CI 令牌，构建流水线自动注册） ----------
async function handleEnroll(env: Env, req: Request): Promise<Response> {
  if (!env.CI_TOKEN) return j({ error: "enroll_disabled" }, 501);
  const auth = req.headers.get("authorization") || "";
  if (auth !== "Bearer " + env.CI_TOKEN) return j({ error: "unauthorized" }, 401);
  const b = await req.json() as any;
  for (const k of ["did", "dk_pub", "tk_master", "wk0_root", "wk1_root", "dek_sys", "dek_app"]) {
    if (!b[k]) return j({ error: "missing:" + k }, 400);
  }
  await env.DB.prepare(`INSERT INTO devices
    (did, dk_pub, tk_master, wk0_root, wk1_root, dek_sys, dek_app, grub_ver_max, status, created_at)
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'provisioned',?9)
    ON CONFLICT(did) DO UPDATE SET dk_pub=excluded.dk_pub, status='provisioned'`)
    .bind(b.did, b.dk_pub, b.tk_master, b.wk0_root, b.wk1_root, b.dek_sys, b.dek_app,
      b.grub_ver_max ?? 1, Date.now()).run();
  // 重新注册 = 全新生命周期：清空历史 epoch 状态（与 CI 每次构建语义一致）
  await env.DB.prepare("DELETE FROM epochs WHERE did=?1").bind(b.did).run();
  await logEvent(env, b.did, "enroll", 0, "ci");
  return j({ ok: true, did: b.did, status: "provisioned" });
}

// ---------- acme-dns：设备 DK 签名鉴权的 DNS-01 TXT 代理（M5.1 证书续期） ----------
// 设备向 LE 申请证书时持有 DNS-01 挑战 token；Worker 代为写/删 TXT 记录。
// 设备永不持有 CF 凭据；鉴权与 /v1/ack 相同（DK 签名 + 设备白名单域名）。
async function handleAcmeDns(env: Env, req: Request): Promise<Response> {
  if (!env.CF_DNS_TOKEN || !env.CF_DNS_ZONE_ID) return j({ error: "acme_dns_disabled" }, 501);
  const b = await req.json().catch(() => ({})) as any;
  const { did, epoch, domain, token, action } = b || {};
  if (!did || !epoch || !domain || !token || !action) return j({ error: "bad_request" }, 400);
  if (action !== "set" && action !== "clear") return j({ error: "bad_action" }, 400);
  // 域名白名单：设备只能为本机绑定的 ACME 域名申请验证
  // 未配置白名单时一律拒绝（空列表 ≠ 允许任意域名；短路放行会造成任意域名 DNS-01 代理）
  const allowed = (env.ACME_DOMAIN || "").split(",").map((x: string) => x.trim()).filter(Boolean);
  if (allowed.length === 0) {
    await logEvent(env, did, "acme_dns_denied", epoch, "no_allowlist");
    return j({ error: "acme_allowlist_unset" }, 403);
  }
  if (!allowed.includes(domain)) {
    await logEvent(env, did, "acme_dns_denied", epoch, "domain=" + domain);
    return j({ error: "domain_not_allowed" }, 403);
  }
  const dev = await getDevice(env, did);
  if (!dev) return j({ error: "unknown_device" }, 404);
  if (dev.status === "revoked" || dev.status === "quarantine") return j({ error: "denied" }, 403);
  const nonceB64 = String(b.nonce || "");
  if (!nonceB64) return j({ error: "missing_nonce" }, 400);
  const m = enc.encode(did + "|acme_dns|" + epoch + "|" + nonceB64 + "|" + domain + "|" + token);
  if (!(await dkVerify(dev.dk_pub, m, b.sig || ""))) {
    await logEvent(env, did, "acme_dns_denied", epoch, "bad_sig");
    return j({ error: "bad_sig" }, 403);
  }
  // 一次性 nonce：防重放（同一 DNS-01 写/删请求不可被重投）
  const aom = (o: string) => did + "|acme_dns|" + epoch + "|" + nonceB64 + "|" + o;
  if (!(await consumeNonce(env, did, nonceB64))) {
    await logEvent(env, did, "acme_dns_denied", epoch, "replay");
    return jSigned(env, 409, "err:replay", aom("err:replay"));
  }
  const recName = "_acme-challenge." + domain;
  const zq = "https://api.cloudflare.com/client/v4/zones/" + env.CF_DNS_ZONE_ID + "/dns_records?name=" + encodeURIComponent(recName) + "&type=TXT";
  const zr = await fetch(zq, { headers: { authorization: "Bearer " + env.CF_DNS_TOKEN } });
  if (!zr.ok) return j({ error: "cf_list_fail" }, 502);
  const zl = (await zr.json()) as any;
  if (action === "set") {
    // upsert：先删同下全部旧 TXT（多次尝试不堆积陈旧 token 记录）
    for (const rec of (zl.result || [])) {
      await fetch("https://api.cloudflare.com/client/v4/zones/" + env.CF_DNS_ZONE_ID + "/dns_records/" + rec.id,
        { method: "DELETE", headers: { authorization: "Bearer " + env.CF_DNS_TOKEN } });
    }
    const c = await fetch("https://api.cloudflare.com/client/v4/zones/" + env.CF_DNS_ZONE_ID + "/dns_records",
      { method: "POST", headers: { authorization: "Bearer " + env.CF_DNS_TOKEN, "content-type": "application/json" },
        body: JSON.stringify({ type: "TXT", name: recName, content: token, ttl: 120 }) });
    if (!c.ok) return j({ error: "cf_set_fail" }, 502);
  } else {
    for (const rec of (zl.result || [])) {
      await fetch("https://api.cloudflare.com/client/v4/zones/" + env.CF_DNS_ZONE_ID + "/dns_records/" + rec.id,
        { method: "DELETE", headers: { authorization: "Bearer " + env.CF_DNS_TOKEN } });
    }
  }
  await logEvent(env, did, "acme_dns_" + action, epoch, domain);
  return jSigned(env, 200, "ok:" + action, aom("ok:" + action), { ok: true, action, domain });
}

// ---------- owner：revoke / quarantine-clear / rearm / policy ----------
async function ownerGate(env: Env, req: Request): Promise<boolean> {
  return !!env.OWNER_TOKEN && req.headers.get("authorization") === "Bearer " + env.OWNER_TOKEN;
}

async function handleOwner(env: Env, req: Request, url: URL): Promise<Response> {
  if (!(await ownerGate(env, req))) return j({ error: "unauthorized" }, 401);
  const op = url.pathname.replace("/v1/", "");
  const b = await req.json().catch(() => ({})) as any;
  const did = b.did || url.searchParams.get("did") || "";
  if (!did) return j({ error: "missing_did" }, 400);
  if (op === "revoke") {
    await env.DB.prepare("UPDATE devices SET status='revoked' WHERE did=?1").bind(did).run();
  } else if (op === "rearm") {
    await env.DB.prepare("DELETE FROM epochs WHERE did=?1").bind(did).run();
    await env.DB.prepare("UPDATE devices SET status='provisioned' WHERE did=?1").bind(did).run();
    await logEvent(env, did, "rearm", 0, "owner");
  } else if (op === "policy") {
    return j({ error: "not_implemented_in_e2e" }, 501);
  } else return j({ error: "unknown_op" }, 404);
  return j({ ok: true, op, did });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      if (p === "/v1/health") return j({ ok: true, ts: Date.now() });
      if (p === "/v1/boot/challenge" && req.method === "GET") return handleChallenge(env, url);
      if (p === "/v1/ack" && req.method === "POST") return handleAck(env, req);
      if (p === "/v1/enroll" && req.method === "POST") return handleEnroll(env, req);
      if (p === "/v1/acme-dns" && req.method === "POST") return handleAcmeDns(env, req);
      if (p.startsWith("/v1/") && req.method === "POST") return handleOwner(env, req, url);
      return j({ error: "not_found" }, 404);
    } catch (e: any) {
      return j({ error: "internal", detail: String(e?.message || e) }, 500);
    }
  }
};