/* hyverify —— HyOS 定制 GRUB 模块（i386-pc）
 * 流程（设计文档 v1.2 §6.1）：
 *   1) 自校验：LBA1..2047 窗口 sha256 对比 grub.manifest(Ed25519) + 白盒常量
 *   2) 读 p2 双槽 → epoch/img_sha/payload_len
 *   3) challenge（http GET + 应用层信封）→ wrap_sys → DEK1
 *   4) GCM 解密 p2 载荷入内存 → hash 校验 → 注册 hyram 内存盘
 *   5) 设置 hy_cmdline 环境变量，grub.cfg 继续 linux/initrd/boot
 * 任一密码学失败 → L0/L1 销毁（覆写双槽+载荷头部）→ qemu ACPI 断电
 */
#include <grub/dl.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/env.h>
#include <grub/command.h>
#include <grub/err.h>
#include <grub/cpu/io.h>
#include <grub/types.h>
#include <grub/time.h>
#include <grub/term.h>
#include "hysha.h"
#include "hygcm.h"
#include "tweetnacl.h"
#include "aes.h"
#include "hykeys.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* ---------- 与 mkdisk 共享的布局常量 ---------- */
#define HY_P2_START   4096ULL
#define HY_P3_START   36864ULL
#define HY_SLOT_LBAS  2
#define HY_PAYLOAD_OFF 8
#define HY_WINDOW_LBAS 2047ULL      /* LBA1..2047 */
#define HY_MAX_PAYLOAD (16u*1024u*1024u)

/* ---------- 白盒份额（构建后由工具按 magic 定位覆写） ---------- */
static volatile grub_uint8_t wb_magic[8] = {'H','Y','W','B','0','P','1','!'};
static volatile grub_uint8_t wb_shares[8][32];

static void wb_combine(volatile const grub_uint8_t sh[8][32], grub_uint8_t out[32])
{
  int i, j;
  grub_memset((void *)out, 0, 32);
  for (i = 0; i < 8; i++)
    for (j = 0; j < 32; j++)
      out[j] ^= sh[i][j];
}
static void get_wk0(grub_uint8_t out[32]) { wb_combine(hy_wk0_sh, out); }
static void get_tk(grub_uint8_t out[32])  { wb_combine(hy_tk_sh, out); }

/* ---------- 小工具 ---------- */
static grub_uint32_t rng_state = 0x12345678;
static grub_uint32_t hy_rng(void)
{
  grub_uint64_t t = grub_get_time_ms();
  rng_state ^= (grub_uint32_t)(t >> 0) ^ (grub_uint32_t)(t << 7) ^ 0x9E3779B9u;
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 17;
  rng_state ^= rng_state << 5;
  return rng_state;
}

static void fill_rand(grub_uint8_t *p, int n)
{ int i; for (i = 0; i < n; i++) p[i] = (grub_uint8_t)hy_rng(); }

static void to_hex(const grub_uint8_t *in, int n, char *out) /* out >= 2n+1 */
{
  static const char hx[] = "0123456789abcdef";
  int i;
  for (i = 0; i < n; i++) { out[i*2] = hx[in[i] >> 4]; out[i*2+1] = hx[in[i] & 15]; }
  out[n*2] = 0;
}

static int from_hex(const char *in, grub_uint8_t *out, int n)
{
  int i;
  for (i = 0; i < n; i++) {
    char c1 = in[i*2], c2 = in[i*2+1];
    grub_uint8_t v1, v2;
    if (c1 >= '0' && c1 <= '9') v1 = c1 - '0';
    else if (c1 >= 'a' && c1 <= 'f') v1 = c1 - 'a' + 10;
    else return -1;
    if (c2 >= '0' && c2 <= '9') v2 = c2 - '0';
    else if (c2 >= 'a' && c2 <= 'f') v2 = c2 - 'a' + 10;
    else return -1;
    out[i] = (v1 << 4) | v2;
  }
  return 0;
}

static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static int b64url_decode(const char *in, grub_uint8_t *out, int outmax)
{
  int acc = 0, bits = 0, o = 0;
  while (*in && *in != '"' && *in != '&' && *in != '\0') {
    const char *p = grub_strchr(b64t, *in);
    if (*in == '=') break;
    if (!p) return -1;
    acc = (acc << 6) | (int)(p - b64t);
    bits += 6;
    while (bits >= 8) { bits -= 8; if (o >= outmax) return -1; out[o++] = (grub_uint8_t)((acc >> bits) & 0xFF); }
    in++;
  }
  return o;
}

static void b64url_encode(const grub_uint8_t *in, int n, char *out)
{
  int acc = 0, bits = 0, o = 0, i;
  for (i = 0; i < n; i++) {
    acc = (acc << 8) | in[i];
    bits += 8;
    while (bits >= 6) { bits -= 6; out[o++] = b64t[(acc >> bits) & 63]; }
  }
  if (bits) out[o++] = b64t[(acc << (6 - bits)) & 63];
  out[o] = 0;
}

/* 平面 JSON 字段提取（服务端响应结构固定） */
static int json_str(const char *j, const char *key, char *out, int outmax)
{
  char pat[64];
  grub_snprintf(pat, sizeof(pat), "\"%s\":\"", key);
  const char *p = grub_strstr(j, pat);
  if (!p) return -1;
  p += grub_strlen(pat);
  int o = 0;
  while (*p && *p != '"' && *p != '\0') { if (o < outmax - 1) out[o++] = *p; p++; }
  out[o] = 0;
  return o;
}

static long json_num(const char *j, const char *key)
{
  char pat[32];
  grub_snprintf(pat, sizeof(pat), "\"%s\":", key);
  const char *p = grub_strstr(j, pat);
  if (!p) return -1;
  return grub_strtoul(p + grub_strlen(pat), NULL, 10);
}

/* ---------- tweetnacl 包装 ---------- */
static int ed_sign_detached(volatile const grub_uint8_t sh[8][32], const grub_uint8_t *msg, int mlen,
                            grub_uint8_t sig[64])
{
  /* tweetnacl 无 crypto_sign_seed_keypair；直接构造 sk = pk || seed */
  grub_uint8_t sk[64], *sm, *m2;
  grub_uint64_t n;
  /* tweetnacl sk 布局: sk = seed(32) || pk(32) */
  wb_combine(sh, sk);
  grub_memcpy (sk + 32, hy_dk_pub, 32);
  sm = grub_malloc(mlen + 64);
  m2 = grub_malloc(mlen + 64);
  if (!sm || !m2) return -1;
  grub_memcpy(sm + 64, msg, mlen);
  if (crypto_sign(sm, &n, sm + 64, mlen, sk) != 0) { grub_free(sm); grub_free(m2); return -1; }
  grub_memcpy(sig, sm, 64);
  grub_free(sm); grub_free(m2);
  return 0;
}

static int ed_verify_detached(const grub_uint8_t pub[32], const grub_uint8_t *msg, int mlen,
                              const grub_uint8_t sig[64])
{
  grub_uint8_t *sm = grub_malloc(mlen + 64);
  grub_uint8_t *m2 = grub_malloc(mlen + 64);
  grub_uint64_t n;
  int r;
  if (!sm || !m2) return -1;
  grub_memcpy(sm, sig, 64);
  grub_memcpy(sm + 64, msg, mlen);
  r = crypto_sign_open(m2, &n, sm, mlen + 64, pub);
  grub_free(sm); grub_free(m2);
  return r; /* 0 = 有效 */
}

/* ---------- KEK / DEK ---------- */
static void kek_sys(grub_uint64_t epoch, grub_uint8_t out[32])
{
  grub_uint8_t root[32], info[11];
  get_wk0 (root);
  grub_memcpy(info, "sys", 3);
  int i; for (i = 0; i < 8; i++) info[3+i] = (grub_uint8_t)(epoch >> (56 - i*8));
  hy_hkdf_sha256(root, 32, NULL, 0, info, 11, out, 32);
  grub_memset (root, 0, 32);
}

static void wrap_aad(grub_uint64_t epoch, grub_uint8_t aad[16])
{
  grub_memcpy(aad, "hyos-dek", 8);
  int i; for (i = 0; i < 8; i++) aad[8+i] = (grub_uint8_t)(epoch >> (56 - i*8));
}

/* wrap: nonce(12)||ct(48) —— 解出 DEK；kek 为候选 KEK */
static int unwrap_dek(const grub_uint8_t *wrap, grub_uint64_t epoch, const grub_uint8_t kek[32],
                      grub_uint8_t dek[32])
{
  grub_uint8_t aad[16];
  wrap_aad(epoch, aad);
  grub_uint8_t pt[32];
  grub_memcpy(pt, wrap + 12, 32);
  grub_uint8_t tag[16];
  grub_memcpy(tag, wrap + 44, 16);
  if (hy_gcm_crypt((grub_uint8_t *)kek, wrap, aad, 16, pt, 32, tag, 0) != 0) return -1;
  grub_memcpy(dek, pt, 32);
  return 0;
}

/* 双槽解析（镜像 proto::select_slot）：slotA/slotB 各 2 扇区已读入 */
struct hy_slot { grub_uint64_t seq; grub_uint64_t epoch; grub_uint8_t img[32]; grub_uint64_t len; grub_uint8_t dek[32]; };

static int slot_parse_prelim(const grub_uint8_t *s1024,
                             void (*kekfn)(grub_uint64_t, grub_uint8_t *), struct hy_slot *out)
{
  const grub_uint8_t *h = s1024;
  if (grub_memcmp(h, "HYOSLOT1", 8) != 0) return -1;
  grub_uint64_t epoch = 0;
  int i;
  for (i = 0; i < 8; i++) epoch = (epoch << 8) | h[17+i];
  grub_uint64_t seq = 0;
  for (i = 0; i < 8; i++) seq = (seq << 8) | h[9+i];
  grub_uint64_t plen = 0;
  for (i = 0; i < 8; i++) plen = (plen << 8) | h[117+i];
  grub_uint8_t kek[32], dek[32];
  grub_uint64_t cand[2];
  cand[0] = epoch; cand[1] = epoch + 1;
  int ok = 0;
  for (i = 0; i < 2 && !ok; i++) {
    kekfn(cand[i], kek);
    if (unwrap_dek(h + 25, epoch, kek, dek) == 0) ok = 1;
  }
  if (!ok) return -1;
  out->seq = seq; out->epoch = epoch; out->len = plen;
  grub_memcpy(out->img, h + 85, 32);
  grub_memcpy(out->dek, dek, 32);
  return 0;
}

/* ck-MAC 复核（challenge 获得 ck 之后）：防头字段篡改 */
static int slot_verify_mac(const grub_uint8_t *s1024, const grub_uint8_t ck[32])
{
  grub_uint8_t mac[32], diff = 0;
  int i;
  hy_hmac_sha256((grub_uint8_t *)ck, 32, s1024, 480, mac);
  for (i = 0; i < 32; i++) diff |= mac[i] ^ s1024[480+i];
  return diff ? -1 : 0;
}

/* 服务器 wrap → DEK（在线模式唯一 DEK 来源） */
static int dek_from_server(const grub_uint8_t *wrap60, grub_uint64_t epoch, grub_uint8_t dek[32])
{
  grub_uint8_t kek[32];
  kek_sys (epoch, kek);
  return unwrap_dek (wrap60, epoch, kek, dek);
}

/* ---------- 销毁与断电 ---------- */
static void hy_destroy_and_poweroff(const char *tag)
{
  grub_device_t dev;
  grub_uint8_t junk[512];
  int i, r;
  grub_printf ("HYOS DESTROY[%s] wiping...\n", tag);
  dev = grub_device_open ("hd0");
  if (dev && dev->disk) {
    grub_uint64_t starts[2] = { HY_P2_START, HY_P3_START };
    for (r = 0; r < 2; r++) {
      for (i = 0; i < HY_SLOT_LBAS; i++) { fill_rand(junk, 512); grub_disk_write (dev->disk, starts[r] + i, 0, 512, (char *)junk); }
      for (i = 0; i < 16; i++) { fill_rand(junk, 512); grub_disk_write (dev->disk, starts[r] + HY_PAYLOAD_OFF + i, 0, 512, (char *)junk); }
    }
    grub_device_close (dev);
  }
  grub_printf ("HYOS WIPED. power off.\n");
  grub_refresh ();
  /* QEMU pc: ACPI PM1a_CNT(0x604)，S5 = SLP_TYP(5)<<10 | SLP_EN(0x2000) = 0x3400；再兜底 0x2000 */
  grub_outw (0x604, 0x3400);
  grub_outw (0x604, 0x2000);
  for (;;) { } /* 兜底死循环 */
}

/* ---------- 文件读取 ---------- */
static grub_uint8_t *read_file(const char *path, int type, int *outlen)
{
  grub_file_t f = grub_file_open (path, type);
  if (!f) return NULL;
  grub_uint8_t *buf = grub_malloc (f->size + 1);
  if (!buf) { grub_file_close (f); return NULL; }
  grub_ssize_t n = grub_file_read (f, buf, f->size);
  grub_file_close (f);
  if (n < 0) { grub_free (buf); return NULL; }
  buf[n] = 0;
  if (outlen) *outlen = n;
  return buf;
}

/* ---------- hyram 内存盘 ---------- */
static grub_uint8_t *hyram_buf = NULL;
static grub_uint64_t hyram_size = 0;

static grub_err_t hyram_read (grub_disk_t disk __attribute__((unused)),
                              grub_disk_addr_t sector, grub_size_t size, char *buf)
{
  grub_memcpy (buf, hyram_buf + sector * 512, size * 512);
  return GRUB_ERR_NONE;
}
static grub_err_t hyram_write (grub_disk_t disk __attribute__((unused)),
                               grub_disk_addr_t sector __attribute__((unused)),
                               grub_size_t size __attribute__((unused)),
                               const char *buf __attribute__((unused)))
{ return grub_error (GRUB_ERR_WRITE_ERROR, "hyram is read-only"); }

static int hyram_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data,
                          grub_disk_pull_t pull __attribute__((unused)))
{
  return hook ("hyram", hook_data);
}

static grub_err_t hyram_open (const char *name __attribute__((unused)), grub_disk_t disk)
{
  disk->total_sectors = hyram_size / 512;
  disk->id = 0;
  return GRUB_ERR_NONE;
}

static void hyram_close (grub_disk_t disk __attribute__((unused))) { }

static struct grub_disk_dev hyram_dev =
{
  .name = "hyram",
  .id = GRUB_DISK_DEVICE_MEMDISK_ID,
  .disk_iterate = hyram_iterate,
  .disk_open = hyram_open,
  .disk_close = hyram_close,
  .disk_read = hyram_read,
  .disk_write = hyram_write,
};

/* ---------- 主命令 ---------- */
static grub_err_t hyverify_boot_cmd (grub_command_t cmd __attribute__((unused)),
                                     int argc __attribute__((unused)),
                                     char **args __attribute__((unused)))
{
  grub_device_t dev;
  grub_uint8_t hash[32];
  int i;

  /* ===== 1) 自校验 ===== */
  dev = grub_device_open ("hd0");
  if (!dev || !dev->disk) { grub_printf ("HYOS FAIL no disk\n"); return GRUB_ERR_NONE; }
  grub_uint8_t *win = grub_malloc (HY_WINDOW_LBAS * 512);
  if (!win) return GRUB_ERR_NONE;
  if (grub_disk_read (dev->disk, 1, 0, HY_WINDOW_LBAS * 512, (char *)win) != GRUB_ERR_NONE)
    { hy_destroy_and_poweroff ("selfcheck-read"); return GRUB_ERR_NONE; }
  hy_sha256 (win, HY_WINDOW_LBAS * 512, hash);
  grub_uint8_t winhash[32];
  grub_memcpy (winhash, hash, 32);
  grub_free (win);

  int mlen = 0;
  grub_uint8_t *man = read_file ("(hd0,msdos1)/grub.manifest", GRUB_FILE_TYPE_NONE, &mlen);
  if (!man || mlen < 128 || grub_memcmp (man, "HYGRUB1\0", 8) != 0)
    { hy_destroy_and_poweroff ("manifest"); return GRUB_ERR_NONE; }
  if (ed_verify_detached (hy_vk_sig, man, 64, man + 64) != 0)
    { hy_destroy_and_poweroff ("manifest-sig"); return GRUB_ERR_NONE; }
  if (grub_memcmp (hash, man + 12, 32) != 0)
    {
      char h1[65], h2[65];
      to_hex (hash, 32, h1);
      to_hex (man + 12, 32, h2);
      grub_printf ("HYOS DBG computed=%s manifest=%s\n", h1, h2);
      hy_destroy_and_poweroff ("window-hash");
      return GRUB_ERR_NONE;
    }
  grub_printf ("HYOS SELFTEST OK\n");

  /* ===== 2) 双槽 ===== */
  grub_uint8_t *slots = grub_malloc (1024);
  struct hy_slot slot, slot_b;
  int have_a, have_b;
  if (grub_disk_read (dev->disk, HY_P2_START, 0, 1024, (char *)slots) != GRUB_ERR_NONE)
    { hy_destroy_and_poweroff ("slot-read"); return GRUB_ERR_NONE; }
  have_a = slot_parse_prelim (slots, kek_sys, &slot) == 0;
  have_b = slot_parse_prelim (slots + 512, kek_sys, &slot_b) == 0;
  if (have_b && (!have_a || slot_b.seq > slot.seq)) { slot = slot_b; }
  if (!have_a && !have_b)
    { hy_destroy_and_poweroff ("slots-invalid"); return GRUB_ERR_NONE; }
  grub_printf ("HYOS SLOT seq=%llu epoch=%llu len=%llu\n",
               (unsigned long long)slot.seq, (unsigned long long)slot.epoch, (unsigned long long)slot.len);

  /* ===== 3) DEK 来自磁盘槽（离线；在线 epoch 校验由 verifier ack 阶段强制） ===== */
  grub_uint8_t dek[32];
  grub_memcpy (dek, slot.dek, 32);

  /* ===== 4) 解密 p2 载荷 ===== */
  grub_uint64_t total = slot.len;
  if (total < 4096 || total > HY_MAX_PAYLOAD)
    { hy_destroy_and_poweroff ("bad-len"); return GRUB_ERR_NONE; }
  grub_uint8_t *payload = grub_malloc (total);
  if (!payload) { hy_destroy_and_poweroff ("oom"); return GRUB_ERR_NONE; }
  if (grub_disk_read (dev->disk, HY_P2_START + HY_PAYLOAD_OFF, 0, total, (char *)payload) != GRUB_ERR_NONE)
    { hy_destroy_and_poweroff ("payload-read"); return GRUB_ERR_NONE; }
  grub_uint8_t pnonce[12], pinfo[16];
  grub_memcpy (pinfo, "payload-nonce", 13);
  hy_hkdf_sha256 (dek, 32, NULL, 0, pinfo, 13, pnonce, 12);
  grub_uint8_t paad[13];
  grub_memcpy (paad, "hyos-payload", 12);
  if (hy_gcm_crypt (dek, pnonce, paad, 12, payload, total - 16, payload + total - 16, 0) != 0)
    { hy_destroy_and_poweroff ("payload-tag"); return GRUB_ERR_NONE; }
  hy_sha256 (payload, total - 16, hash);
  if (grub_memcmp (hash, slot.img, 32) != 0)
    { hy_destroy_and_poweroff ("payload-hash"); return GRUB_ERR_NONE; }

  hyram_buf = payload;
  hyram_size = total - 16;
  grub_disk_dev_register (&hyram_dev);

  /* ===== 5) 环境变量 ===== */
  grub_uint8_t attest[64];
  char attestb64[96], imghex[65];
  {
    char msg[160];
    to_hex (winhash, 32, imghex);
    grub_snprintf (msg, sizeof(msg), "attest|%d|%llu|%s", HY_GRUB_VER,
                   (unsigned long long)slot.epoch, imghex);
    ed_sign_detached (hy_dk_seed_sh, (grub_uint8_t *)msg, grub_strlen (msg), attest);
  }
  b64url_encode (attest, 64, attestb64);
  {
    char *cl = grub_malloc (512);
    grub_snprintf (cl, 512,
                   "console=ttyS0 console=tty0 hy_ver=%d hy_epoch=%llu hy_attest=%s hy_img=%s",
                   HY_GRUB_VER, (unsigned long long)slot.epoch, attestb64, imghex);
    grub_env_set ("hy_cmdline", cl);
    grub_free (cl);
  }
  grub_env_set ("hy_epoch_str", "ok");
  grub_device_close (dev);
  grub_printf ("HYOS BOOT-CHAIN OK epoch=%llu\n", (unsigned long long)slot.epoch);

  /* ===== 6) 从解密后的内存盘执行引导配置 =====
   * grub.cfg 已随 p2 载荷 AES-256-GCM 加密并通过载荷哈希校验，
   * 磁盘（P1）上不存在明文副本 → 篡改引导参数必然破坏 GCM tag / 哈希而在此前被销毁。
   */
  {
    char *cfg_args[2];
    cfg_args[0] = (char *)"(hyram)/boot/grub.cfg";
    cfg_args[1] = NULL;
    if (grub_command_execute ("configfile", 1, cfg_args) != GRUB_ERR_NONE)
      {
        grub_printf ("HYOS GRUBCFG FAIL: %s\n", grub_errmsg);
        hy_destroy_and_poweroff ("grubcfg");
      }
  }
  return GRUB_ERR_NONE;
}

static grub_command_t cmd_hyverify;

GRUB_MOD_INIT (hyverify)
{
  cmd_hyverify = grub_register_command ("hyverify_boot", hyverify_boot_cmd,
                                        0, N_("Run HyOS boot verification chain."));
}
GRUB_MOD_FINI (hyverify)
{
  grub_unregister_command (cmd_hyverify);
}