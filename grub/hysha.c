/* SHA-256 (FIPS 180-4) + HMAC + HKDF —— 自包含实现，供 hyverify 模块使用 */
#include <grub/misc.h>
#include <grub/mm.h>
#include "hysha.h"

static const grub_uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_compress(grub_uint32_t st[8], const grub_uint8_t blk[64])
{
  grub_uint32_t w[64], v[8], t1, t2;
  int i;
  for (i = 0; i < 16; i++)
    w[i] = ((grub_uint32_t)blk[i*4]<<24) | ((grub_uint32_t)blk[i*4+1]<<16) |
           ((grub_uint32_t)blk[i*4+2]<<8) | (grub_uint32_t)blk[i*4+3];
  for (i = 16; i < 64; i++) {
    grub_uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3);
    grub_uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  for (i = 0; i < 8; i++) v[i] = st[i];
  for (i = 0; i < 64; i++) {
    grub_uint32_t S1 = ROR(v[4],6) ^ ROR(v[4],11) ^ ROR(v[4],25);
    grub_uint32_t ch = (v[4] & v[5]) ^ ((~v[4]) & v[6]);
    t1 = v[7] + S1 + ch + K[i] + w[i];
    grub_uint32_t S0 = ROR(v[0],2) ^ ROR(v[0],13) ^ ROR(v[0],22);
    grub_uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
    t2 = S0 + maj;
    v[7]=v[6]; v[6]=v[5]; v[5]=v[4]; v[4]=v[3]+t1;
    v[3]=v[2]; v[2]=v[1]; v[1]=v[0]; v[0]=t1+t2;
  }
  for (i = 0; i < 8; i++) st[i] += v[i];
}

void hy_sha256(const grub_uint8_t *data, grub_uint32_t len, grub_uint8_t out[32])
{
  grub_uint32_t st[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                         0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  grub_uint8_t tail[128];
  grub_uint32_t i = 0, full = len / 64;
  grub_uint64_t bits = (grub_uint64_t)len * 8;
  grub_uint32_t t;
  for (i = 0; i < full; i++) sha256_compress(st, data + i*64);
  t = len - full*64;
  grub_memset(tail, 0, sizeof(tail));
  grub_memcpy(tail, data + full*64, t);
  tail[t] = 0x80;
  if (t + 9 > 64) sha256_compress(st, tail);
  grub_uint32_t off = (t + 9 > 64) ? 64 : 0;
  for (i = 0; i < 8; i++) tail[off + 56 + i] = (grub_uint8_t)(bits >> (56 - i*8));
  sha256_compress(st, tail + off);
  for (i = 0; i < 8; i++) {
    out[i*4]   = (grub_uint8_t)(st[i] >> 24);
    out[i*4+1] = (grub_uint8_t)(st[i] >> 16);
    out[i*4+2] = (grub_uint8_t)(st[i] >> 8);
    out[i*4+3] = (grub_uint8_t)(st[i]);
  }
}

void hy_hmac_sha256(const grub_uint8_t *key, grub_uint32_t keylen,
                    const grub_uint8_t *data, grub_uint32_t len, grub_uint8_t out[32])
{
  grub_uint8_t k[64], ipad[64], opad[64], kh[32];
  grub_uint32_t i;
  grub_memset(k, 0, 64);
  if (keylen > 64) { hy_sha256(key, keylen, kh); grub_memcpy(k, kh, 32); }
  else grub_memcpy(k, key, keylen);
  for (i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
  grub_uint8_t inner[32];
  /* 拼接受限：两段式（data <= 4GB，逐次压缩不可行 → 用一次性缓冲 32+data）
     模块内 data 最大为 512B 头，直接栈/堆缓冲 */
  grub_uint8_t *tmp = grub_malloc(64 + len);
  grub_memcpy(tmp, ipad, 64);
  grub_memcpy(tmp + 64, data, len);
  hy_sha256(tmp, 64 + len, inner);
  grub_free(tmp);
  grub_uint8_t tmp2[96];
  grub_memcpy(tmp2, opad, 64);
  grub_memcpy(tmp2 + 64, inner, 32);
  hy_sha256(tmp2, 96, out);
}

int hy_hkdf_sha256(const grub_uint8_t *ikm, grub_uint32_t ikmlen,
                   const grub_uint8_t *salt, grub_uint32_t saltlen,
                   const grub_uint8_t *info, grub_uint32_t infolen,
                   grub_uint8_t *okm, grub_uint32_t okmlen)
{
  static const grub_uint8_t empty = 0;
  /* RFC5869: saltlen==0 -> zsalt (32B zero) 由下方三目选取 */ /* HMAC(salt=1B 0x00)? 不对——RFC 空盐=全零 32B 块 */
  /* RFC5869: 空盐 == 0x00 重复 HashLen（32B） */
  grub_uint8_t zsalt[32];
  grub_memset(zsalt, 0, 32);
  grub_uint8_t prk[32];
  hy_hmac_sha256(saltlen ? (grub_uint8_t *)salt : zsalt, saltlen ? saltlen : 32,
                 ikm, ikmlen, prk);
  grub_uint8_t t[32];
  grub_uint32_t n = (okmlen + 31) / 32, i;
  grub_uint32_t done = 0;
  for (i = 1; i <= n; i++) {
    grub_uint8_t *tmp = grub_malloc(32 + infolen + 1);
    grub_memcpy(tmp, t, i == 1 ? 0 : 32);
    grub_memcpy(tmp + (i == 1 ? 0 : 32), info, infolen);
    tmp[(i == 1 ? 0 : 32) + infolen] = (grub_uint8_t)i;
    hy_hmac_sha256(prk, 32, tmp, (i == 1 ? 0 : 32) + infolen + 1, t);
    grub_free(tmp);
    grub_uint32_t cp = okmlen - done; if (cp > 32) cp = 32;
    grub_memcpy(okm + done, t, cp);
    done += cp;
  }
  grub_memset(prk, 0, 32); grub_memset(t, 0, 32);
  return 0;
}