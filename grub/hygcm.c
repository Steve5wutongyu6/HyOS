/* AES-256-GCM：NIST SP 800-38D，CTR + GHASH，块加密用 tiny-AES（AES256=1） */
#include <grub/types.h>
#include <grub/misc.h>
#include "hygcm.h"
#include "aes.h"

/* GF(2^128) 乘法：X = X * H（msb-first 逐位法） */
static void ghash_mul(grub_uint8_t X[16], const grub_uint8_t H[16])
{
  grub_uint8_t Z[16], V[16];
  int i, j;
  grub_memset(Z, 0, 16);
  grub_memcpy(V, H, 16);
  for (i = 0; i < 128; i++) {
    grub_uint8_t bit = (X[i / 8] >> (7 - (i % 8))) & 1;
    if (bit) for (j = 0; j < 16; j++) Z[j] ^= V[j];
    int lsb = V[15] & 1;
    for (j = 15; j > 0; j--) V[j] = (V[j] >> 1) | (V[j - 1] << 7);
    V[0] >>= 1;
    if (lsb) V[0] ^= 0xE1; /* R = 0xE1 || 0x00... */
  }
  grub_memcpy(X, Z, 16);
}

static void ghash_update(grub_uint8_t Y[16], const grub_uint8_t H[16],
                         const grub_uint8_t *data, grub_uint32_t len)
{
  grub_uint8_t blk[16];
  grub_uint32_t off = 0;
  while (off < len) {
    grub_uint32_t n = len - off;
    if (n > 16) n = 16;
    grub_memset(blk, 0, 16);
    grub_memcpy(blk, data + off, n);
    int i;
    for (i = 0; i < 16; i++) Y[i] ^= blk[i];
    ghash_mul(Y, H);
    off += n;
  }
}

int hy_gcm_crypt(const grub_uint8_t key[32], const grub_uint8_t iv[12],
                 const grub_uint8_t *aad, grub_uint32_t aadlen,
                 grub_uint8_t *inout, grub_uint32_t len,
                 grub_uint8_t tag[16], int encrypt)
{
  struct AES_ctx ctx;
  grub_uint8_t H[16], J0[16], cb[16], Y[16], S[16], EJ0[16], lenblk[16];
  grub_uint32_t i, counter = 2, off = 0;

  AES_init_ctx(&ctx, key);
  grub_memset(H, 0, 16);
  AES_ECB_encrypt(&ctx, H);            /* H = AES(K, 0^128) */

  grub_memcpy(J0, iv, 12);
  J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;   /* J0 = IV || 0^32 || 1 */

  grub_memset(Y, 0, 16);
  if (aadlen) ghash_update(Y, H, aad, aadlen);
  /* GCM: GHASH 必须作用于密文 —— 解密方向在 CTR 之前取输入密文 */
  if (!encrypt) ghash_update(Y, H, inout, len);

  /* CTR：counter 从 2 开始（J0 留给 tag 的 GCTR） */
  while (off < len) {
    grub_memcpy(cb, J0, 16);
    cb[15] = (grub_uint8_t)counter;
    cb[14] = (grub_uint8_t)(counter >> 8);
    cb[13] = (grub_uint8_t)(counter >> 16);
    cb[12] = (grub_uint8_t)(counter >> 24);
    AES_ECB_encrypt(&ctx, cb);
    grub_uint32_t n = len - off;
    if (n > 16) n = 16;
    for (i = 0; i < n; i++) inout[off + i] ^= cb[i];
    off += n;
    counter++;
  }
  /* 加密方向：CTR 后 inout 即密文 */
  if (encrypt) ghash_update(Y, H, inout, len);

  grub_memset(lenblk, 0, 16);
  grub_uint32_t aadbits = aadlen * 8, dbits = len * 8;
  lenblk[4]  = (grub_uint8_t)(aadbits >> 24); lenblk[5]  = (grub_uint8_t)(aadbits >> 16);
  lenblk[6]  = (grub_uint8_t)(aadbits >> 8);  lenblk[7]  = (grub_uint8_t)aadbits;
  lenblk[12] = (grub_uint8_t)(dbits >> 24);   lenblk[13] = (grub_uint8_t)(dbits >> 16);
  lenblk[14] = (grub_uint8_t)(dbits >> 8);    lenblk[15] = (grub_uint8_t)dbits;
  for (i = 0; i < 16; i++) Y[i] ^= lenblk[i];
  ghash_mul(Y, H);

  grub_memcpy(EJ0, J0, 16);
  AES_ECB_encrypt(&ctx, EJ0);
  for (i = 0; i < 16; i++) S[i] = Y[i] ^ EJ0[i];

  if (encrypt) { grub_memcpy(tag, S, 16); return 0; }
  grub_uint8_t diff = 0;
  for (i = 0; i < 16; i++) diff |= tag[i] ^ S[i];
  return diff ? -1 : 0;
}
