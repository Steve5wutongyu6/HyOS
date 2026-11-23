/* AES-256-GCM（CTR+GHASH over tiny-AES ECB）*/
#ifndef HYGCM_H
#define HYGCM_H
#include <grub/types.h>

/* 密钥 32B；iv 12B；aad 可空；in/out 允许同一缓冲（就地解密）；tag 16B */
int hy_gcm_crypt(const grub_uint8_t key[32], const grub_uint8_t iv[12],
                 const grub_uint8_t *aad, grub_uint32_t aadlen,
                 grub_uint8_t *inout, grub_uint32_t len,
                 grub_uint8_t tag[16], int encrypt /* 1=enc 0=dec, tag 校验 */);
#endif
