/* HyOS 自包含 SHA-256/HMAC-SHA256/HKDF（GRUB 模块内用，无外部依赖） */
#ifndef HYSHA_H
#define HYSHA_H
#include <grub/types.h>

void hy_sha256(const grub_uint8_t *data, grub_uint32_t len, grub_uint8_t out[32]);
void hy_hmac_sha256(const grub_uint8_t *key, grub_uint32_t keylen,
                    const grub_uint8_t *data, grub_uint32_t len, grub_uint8_t out[32]);
/* HKDF-SHA256: salt 可为空（saltlen==0 表示 RFC 空盐） */
int hy_hkdf_sha256(const grub_uint8_t *ikm, grub_uint32_t ikmlen,
                   const grub_uint8_t *salt, grub_uint32_t saltlen,
                   const grub_uint8_t *info, grub_uint32_t infolen,
                   grub_uint8_t *okm, grub_uint32_t okmlen);
#endif
