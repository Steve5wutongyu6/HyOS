#ifndef TWEETNACL_H
#define TWEETNACL_H
#include <stdint.h>
typedef unsigned char u8;
typedef unsigned long long u64;
typedef long long i64;
extern int crypto_sign(u8 *sm, u64 *smlen, const u8 *m, u64 mlen, const u8 *sk);
extern int crypto_sign_open(u8 *m, u64 *mlen, const u8 *sm, u64 smlen, const u8 *pk);
extern int crypto_sign_keypair(u8 *pk, u8 *sk);
extern int crypto_sign_seed_keypair(u8 *pk, u8 *sk, const u8 *seed);
#endif
