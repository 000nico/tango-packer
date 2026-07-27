#ifndef CHACHA_H
#define CHACHA_H

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

typedef unsigned char      u8;
typedef unsigned int       u32;
typedef unsigned long long u64;

void chacha20_decrypt(u8 *data, u64 data_len, u32 key[2][4], u32 nonce[3], u32 initial_counter);

#endif