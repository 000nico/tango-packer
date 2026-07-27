#include "chacha20.h"

static void my_memcpy(void *dst, const void *src, u64 len) {
    u8       *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    while (len--) *d++ = *s++;
}

static void quarter_round(u32 *a, u32 *b, u32 *c, u32 *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d,  8);
    *c += *d; *b ^= *c; *b = ROTL32(*b,  7);
}

static void qr(u32 s[4][4], int ar, int ac, int br, int bc, int cr, int cc, int dr, int dc) {
    u32 a = s[ar][ac], b = s[br][bc], c = s[cr][cc], d = s[dr][dc];
    quarter_round(&a, &b, &c, &d);
    s[ar][ac] = a; s[br][bc] = b; s[cr][cc] = c; s[dr][dc] = d;
}

static void double_round(u32 s[4][4]) {
    qr(s, 0,0, 1,0, 2,0, 3,0);
    qr(s, 0,1, 1,1, 2,1, 3,1);
    qr(s, 0,2, 1,2, 2,2, 3,2);
    qr(s, 0,3, 1,3, 2,3, 3,3);

    qr(s, 0,0, 1,1, 2,2, 3,3);
    qr(s, 0,1, 1,2, 2,3, 3,0);
    qr(s, 0,2, 1,3, 2,0, 3,1);
    qr(s, 0,3, 1,0, 2,1, 3,2);
}

static void chacha20_block(u32 key[2][4], u32 nonce[3], u32 counter, u8 keystream[64]) {
    u32 initial[4][4] = {
        { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 },
        { key[0][0],  key[0][1],  key[0][2],  key[0][3]  },
        { key[1][0],  key[1][1],  key[1][2],  key[1][3]  },
        { counter,    nonce[0],   nonce[1],   nonce[2]   },
    };

    u32 work[4][4];
    my_memcpy(work, initial, sizeof(initial));

    for (int i = 0; i < 10; i++) {
        double_round(work);
    }

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            work[i][j] += initial[i][j];

    int idx = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            keystream[idx++] =  work[i][j]        & 0xFF;
            keystream[idx++] = (work[i][j] >>  8) & 0xFF;
            keystream[idx++] = (work[i][j] >> 16) & 0xFF;
            keystream[idx++] = (work[i][j] >> 24) & 0xFF;
        }
    }
}

void chacha20_decrypt(u8 *data, u64 data_len, u32 key[2][4], u32 nonce[3], u32 initial_counter) {
    u32 counter = initial_counter;
    u8  keystream[64];
    u64 offset = 0;

    while (offset < data_len) {
        chacha20_block(key, nonce, counter, keystream);

        u64 block_size = data_len - offset;
        if (block_size > 64) block_size = 64;

        for (u64 i = 0; i < block_size; i++) {
            data[offset + i] ^= keystream[i];
        }

        offset  += 64;
        counter += 1;
    }
}