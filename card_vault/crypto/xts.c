#include "xts.h"
#include "secure_mem.h"

#define XTS_BLOCKS_PER_SECTOR (XTS_SECTOR_SIZE / AES_BLOCK_SIZE)
/* Sectors whose tweaks are computed per AES key load. */
#define XTS_BATCH 32

/* Multiply by the primitive element alpha in GF(2^128), little-endian convention. */
static inline void xts_mul_alpha(uint8_t t[AES_BLOCK_SIZE]) {
    uint8_t carry = t[15] >> 7;
    for(int i = 15; i > 0; i--) {
        t[i] = (uint8_t)((t[i] << 1) | (t[i - 1] >> 7));
    }
    t[0] = (uint8_t)((t[0] << 1) ^ (carry ? 0x87 : 0));
}

/* XOR every block of a sector with its tweak T_j = T_0 * alpha^j. */
static void xts_whiten(uint8_t* sector, const uint8_t t0[AES_BLOCK_SIZE]) {
    uint8_t t[AES_BLOCK_SIZE];
    memcpy(t, t0, sizeof(t));
    for(size_t j = 0; j < XTS_BLOCKS_PER_SECTOR; j++) {
        uint8_t* blk = sector + j * AES_BLOCK_SIZE;
        for(size_t k = 0; k < AES_BLOCK_SIZE; k++)
            blk[k] ^= t[k];
        xts_mul_alpha(t);
    }
    secure_zero(t, sizeof(t));
}

bool xts_crypt(const XtsKey* key, uint64_t sector, uint8_t* buf, size_t count, bool encrypt) {
    uint8_t tweaks[XTS_BATCH * AES_BLOCK_SIZE];
    bool ok = true;

    while(count && ok) {
        size_t n = count < XTS_BATCH ? count : XTS_BATCH;

        memset(tweaks, 0, n * AES_BLOCK_SIZE);
        for(size_t i = 0; i < n; i++) {
            uint64_t s = sector + i;
            for(size_t b = 0; b < 8; b++)
                tweaks[i * AES_BLOCK_SIZE + b] = (uint8_t)(s >> (8 * b));
        }
        ok = aes256_ecb(key->tweak_key, tweaks, n, true);

        if(ok) {
            for(size_t i = 0; i < n; i++)
                xts_whiten(buf + i * XTS_SECTOR_SIZE, tweaks + i * AES_BLOCK_SIZE);
            ok = aes256_ecb(key->data_key, buf, n * XTS_BLOCKS_PER_SECTOR, encrypt);
        }
        if(ok) {
            for(size_t i = 0; i < n; i++)
                xts_whiten(buf + i * XTS_SECTOR_SIZE, tweaks + i * AES_BLOCK_SIZE);
        }

        buf += n * XTS_SECTOR_SIZE;
        sector += n;
        count -= n;
    }

    secure_zero(tweaks, sizeof(tweaks));
    return ok;
}
