#include "selftest.h"
#include "kdf.h"
#include "xts.h"
#include "secure_mem.h"

#include <stdlib.h>

/* Expected values generated with Python hashlib / pyca cryptography (OpenSSL). */

static bool kat_sha512(void) {
    static const uint8_t expected[16] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31};
    uint8_t out[SHA512_DIGEST_SIZE];
    sha512("abc", 3, out);
    return memcmp(out, expected, sizeof(expected)) == 0;
}

static bool kat_aes(void) {
    /* FIPS-197 Appendix C.3 */
    static const uint8_t expected[16] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
    uint8_t key[32], blk[16];
    for(int i = 0; i < 32; i++)
        key[i] = (uint8_t)i;
    for(int i = 0; i < 16; i++)
        blk[i] = (uint8_t)(i * 0x11);
    if(!aes256_ecb(key, blk, 1, true) || memcmp(blk, expected, 16) != 0) return false;
    if(!aes256_ecb(key, blk, 1, false)) return false;
    for(int i = 0; i < 16; i++)
        if(blk[i] != (uint8_t)(i * 0x11)) return false;
    return true;
}

static bool kat_xts(void) {
    static const uint8_t expected_head[16] = {
        0x2b, 0x3c, 0xdc, 0xb4, 0x8f, 0xf3, 0xb5, 0x42,
        0xe3, 0x93, 0xb6, 0xef, 0x45, 0x57, 0xe3, 0x36};
    static const uint8_t expected_hash[16] = {
        0xd0, 0x86, 0xd8, 0xf3, 0xd0, 0x91, 0xe6, 0xbb,
        0x77, 0x1e, 0x3e, 0x80, 0xde, 0xd2, 0x02, 0x82};
    XtsKey key;
    uint8_t* buf = malloc(2 * XTS_SECTOR_SIZE);
    uint8_t hash[SHA512_DIGEST_SIZE];
    bool ok;

    for(int i = 0; i < 64; i++)
        ((uint8_t*)&key)[i] = (uint8_t)i;
    for(int i = 0; i < 2 * XTS_SECTOR_SIZE; i++)
        buf[i] = (uint8_t)(i * 7 + 3);

    ok = xts_crypt(&key, 0x123456789ULL, buf, 2, true);
    sha512(buf, 2 * XTS_SECTOR_SIZE, hash);
    ok = ok && memcmp(buf, expected_head, 16) == 0 && memcmp(hash, expected_hash, 16) == 0;
    ok = ok && xts_crypt(&key, 0x123456789ULL, buf, 2, false);
    for(int i = 0; ok && i < 2 * XTS_SECTOR_SIZE; i++)
        ok = buf[i] == (uint8_t)(i * 7 + 3);

    free(buf);
    secure_zero(&key, sizeof(key));
    return ok;
}

static bool kat_gcm(void) {
    static const uint8_t expected_hash[16] = {
        0x8f, 0x85, 0xc4, 0x6e, 0xa2, 0xbe, 0x42, 0xbd,
        0x05, 0xc3, 0x20, 0xd2, 0xdb, 0xb4, 0x75, 0xa6};
    static const uint8_t expected_tag[16] = {
        0x2c, 0x61, 0xd4, 0xd9, 0x8c, 0xb9, 0x77, 0xe9,
        0x28, 0x4f, 0x6f, 0xba, 0xd2, 0xf1, 0x81, 0x43};
    static const char aad[] = "CardVault-aad";
    uint8_t key[32] __attribute__((aligned(4)));
    uint8_t nonce[12] __attribute__((aligned(4)));
    uint8_t pt[64] __attribute__((aligned(4)));
    uint8_t ct[64] __attribute__((aligned(4)));
    uint8_t tag[16] __attribute__((aligned(4)));
    uint8_t hash[SHA512_DIGEST_SIZE];

    for(int i = 0; i < 32; i++)
        key[i] = (uint8_t)(100 + i);
    for(int i = 0; i < 12; i++)
        nonce[i] = (uint8_t)i;
    for(int i = 0; i < 64; i++)
        pt[i] = (uint8_t)i;

    if(!aes256_gcm_encrypt(key, nonce, (const uint8_t*)aad, 13, pt, ct, 64, tag)) return false;
    sha512(ct, sizeof(ct), hash);
    if(memcmp(hash, expected_hash, 16) != 0 || memcmp(tag, expected_tag, 16) != 0) return false;

    if(!aes256_gcm_decrypt(key, nonce, (const uint8_t*)aad, 13, ct, pt, 64, tag)) return false;
    for(int i = 0; i < 64; i++)
        if(pt[i] != (uint8_t)i) return false;

    /* tampering must be rejected */
    ct[5] ^= 1;
    return !aes256_gcm_decrypt(key, nonce, (const uint8_t*)aad, 13, ct, pt, 64, tag);
}

const char* crypto_selftest(void) {
    if(!kat_sha512()) return "SHA-512";
    if(!kat_aes()) return "AES-256";
    if(!kat_xts()) return "XTS-AES-256";
    if(!kat_gcm()) return "AES-256-GCM";
    return NULL;
}
