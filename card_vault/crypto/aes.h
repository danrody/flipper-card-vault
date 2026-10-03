#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE  16
#define AES256_KEY_SIZE 32

/* Raw AES-256 block transform (ECB) of `nblocks` blocks, in place.
 * Implemented by the platform: hardware AES1 on the Flipper (aes_hw.c),
 * OpenSSL in host tests. Building block for XTS only - never use ECB directly. */
bool aes256_ecb(const uint8_t key[AES256_KEY_SIZE], uint8_t* data, size_t nblocks, bool encrypt);

/* AES-256-GCM with a 12-byte nonce and 16-byte tag. */
bool aes256_gcm_encrypt(
    const uint8_t key[AES256_KEY_SIZE],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* in,
    uint8_t* out,
    size_t len,
    uint8_t tag[16]);

/* Returns false on authentication failure; `out` is wiped in that case. */
bool aes256_gcm_decrypt(
    const uint8_t key[AES256_KEY_SIZE],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* in,
    uint8_t* out,
    size_t len,
    const uint8_t tag[16]);
