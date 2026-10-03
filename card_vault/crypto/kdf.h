#pragma once

#include "sha512.h"

#include <stdbool.h>

/* HMAC-SHA-512 with precomputed inner/outer states, so each extra message
 * costs only the message blocks (PBKDF2 relies on this). */
typedef struct {
    Sha512Ctx inner;
    Sha512Ctx outer;
} HmacSha512Ctx;

void hmac_sha512_init(HmacSha512Ctx* ctx, const void* key, size_t key_len);
void hmac_sha512_update(HmacSha512Ctx* ctx, const void* data, size_t len);
void hmac_sha512_final(HmacSha512Ctx* ctx, uint8_t out[SHA512_DIGEST_SIZE]);
void hmac_sha512(
    const void* key,
    size_t key_len,
    const void* data,
    size_t len,
    uint8_t out[SHA512_DIGEST_SIZE]);

/* Called every `progress_step` iterations; return false to abort. */
typedef bool (*KdfProgressCb)(uint32_t done, uint32_t total, void* ctx);

/* PBKDF2-HMAC-SHA-512, RFC 8018. Returns false only when aborted. */
bool pbkdf2_hmac_sha512(
    const void* password,
    size_t password_len,
    const void* salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t* out,
    size_t out_len,
    KdfProgressCb progress,
    void* progress_ctx);

/* HKDF-SHA-512, RFC 5869. out_len <= 255 * 64. */
void hkdf_sha512(
    const void* salt,
    size_t salt_len,
    const void* ikm,
    size_t ikm_len,
    const void* info,
    size_t info_len,
    uint8_t* out,
    size_t out_len);
