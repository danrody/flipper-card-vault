#include "kdf.h"
#include "secure_mem.h"

#include <string.h>

void hmac_sha512_init(HmacSha512Ctx* ctx, const void* key, size_t key_len) {
    uint8_t pad[SHA512_BLOCK_SIZE];
    uint8_t key_hash[SHA512_DIGEST_SIZE];

    if(key_len > SHA512_BLOCK_SIZE) {
        sha512(key, key_len, key_hash);
        key = key_hash;
        key_len = sizeof(key_hash);
    }

    memset(pad, 0x36, sizeof(pad));
    for(size_t i = 0; i < key_len; i++)
        pad[i] ^= ((const uint8_t*)key)[i];
    sha512_init(&ctx->inner);
    sha512_update(&ctx->inner, pad, sizeof(pad));

    memset(pad, 0x5c, sizeof(pad));
    for(size_t i = 0; i < key_len; i++)
        pad[i] ^= ((const uint8_t*)key)[i];
    sha512_init(&ctx->outer);
    sha512_update(&ctx->outer, pad, sizeof(pad));

    secure_zero(pad, sizeof(pad));
    secure_zero(key_hash, sizeof(key_hash));
}

void hmac_sha512_update(HmacSha512Ctx* ctx, const void* data, size_t len) {
    sha512_update(&ctx->inner, data, len);
}

void hmac_sha512_final(HmacSha512Ctx* ctx, uint8_t out[SHA512_DIGEST_SIZE]) {
    uint8_t inner_hash[SHA512_DIGEST_SIZE];
    sha512_final(&ctx->inner, inner_hash);
    sha512_update(&ctx->outer, inner_hash, sizeof(inner_hash));
    sha512_final(&ctx->outer, out);
    secure_zero(inner_hash, sizeof(inner_hash));
}

void hmac_sha512(
    const void* key,
    size_t key_len,
    const void* data,
    size_t len,
    uint8_t out[SHA512_DIGEST_SIZE]) {
    HmacSha512Ctx ctx;
    hmac_sha512_init(&ctx, key, key_len);
    hmac_sha512_update(&ctx, data, len);
    hmac_sha512_final(&ctx, out);
    secure_zero(&ctx, sizeof(ctx));
}

bool pbkdf2_hmac_sha512(
    const void* password,
    size_t password_len,
    const void* salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t* out,
    size_t out_len,
    KdfProgressCb progress,
    void* progress_ctx) {
    HmacSha512Ctx base, ctx;
    uint8_t u[SHA512_DIGEST_SIZE];
    uint8_t t[SHA512_DIGEST_SIZE];
    bool ok = true;

    hmac_sha512_init(&base, password, password_len);

    uint32_t blocks = (uint32_t)((out_len + SHA512_DIGEST_SIZE - 1) / SHA512_DIGEST_SIZE);
    uint32_t total = blocks * iterations;

    for(uint32_t blk = 1; blk <= blocks && ok; blk++) {
        uint8_t be_blk[4] = {blk >> 24, blk >> 16, blk >> 8, blk};
        ctx = base;
        hmac_sha512_update(&ctx, salt, salt_len);
        hmac_sha512_update(&ctx, be_blk, sizeof(be_blk));
        hmac_sha512_final(&ctx, u);
        memcpy(t, u, sizeof(t));

        for(uint32_t i = 1; i < iterations; i++) {
            ctx = base;
            hmac_sha512_update(&ctx, u, sizeof(u));
            hmac_sha512_final(&ctx, u);
            for(size_t j = 0; j < sizeof(t); j++)
                t[j] ^= u[j];

            if(progress && (i & 0xFF) == 0) {
                if(!progress((blk - 1) * iterations + i, total, progress_ctx)) {
                    ok = false;
                    break;
                }
            }
        }

        size_t off = (size_t)(blk - 1) * SHA512_DIGEST_SIZE;
        size_t n = out_len - off < SHA512_DIGEST_SIZE ? out_len - off : SHA512_DIGEST_SIZE;
        memcpy(out + off, t, n);
    }

    secure_zero(&base, sizeof(base));
    secure_zero(&ctx, sizeof(ctx));
    secure_zero(u, sizeof(u));
    secure_zero(t, sizeof(t));
    if(!ok) secure_zero(out, out_len);
    return ok;
}

void hkdf_sha512(
    const void* salt,
    size_t salt_len,
    const void* ikm,
    size_t ikm_len,
    const void* info,
    size_t info_len,
    uint8_t* out,
    size_t out_len) {
    static const uint8_t zero_salt[SHA512_DIGEST_SIZE] = {0};
    uint8_t prk[SHA512_DIGEST_SIZE];
    uint8_t t[SHA512_DIGEST_SIZE];
    HmacSha512Ctx ctx;

    if(!salt || !salt_len) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    hmac_sha512(salt, salt_len, ikm, ikm_len, prk);

    size_t done = 0;
    for(uint8_t counter = 1; done < out_len; counter++) {
        hmac_sha512_init(&ctx, prk, sizeof(prk));
        if(counter > 1) hmac_sha512_update(&ctx, t, sizeof(t));
        hmac_sha512_update(&ctx, info, info_len);
        hmac_sha512_update(&ctx, &counter, 1);
        hmac_sha512_final(&ctx, t);

        size_t n = out_len - done < sizeof(t) ? out_len - done : sizeof(t);
        memcpy(out + done, t, n);
        done += n;
    }

    secure_zero(prk, sizeof(prk));
    secure_zero(t, sizeof(t));
    secure_zero(&ctx, sizeof(ctx));
}
