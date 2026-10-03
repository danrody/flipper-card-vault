#pragma once

#include <stddef.h>
#include <stdint.h>

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128

typedef struct {
    uint64_t state[8];
    uint64_t total; /* bytes processed; 2^64 bytes is far beyond any input here */
    uint8_t buf[SHA512_BLOCK_SIZE];
    size_t buf_len;
} Sha512Ctx;

void sha512_init(Sha512Ctx* ctx);
void sha512_update(Sha512Ctx* ctx, const void* data, size_t len);
void sha512_final(Sha512Ctx* ctx, uint8_t out[SHA512_DIGEST_SIZE]);
void sha512(const void* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]);
