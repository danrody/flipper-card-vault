/* SHA-512, FIPS 180-4. */
#include "sha512.h"
#include "secure_mem.h"

#include <string.h>

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x)        (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S1(x)        (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define s0(x)        (ROTR(x, 1) ^ ROTR(x, 8) ^ ((x) >> 7))
#define s1(x)        (ROTR(x, 19) ^ ROTR(x, 61) ^ ((x) >> 6))

static inline uint64_t load_be64(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static inline void store_be64(uint8_t* p, uint64_t v) {
    for(int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static void sha512_compress(uint64_t state[8], const uint8_t block[SHA512_BLOCK_SIZE]) {
    /* 16-word rolling message schedule keeps the stack footprint at 128 bytes */
    uint64_t w[16];
    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    for(int i = 0; i < 80; i++) {
        uint64_t wi;
        if(i < 16) {
            wi = w[i] = load_be64(block + 8 * i);
        } else {
            wi = w[i & 15] += s1(w[(i - 2) & 15]) + w[(i - 7) & 15] + s0(w[(i - 15) & 15]);
        }
        uint64_t t1 = h + S1(e) + CH(e, f, g) + K[i] + wi;
        uint64_t t2 = S0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
    secure_zero(w, sizeof(w));
}

void sha512_init(Sha512Ctx* ctx) {
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL,
        0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL,
    };
    memcpy(ctx->state, iv, sizeof(iv));
    ctx->total = 0;
    ctx->buf_len = 0;
}

void sha512_update(Sha512Ctx* ctx, const void* data, size_t len) {
    const uint8_t* p = data;
    ctx->total += len;

    if(ctx->buf_len) {
        size_t take = SHA512_BLOCK_SIZE - ctx->buf_len;
        if(take > len) take = len;
        memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len += take;
        p += take;
        len -= take;
        if(ctx->buf_len < SHA512_BLOCK_SIZE) return;
        sha512_compress(ctx->state, ctx->buf);
        ctx->buf_len = 0;
    }
    for(; len >= SHA512_BLOCK_SIZE; p += SHA512_BLOCK_SIZE, len -= SHA512_BLOCK_SIZE) {
        sha512_compress(ctx->state, p);
    }
    if(len) {
        memcpy(ctx->buf, p, len);
        ctx->buf_len = len;
    }
}

void sha512_final(Sha512Ctx* ctx, uint8_t out[SHA512_DIGEST_SIZE]) {
    uint64_t bits = ctx->total << 3;
    size_t n = ctx->buf_len;

    ctx->buf[n++] = 0x80;
    if(n > SHA512_BLOCK_SIZE - 16) {
        memset(ctx->buf + n, 0, SHA512_BLOCK_SIZE - n);
        sha512_compress(ctx->state, ctx->buf);
        n = 0;
    }
    memset(ctx->buf + n, 0, SHA512_BLOCK_SIZE - 8 - n);
    /* upper 64 bits of the 128-bit length are always zero for our inputs */
    store_be64(ctx->buf + SHA512_BLOCK_SIZE - 8, bits);
    sha512_compress(ctx->state, ctx->buf);

    for(int i = 0; i < 8; i++) {
        store_be64(out + 8 * i, ctx->state[i]);
    }
    secure_zero(ctx, sizeof(*ctx));
}

void sha512(const void* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]) {
    Sha512Ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, out);
}
