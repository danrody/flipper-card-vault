/* Host harness: prints primitive outputs for fixed inputs (verified by
 * run_host_tests.py against Python reference implementations) and produces
 * an encrypted FAT32 image for end-to-end checks. */
#include "../card_vault/crypto/kdf.h"
#include "../card_vault/crypto/xts.h"
#include "../card_vault/vault/fat32.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void hex(const char* name, const uint8_t* p, size_t n) {
    printf("%s=", name);
    for(size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void test_kdf(void) {
    uint8_t out[256];
    uint8_t big[1000];
    memset(big, 'a', sizeof(big));

    sha512("abc", 3, out);
    hex("sha512_abc", out, 64);
    sha512("", 0, out);
    hex("sha512_empty", out, 64);

    /* chunked updates across block boundaries */
    Sha512Ctx c;
    sha512_init(&c);
    for(size_t off = 0; off < sizeof(big);) {
        size_t n = (off * 7 + 13) % 150 + 1;
        if(n > sizeof(big) - off) n = sizeof(big) - off;
        sha512_update(&c, big + off, n);
        off += n;
    }
    sha512_final(&c, out);
    hex("sha512_1000a", out, 64);

    for(size_t len = 110; len <= 113; len++) {
        char name[32];
        sha512(big, len, out);
        snprintf(name, sizeof(name), "sha512_a%zu", len);
        hex(name, out, 64);
    }

    hmac_sha512("key", 3, "The quick brown fox", 19, out);
    hex("hmac_short", out, 64);
    hmac_sha512(big, 200, "msg", 3, out);
    hex("hmac_longkey", out, 64);

    pbkdf2_hmac_sha512("password", 8, "saltsalt", 8, 1000, out, 100, NULL, NULL);
    hex("pbkdf2", out, 100);

    hkdf_sha512("salt", 4, "ikm-material", 12, "info", 4, out, 200);
    hex("hkdf", out, 200);
    hkdf_sha512(NULL, 0, "ikm", 3, "", 0, out, 32);
    hex("hkdf_nosalt", out, 32);
}

static XtsKey test_key(void) {
    XtsKey k;
    for(int i = 0; i < 32; i++) {
        k.data_key[i] = (uint8_t)(i * 3 + 1);
        k.tweak_key[i] = (uint8_t)(0xA0 ^ (i * 5));
    }
    return k;
}

static int test_xts(const char* path) {
    XtsKey k = test_key();
    size_t n = 70; /* crosses the internal batch boundary */
    uint8_t* buf = malloc(n * XTS_SECTOR_SIZE);
    for(size_t i = 0; i < n * XTS_SECTOR_SIZE; i++)
        buf[i] = (uint8_t)(i * 31 + 7);
    if(!xts_crypt(&k, 1000, buf, n, true)) return 1;
    FILE* f = fopen(path, "wb");
    fwrite(buf, XTS_SECTOR_SIZE, n, f);
    fclose(f);
    /* round trip */
    if(!xts_crypt(&k, 1000, buf, n, false)) return 1;
    for(size_t i = 0; i < n * XTS_SECTOR_SIZE; i++)
        if(buf[i] != (uint8_t)(i * 31 + 7)) return 2;
    free(buf);
    return 0;
}

typedef struct {
    FILE* f;
    XtsKey key;
} ImgCtx;

static bool img_write(void* ctx, uint32_t sector, uint8_t* buf, uint32_t count) {
    ImgCtx* c = ctx;
    if(!xts_crypt(&c->key, sector, buf, count, true)) return false;
    fseek(c->f, (long)sector * 512, SEEK_SET);
    return fwrite(buf, 512, count, c->f) == count;
}

static int test_fat(const char* path, uint32_t sectors) {
    ImgCtx c = {.key = test_key()};
    c.f = fopen(path, "wb+");
    /* fill with junk to mimic uninitialised SD space */
    uint8_t junk[512];
    for(uint32_t s = 0; s < sectors; s++) {
        for(int i = 0; i < 512; i++)
            junk[i] = (uint8_t)rand();
        fwrite(junk, 1, 512, c.f);
    }
    bool ok = fat32_format(sectors, "CARDVAULT", 0x12345678, img_write, &c);
    fclose(c.f);
    return ok ? 0 : 1;
}

int main(int argc, char** argv) {
    if(argc >= 2 && !strcmp(argv[1], "kdf")) {
        test_kdf();
        return 0;
    }
    if(argc >= 3 && !strcmp(argv[1], "xts")) return test_xts(argv[2]);
    if(argc >= 4 && !strcmp(argv[1], "fat")) return test_fat(argv[2], (uint32_t)atol(argv[3]));
    fprintf(stderr, "usage: host_test kdf | xts <out> | fat <out> <sectors>\n");
    return 64;
}
