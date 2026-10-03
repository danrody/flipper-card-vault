/* Host AES backend for tests: OpenSSL EVP. */
#include "../card_vault/crypto/aes.h"

#include <openssl/evp.h>
#include <string.h>

bool aes256_ecb(const uint8_t key[AES256_KEY_SIZE], uint8_t* data, size_t nblocks, bool encrypt) {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    int len = 0;
    bool ok = EVP_CipherInit_ex(c, EVP_aes_256_ecb(), NULL, key, NULL, encrypt) == 1 &&
              EVP_CIPHER_CTX_set_padding(c, 0) == 1 &&
              EVP_CipherUpdate(c, data, &len, data, (int)(nblocks * AES_BLOCK_SIZE)) == 1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

static bool gcm(
    const uint8_t* key,
    const uint8_t* nonce,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* in,
    uint8_t* out,
    size_t len,
    uint8_t* tag,
    bool encrypt) {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    int n = 0;
    bool ok = EVP_CipherInit_ex(c, EVP_aes_256_gcm(), NULL, key, nonce, encrypt) == 1;
    if(ok && aad_len) ok = EVP_CipherUpdate(c, NULL, &n, aad, (int)aad_len) == 1;
    if(ok) ok = EVP_CipherUpdate(c, out, &n, in, (int)len) == 1;
    if(ok && !encrypt) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
    if(ok) ok = EVP_CipherFinal_ex(c, out + n, &n) == 1;
    if(ok && encrypt) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(c);
    if(!ok) memset(out, 0, len);
    return ok;
}

bool aes256_gcm_encrypt(
    const uint8_t key[AES256_KEY_SIZE],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* in,
    uint8_t* out,
    size_t len,
    uint8_t tag[16]) {
    return gcm(key, nonce, aad, aad_len, in, out, len, tag, true);
}

bool aes256_gcm_decrypt(
    const uint8_t key[AES256_KEY_SIZE],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* in,
    uint8_t* out,
    size_t len,
    const uint8_t tag[16]) {
    uint8_t t[16];
    memcpy(t, tag, 16);
    return gcm(key, nonce, aad, aad_len, in, out, len, t, false);
}
