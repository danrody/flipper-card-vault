/* AES-256 on the STM32WB AES1 peripheral.
 *
 * The HAL only offers CBC for raw keys and costs a full enable/disable cycle
 * per call, which made XTS slower than the SD card. Instead we take the HAL's
 * key load (it owns the AES1 mutex and clock), then switch the engine to ECB
 * with hardware byte swapping and stream blocks through the data registers.
 * Correctness is enforced by the known-answer self-test at application start. */
#include "aes.h"
#include "secure_mem.h"

#include <furi_hal.h>
#include <furi_hal_crypto.h>

#define AES_DATATYPE_BYTE_SWAP AES_CR_DATATYPE_1
#define AES_MODE_ENCRYPT       0U
#define AES_MODE_KEY_DERIVE    AES_CR_MODE_0
#define AES_MODE_DECRYPT       AES_CR_MODE_1
#define AES_SPIN_LIMIT         10000U

static inline uint32_t load_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static inline bool aes_wait_ccf(void) {
    for(uint32_t i = 0; i < AES_SPIN_LIMIT; i++) {
        if(AES1->SR & AES_SR_CCF) {
            AES1->CR |= AES_CR_CCFC;
            return true;
        }
    }
    return false;
}

bool aes256_ecb(const uint8_t key[AES256_KEY_SIZE], uint8_t* data, size_t nblocks, bool encrypt) {
    /* key registers ignore DATATYPE: KEYR7 holds the first key bytes, big-endian */
    uint32_t hw_key[8];
    uint32_t iv[4] = {0};
    bool ok = true;

    for(size_t i = 0; i < 8; i++)
        hw_key[i] = load_be32(key + 4 * i);
    if(!furi_hal_crypto_load_key((const uint8_t*)hw_key, (const uint8_t*)iv)) {
        secure_zero(hw_key, sizeof(hw_key));
        return false;
    }
    secure_zero(hw_key, sizeof(hw_key));

    MODIFY_REG(
        AES1->CR,
        AES_CR_EN | AES_CR_CHMOD | AES_CR_DATATYPE | AES_CR_MODE,
        AES_DATATYPE_BYTE_SWAP | (encrypt ? AES_MODE_ENCRYPT : AES_MODE_KEY_DERIVE));
    if(!encrypt) {
        /* derive the decryption key schedule from the loaded key */
        AES1->CR |= AES_CR_EN;
        ok = aes_wait_ccf();
        MODIFY_REG(AES1->CR, AES_CR_MODE, AES_MODE_DECRYPT);
    }
    AES1->CR |= AES_CR_EN;

    for(size_t b = 0; b < nblocks && ok; b++) {
        uint32_t w[4];
        uint8_t* blk = data + b * AES_BLOCK_SIZE;
        memcpy(w, blk, sizeof(w));
        AES1->DINR = w[0];
        AES1->DINR = w[1];
        AES1->DINR = w[2];
        AES1->DINR = w[3];
        ok = aes_wait_ccf();
        w[0] = AES1->DOUTR;
        w[1] = AES1->DOUTR;
        w[2] = AES1->DOUTR;
        w[3] = AES1->DOUTR;
        memcpy(blk, w, sizeof(w));
    }

    furi_hal_crypto_unload_key();
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
    return furi_hal_crypto_gcm_encrypt_and_tag(key, nonce, aad, aad_len, in, out, len, tag) ==
           FuriHalCryptoGCMStateOk;
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
    return furi_hal_crypto_gcm_decrypt_and_verify(key, nonce, aad, aad_len, in, out, len, tag) ==
           FuriHalCryptoGCMStateOk;
}
