#pragma once

#include "aes.h"

#define XTS_SECTOR_SIZE 512

/* XTS-AES-256 (IEEE 1619 / NIST SP 800-38E), 512-byte data units,
 * data unit number = sector index encoded little-endian in the tweak. */
typedef struct {
    uint8_t data_key[AES256_KEY_SIZE];
    uint8_t tweak_key[AES256_KEY_SIZE];
} XtsKey;

/* Encrypts/decrypts `count` consecutive sectors starting at `sector`, in place. */
bool xts_crypt(const XtsKey* key, uint64_t sector, uint8_t* buf, size_t count, bool encrypt);
