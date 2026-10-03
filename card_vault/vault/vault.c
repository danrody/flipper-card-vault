#include "vault.h"
#include "../crypto/secure_mem.h"

#include <furi.h>
#include <furi_hal_random.h>
#include <stdio.h>
#include <stdlib.h>

#define TAG "CardVault"

#define VAULT_MAGIC   "CVAULT01"
#define VAULT_VERSION 1

#define LABEL_PW_VERIFY "CardVault pw-verify v1"
#define LABEL_CARD_KEYS "CardVault card-keys v1"
#define LABEL_KEK       "CardVault kek v1"
#define LABEL_MK_CHECK  "CardVault mk-check v1"

#define KDF_ITER_MIN 4096U
#define KDF_ITER_MAX 2000000U

void vault_session_wipe(VaultSession* s) {
    secure_zero(s, sizeof(*s));
}

bool vault_exists(Storage* storage) {
    return storage_file_exists(storage, VAULT_HEADER_PATH) ||
           storage_file_exists(storage, VAULT_HEADER_TMP);
}

bool vault_image_exists(Storage* storage) {
    return storage_file_exists(storage, VAULT_IMAGE_PATH);
}

bool vault_recovery_exists(Storage* storage) {
    return storage_file_exists(storage, VAULT_RECOVERY_PATH);
}

/* ---------- header I/O ---------- */

static bool read_exact(Storage* storage, const char* path, void* buf, size_t len) {
    File* f = storage_file_alloc(storage);
    bool ok = storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING) &&
              storage_file_size(f) == len && storage_file_read(f, buf, len) == len;
    storage_file_close(f);
    storage_file_free(f);
    return ok;
}

static bool write_synced(Storage* storage, const char* path, const void* buf, size_t len) {
    File* f = storage_file_alloc(storage);
    bool ok = storage_file_open(f, path, FSAM_WRITE, FSOM_CREATE_ALWAYS) &&
              storage_file_write(f, buf, len) == len && storage_file_sync(f);
    storage_file_close(f);
    storage_file_free(f);
    return ok;
}

static bool header_valid(const VaultHeader* h) {
    return memcmp(h->magic, VAULT_MAGIC, sizeof(h->magic)) == 0 && h->version == VAULT_VERSION &&
           h->kdf_iterations >= KDF_ITER_MIN && h->kdf_iterations <= KDF_ITER_MAX &&
           h->volume_sectors > 0;
}

VaultStatus vault_header_load(Storage* storage, VaultHeader* hdr) {
    /* A leftover tmp file means a save was interrupted after the old header
     * was removed; it is complete (synced before the swap), so promote it. */
    if(!storage_file_exists(storage, VAULT_HEADER_PATH) &&
       storage_file_exists(storage, VAULT_HEADER_TMP)) {
        storage_common_rename(storage, VAULT_HEADER_TMP, VAULT_HEADER_PATH);
    }
    if(!storage_file_exists(storage, VAULT_HEADER_PATH)) return VaultErrNoVault;
    if(!read_exact(storage, VAULT_HEADER_PATH, hdr, sizeof(*hdr))) return VaultErrIo;
    return header_valid(hdr) ? VaultOk : VaultErrCorrupt;
}

VaultStatus vault_header_save(Storage* storage, const VaultHeader* hdr) {
    storage_simply_mkdir(storage, VAULT_DIR);
    if(!write_synced(storage, VAULT_HEADER_TMP, hdr, sizeof(*hdr))) return VaultErrIo;
    storage_common_remove(storage, VAULT_HEADER_PATH);
    if(storage_common_rename(storage, VAULT_HEADER_TMP, VAULT_HEADER_PATH) != FSE_OK)
        return VaultErrIo;
    return VaultOk;
}

/* ---------- key derivation ---------- */

uint32_t vault_calibrate_iterations(uint32_t target_ms) {
    static const uint32_t probe = 2048;
    uint8_t out[VAULT_PW_KEY_SIZE];
    uint32_t start = furi_get_tick();
    pbkdf2_hmac_sha512("calibrate", 9, "salt", 4, probe, out, sizeof(out), NULL, NULL);
    uint32_t elapsed = furi_get_tick() - start;
    secure_zero(out, sizeof(out));
    if(!elapsed) elapsed = 1;

    uint64_t iters = (uint64_t)probe * furi_ms_to_ticks(target_ms) / elapsed;
    if(iters < KDF_ITER_MIN) iters = KDF_ITER_MIN;
    if(iters > KDF_ITER_MAX) iters = KDF_ITER_MAX;
    FURI_LOG_I(TAG, "PBKDF2: %lu iter in %lu ticks -> %lu", probe, elapsed, (uint32_t)iters);
    return (uint32_t)iters;
}

static void mk_check(const XtsKey* mk, uint8_t out[VAULT_MK_CHECK_SIZE]) {
    uint8_t h[SHA512_DIGEST_SIZE];
    hmac_sha512(mk, sizeof(*mk), LABEL_MK_CHECK, strlen(LABEL_MK_CHECK), h);
    memcpy(out, h, VAULT_MK_CHECK_SIZE);
    secure_zero(h, sizeof(h));
}

static void header_init_common(VaultHeader* h, uint32_t kdf_iterations) {
    memcpy(h->magic, VAULT_MAGIC, sizeof(h->magic));
    h->version = VAULT_VERSION;
    h->kdf_iterations = kdf_iterations;
    furi_hal_random_fill_buf(h->salt, sizeof(h->salt));
    h->failed_attempts = 0;
}

void vault_session_new(VaultSession* s, uint64_t volume_sectors, uint32_t kdf_iterations) {
    vault_session_wipe(s);
    header_init_common(&s->hdr, kdf_iterations);
    s->hdr.volume_sectors = volume_sectors;
    furi_hal_random_fill_buf(s->hdr.vault_id, sizeof(s->hdr.vault_id));
    furi_hal_random_fill_buf((uint8_t*)&s->mk, sizeof(s->mk));
    mk_check(&s->mk, s->hdr.mk_check);
}

void vault_session_rekey(VaultSession* s, uint32_t kdf_iterations) {
    header_init_common(&s->hdr, kdf_iterations);
    memset(s->hdr.pw_verifier, 0, sizeof(s->hdr.pw_verifier));
    memset(s->hdr.wrap_nonce, 0, sizeof(s->hdr.wrap_nonce));
    memset(s->hdr.wrap_tag, 0, sizeof(s->hdr.wrap_tag));
    memset(s->hdr.wrapped_mk, 0, sizeof(s->hdr.wrapped_mk));
    secure_zero(s->pw_key, sizeof(s->pw_key));
    secure_zero(s->card_keys, sizeof(s->card_keys));
    secure_zero(s->card_secret, sizeof(s->card_secret));
}

/* info = label || vault_id, binding every derived key to this vault */
static void derive(
    const VaultSession* s,
    const char* label,
    const void* ikm,
    size_t ikm_len,
    uint8_t* out,
    size_t out_len) {
    uint8_t info[48];
    size_t label_len = strlen(label);
    furi_check(label_len + VAULT_ID_SIZE <= sizeof(info));
    memcpy(info, label, label_len);
    memcpy(info + label_len, s->hdr.vault_id, VAULT_ID_SIZE);
    hkdf_sha512(
        s->hdr.salt, sizeof(s->hdr.salt), ikm, ikm_len, info, label_len + VAULT_ID_SIZE, out, out_len);
}

VaultStatus vault_derive_password(
    VaultSession* s,
    const char* password,
    bool verify,
    KdfProgressCb progress,
    void* ctx) {
    if(!pbkdf2_hmac_sha512(
           password,
           strlen(password),
           s->hdr.salt,
           sizeof(s->hdr.salt),
           s->hdr.kdf_iterations,
           s->pw_key,
           sizeof(s->pw_key),
           progress,
           ctx)) {
        return VaultErrCancelled;
    }

    uint8_t verifier[sizeof(s->hdr.pw_verifier)];
    derive(s, LABEL_PW_VERIFY, s->pw_key, sizeof(s->pw_key), verifier, sizeof(verifier));
    if(verify) {
        bool match = secure_equal(verifier, s->hdr.pw_verifier, sizeof(verifier));
        secure_zero(verifier, sizeof(verifier));
        if(!match) {
            secure_zero(s->pw_key, sizeof(s->pw_key));
            return VaultErrWrongPassword;
        }
    } else {
        memcpy(s->hdr.pw_verifier, verifier, sizeof(verifier));
        secure_zero(verifier, sizeof(verifier));
    }

    derive(s, LABEL_CARD_KEYS, s->pw_key, sizeof(s->pw_key), s->card_keys, sizeof(s->card_keys));
    return VaultOk;
}

static void derive_kek(const VaultSession* s, uint8_t kek[AES256_KEY_SIZE]) {
    /* IKM = password key || card secret: both factors are required */
    uint8_t* ikm = malloc(sizeof(s->pw_key) + sizeof(s->card_secret));
    memcpy(ikm, s->pw_key, sizeof(s->pw_key));
    memcpy(ikm + sizeof(s->pw_key), s->card_secret, sizeof(s->card_secret));
    derive(s, LABEL_KEK, ikm, sizeof(s->pw_key) + sizeof(s->card_secret), kek, AES256_KEY_SIZE);
    secure_zero(ikm, sizeof(s->pw_key) + sizeof(s->card_secret));
    free(ikm);
}

#define HEADER_AAD_LEN offsetof(VaultHeader, wrap_nonce)

VaultStatus vault_wrap_mk(VaultSession* s) {
    uint8_t kek[AES256_KEY_SIZE] __attribute__((aligned(4)));
    derive_kek(s, kek);
    furi_hal_random_fill_buf(s->hdr.wrap_nonce, sizeof(s->hdr.wrap_nonce));
    bool ok = aes256_gcm_encrypt(
        kek,
        s->hdr.wrap_nonce,
        (const uint8_t*)&s->hdr,
        HEADER_AAD_LEN,
        (const uint8_t*)&s->mk,
        s->hdr.wrapped_mk,
        sizeof(s->hdr.wrapped_mk),
        s->hdr.wrap_tag);
    secure_zero(kek, sizeof(kek));
    return ok ? VaultOk : VaultErrCrypto;
}

VaultStatus vault_unwrap_mk(VaultSession* s) {
    uint8_t kek[AES256_KEY_SIZE] __attribute__((aligned(4)));
    derive_kek(s, kek);
    bool ok = aes256_gcm_decrypt(
        kek,
        s->hdr.wrap_nonce,
        (const uint8_t*)&s->hdr,
        HEADER_AAD_LEN,
        s->hdr.wrapped_mk,
        (uint8_t*)&s->mk,
        sizeof(s->mk),
        s->hdr.wrap_tag);
    secure_zero(kek, sizeof(kek));
    if(!ok) {
        secure_zero(&s->mk, sizeof(s->mk));
        return VaultErrWrongCard;
    }

    uint8_t check[VAULT_MK_CHECK_SIZE];
    mk_check(&s->mk, check);
    bool match = secure_equal(check, s->hdr.mk_check, sizeof(check));
    secure_zero(check, sizeof(check));
    if(!match) {
        secure_zero(&s->mk, sizeof(s->mk));
        return VaultErrCorrupt;
    }
    return VaultOk;
}

/* ---------- attempt counter ---------- */

VaultStatus vault_attempt_begin(Storage* storage, VaultHeader* hdr) {
    if(hdr->failed_attempts >= VAULT_MAX_ATTEMPTS) return VaultErrWiped;
    hdr->failed_attempts++;
    return vault_header_save(storage, hdr);
}

VaultStatus vault_attempt_reset(Storage* storage, VaultHeader* hdr) {
    if(!hdr->failed_attempts) return VaultOk;
    hdr->failed_attempts = 0;
    return vault_header_save(storage, hdr);
}

/* ---------- recovery key ---------- */

static void hex_encode(char* out, const uint8_t* in, size_t len) {
    static const char digits[] = "0123456789abcdef";
    for(size_t i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0xF];
    }
    out[2 * len] = '\0';
}

static int hex_nibble(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_decode(uint8_t* out, size_t len, const char* in) {
    for(size_t i = 0; i < len; i++) {
        int hi = hex_nibble(in[2 * i]);
        int lo = hi < 0 ? -1 : hex_nibble(in[2 * i + 1]);
        if(lo < 0) return false;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return true;
}

/* Finds "Name: value" and returns a pointer to value (or NULL). */
static const char* find_field(const char* text, const char* name) {
    size_t n = strlen(name);
    for(const char* line = text; line && *line;) {
        if(strncmp(line, name, n) == 0 && line[n] == ':') {
            const char* v = line + n + 1;
            while(*v == ' ')
                v++;
            return v;
        }
        line = strchr(line, '\n');
        if(line) line++;
    }
    return NULL;
}

#define RECOVERY_MAX_SIZE 1024

VaultStatus vault_recovery_write(Storage* storage, const VaultSession* s) {
    char id_hex[VAULT_ID_SIZE * 2 + 1];
    char mk_hex[VAULT_MK_SIZE * 2 + 1];
    char check_hex[VAULT_MK_CHECK_SIZE * 2 + 1];
    char* text = malloc(RECOVERY_MAX_SIZE);

    hex_encode(id_hex, s->hdr.vault_id, VAULT_ID_SIZE);
    hex_encode(mk_hex, (const uint8_t*)&s->mk, VAULT_MK_SIZE);
    hex_encode(check_hex, s->hdr.mk_check, VAULT_MK_CHECK_SIZE);

    int len = snprintf(
        text,
        RECOVERY_MAX_SIZE,
        "# Card Vault recovery key\n"
        "# This file alone + vault.img decrypts the vault. Keep it OFFLINE.\n"
        "# Never leave it on the Flipper SD card.\n"
        "Version: 1\n"
        "Vault ID: %s\n"
        "Volume sectors: %lu\n"
        "Master key: %s\n"
        "Check: %s\n",
        id_hex,
        (uint32_t)s->hdr.volume_sectors,
        mk_hex,
        check_hex);

    storage_simply_mkdir(storage, VAULT_DIR);
    bool ok = len > 0 && len < RECOVERY_MAX_SIZE &&
              write_synced(storage, VAULT_RECOVERY_PATH, text, (size_t)len);

    secure_zero(mk_hex, sizeof(mk_hex));
    secure_zero(text, RECOVERY_MAX_SIZE);
    free(text);
    return ok ? VaultOk : VaultErrIo;
}

VaultStatus vault_recovery_read(Storage* storage, VaultSession* s) {
    VaultStatus st = VaultErrBadRecovery;
    char* text = malloc(RECOVERY_MAX_SIZE + 1);
    File* f = storage_file_alloc(storage);
    size_t len = 0;

    if(storage_file_open(f, VAULT_RECOVERY_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        len = storage_file_read(f, text, RECOVERY_MAX_SIZE);
    }
    storage_file_close(f);
    storage_file_free(f);
    text[len] = '\0';

    do {
        const char* v;
        uint8_t id[VAULT_ID_SIZE], check[VAULT_MK_CHECK_SIZE], calc[VAULT_MK_CHECK_SIZE];

        if(!len) {
            st = VaultErrNoVault;
            break;
        }
        if(!(v = find_field(text, "Version")) || strncmp(v, "1", 1) != 0) break;
        if(!(v = find_field(text, "Vault ID")) || !hex_decode(id, sizeof(id), v)) break;
        if(!(v = find_field(text, "Volume sectors"))) break;
        uint64_t sectors = strtoul(v, NULL, 10);
        if(!(v = find_field(text, "Master key")) ||
           !hex_decode((uint8_t*)&s->mk, VAULT_MK_SIZE, v))
            break;
        if(!(v = find_field(text, "Check")) || !hex_decode(check, sizeof(check), v)) break;

        mk_check(&s->mk, calc);
        if(!secure_equal(calc, check, sizeof(calc))) break;

        VaultHeader existing;
        VaultStatus hs = vault_header_load(storage, &existing);
        if(hs == VaultOk) {
            /* key must belong to the vault on this SD */
            if(memcmp(existing.vault_id, id, sizeof(id)) != 0 ||
               !secure_equal(existing.mk_check, check, sizeof(check)))
                break;
            s->hdr = existing;
        } else {
            /* header lost: rebuild identity from the recovery key */
            memset(&s->hdr, 0, sizeof(s->hdr));
            memcpy(s->hdr.vault_id, id, sizeof(id));
            memcpy(s->hdr.mk_check, check, sizeof(check));
            s->hdr.volume_sectors = sectors;
        }
        st = VaultOk;
    } while(false);

    if(st != VaultOk) secure_zero(&s->mk, sizeof(s->mk));
    secure_zero(text, RECOVERY_MAX_SIZE + 1);
    free(text);
    return st;
}

/* Best effort: overwrite with random data before unlinking. SD wear levelling
 * may still keep old copies in flash, hence "never leave it on the SD". */
static void shred(Storage* storage, const char* path) {
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, path, FSAM_READ_WRITE, FSOM_OPEN_EXISTING)) {
        uint64_t size = storage_file_size(f);
        uint8_t junk[64];
        for(uint64_t off = 0; off < size; off += sizeof(junk)) {
            furi_hal_random_fill_buf(junk, sizeof(junk));
            size_t n = size - off < sizeof(junk) ? (size_t)(size - off) : sizeof(junk);
            storage_file_write(f, junk, n);
        }
        storage_file_sync(f);
    }
    storage_file_close(f);
    storage_file_free(f);
    storage_common_remove(storage, path);
}

void vault_recovery_erase(Storage* storage) {
    if(vault_recovery_exists(storage)) shred(storage, VAULT_RECOVERY_PATH);
}

void vault_wipe(Storage* storage) {
    /* destroying the wrapped key alone makes the image undecryptable
     * without the recovery key; then the image itself is removed */
    shred(storage, VAULT_HEADER_PATH);
    shred(storage, VAULT_HEADER_TMP);
    storage_common_remove(storage, VAULT_IMAGE_PATH);
    vault_recovery_erase(storage);
    FURI_LOG_W(TAG, "vault wiped");
}

const char* vault_status_text(VaultStatus st) {
    switch(st) {
    case VaultOk:
        return "OK";
    case VaultErrIo:
        return "SD card I/O error";
    case VaultErrNoVault:
        return "Vault not found";
    case VaultErrCorrupt:
        return "Vault header corrupted";
    case VaultErrWrongPassword:
        return "Wrong password";
    case VaultErrWiped:
        return "Vault destroyed";
    case VaultErrWrongCard:
        return "Wrong card";
    case VaultErrBadRecovery:
        return "Recovery key invalid\nor for another vault";
    case VaultErrNoSpace:
        return "Not enough space on SD";
    case VaultErrCrypto:
        return "Crypto engine error";
    case VaultErrCancelled:
        return "Cancelled";
    }
    return "Unknown error";
}
