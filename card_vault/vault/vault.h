#pragma once

#include "../crypto/xts.h"
#include "../crypto/kdf.h"

#include <storage/storage.h>

#define VAULT_DIR           EXT_PATH("apps_data/card_vault")
#define VAULT_HEADER_PATH   VAULT_DIR "/vault.hdr"
#define VAULT_HEADER_TMP    VAULT_DIR "/vault.hdr.tmp"
#define VAULT_IMAGE_PATH    VAULT_DIR "/vault.img"
#define VAULT_RECOVERY_PATH VAULT_DIR "/recovery.key"

#define VAULT_MAX_ATTEMPTS  5
#define VAULT_SALT_SIZE     32
#define VAULT_ID_SIZE       16
#define VAULT_PW_KEY_SIZE   64
#define VAULT_MK_SIZE       ((size_t)sizeof(XtsKey))
#define VAULT_MK_CHECK_SIZE 16
#define VAULT_PW_MIN_LEN    6
#define VAULT_PW_MAX_LEN    64

/* Mifare Classic 1K: 16 sectors, 47 data blocks (block 0 is manufacturer data). */
#define CARD_SECTORS     16
#define CARD_KEYS_SIZE   (CARD_SECTORS * 12) /* key A + key B per sector */
#define CARD_SECRET_SIZE (47 * 16)

typedef enum {
    VaultOk,
    VaultErrIo,
    VaultErrNoVault,
    VaultErrCorrupt,
    VaultErrWrongPassword,
    VaultErrWiped,
    VaultErrWrongCard,
    VaultErrBadRecovery,
    VaultErrNoSpace,
    VaultErrCrypto,
    VaultErrCancelled,
} VaultStatus;

/* On-SD header. Everything up to `wrap_nonce` is authenticated as GCM AAD;
 * `failed_attempts` is deliberately outside it (it changes on every try). */
typedef struct __attribute__((packed)) {
    char magic[8];
    uint32_t version;
    uint32_t kdf_iterations;
    uint64_t volume_sectors;
    uint8_t vault_id[VAULT_ID_SIZE];
    uint8_t salt[VAULT_SALT_SIZE];
    uint8_t pw_verifier[32];
    uint8_t mk_check[VAULT_MK_CHECK_SIZE];
    uint8_t wrap_nonce[12];
    uint8_t wrap_tag[16];
    uint8_t wrapped_mk[64];
    uint8_t failed_attempts;
    uint8_t reserved[256 - 8 - 4 - 4 - 8 - 16 - 32 - 32 - 16 - 12 - 16 - 64 - 1];
} VaultHeader;

_Static_assert(sizeof(VaultHeader) == 256, "header layout");

/* All secret material of one operation; wiped with vault_session_wipe(). */
typedef struct {
    VaultHeader hdr;
    uint8_t pw_key[VAULT_PW_KEY_SIZE] __attribute__((aligned(4)));
    uint8_t card_keys[CARD_KEYS_SIZE];
    uint8_t card_secret[CARD_SECRET_SIZE];
    XtsKey mk __attribute__((aligned(4)));
} VaultSession;

void vault_session_wipe(VaultSession* s);

bool vault_exists(Storage* storage);
bool vault_image_exists(Storage* storage);
bool vault_recovery_exists(Storage* storage);

VaultStatus vault_header_load(Storage* storage, VaultHeader* hdr);
VaultStatus vault_header_save(Storage* storage, const VaultHeader* hdr);

/* Picks PBKDF2 iterations so that derivation takes ~target_ms on this device. */
uint32_t vault_calibrate_iterations(uint32_t target_ms);

/* New vault: random MK, vault id, salt; header fields filled. */
void vault_session_new(VaultSession* s, uint64_t volume_sectors, uint32_t kdf_iterations);

/* New card/password for an existing MK (restore): fresh salt, keeps vault id. */
void vault_session_rekey(VaultSession* s, uint32_t kdf_iterations);

/* PBKDF2 + derived card keys. When `verify` is set, checks the stored
 * verifier (constant time) and returns VaultErrWrongPassword on mismatch;
 * otherwise stores a new verifier into the header. */
VaultStatus vault_derive_password(
    VaultSession* s,
    const char* password,
    bool verify,
    KdfProgressCb progress,
    void* ctx);

/* Wraps s->mk under KEK(password key, card secret) into the header. */
VaultStatus vault_wrap_mk(VaultSession* s);
/* Recovers s->mk from the header; VaultErrWrongCard when the tag fails. */
VaultStatus vault_unwrap_mk(VaultSession* s);

/* Password attempt accounting (persisted before the check). */
VaultStatus vault_attempt_begin(Storage* storage, VaultHeader* hdr);
VaultStatus vault_attempt_reset(Storage* storage, VaultHeader* hdr);

/* Recovery key file: MK in plaintext, for offline storage. */
VaultStatus vault_recovery_write(Storage* storage, const VaultSession* s);
VaultStatus vault_recovery_read(Storage* storage, VaultSession* s);
void vault_recovery_erase(Storage* storage);

/* Destroys the header (overwrite + delete), the image and any recovery copy. */
void vault_wipe(Storage* storage);

const char* vault_status_text(VaultStatus st);
