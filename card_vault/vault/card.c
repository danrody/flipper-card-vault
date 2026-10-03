#include "card.h"
#include "../crypto/secure_mem.h"

#include <furi.h>
#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>

#define TAG "CardVaultNfc"

#define RETRY_DELAY_MS 150

/* Transport-configuration access bits (FF 07 80): data blocks read/write with
 * key A|B, key A can rewrite the trailer. The card stays re-programmable by
 * whoever holds key A - which only the vault can derive. */
static const uint8_t ACCESS_BITS[4] = {0xFF, 0x07, 0x80, 0x69};
static const MfClassicKey DEFAULT_KEY = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

typedef enum {
    StepOk,
    StepRetry, /* card absent / field glitch: wait and start over */
    StepFatal,
} Step;

static inline uint8_t sector_first_data_block(uint8_t sector) {
    return sector == 0 ? 1 : sector * 4;
}

static inline uint8_t sector_trailer(uint8_t sector) {
    return sector * 4 + 3;
}

/* Offset of a data block inside the 752-byte card secret. */
static inline size_t secret_offset(uint8_t block) {
    uint8_t sector = block / 4;
    return sector == 0 ? (size_t)(block - 1) * 16 : (size_t)(2 + (sector - 1) * 3 + block % 4) * 16;
}

static void sector_key(const VaultSession* s, uint8_t sector, MfClassicKeyType type, MfClassicKey* k) {
    memcpy(k->data, s->card_keys + sector * 12 + (type == MfClassicKeyTypeA ? 0 : 6), 6);
}

static Step classify(MfClassicError err) {
    switch(err) {
    case MfClassicErrorNone:
        return StepOk;
    case MfClassicErrorAuth:
        return StepFatal;
    default:
        return StepRetry;
    }
}

/* Authenticated block read. A card stays silent after a wrong key, which the
 * stack reports as Timeout - same as "no card". Disambiguate by checking the
 * card is still in the field: present + repeated silence = wrong key. */
static Step read_step(
    Nfc* nfc,
    uint8_t block,
    const MfClassicKey* key,
    MfClassicKeyType type,
    MfClassicBlock* blk) {
    for(int attempt = 0; attempt < 2; attempt++) {
        MfClassicKey k = *key;
        MfClassicError err = mf_classic_poller_sync_read_block(nfc, block, &k, type, blk);
        if(err == MfClassicErrorNone) return StepOk;
        if(err == MfClassicErrorAuth) return StepFatal;
        if(err != MfClassicErrorTimeout) return StepRetry;
        MfClassicType card_type;
        if(mf_classic_poller_sync_detect_type(nfc, &card_type) != MfClassicErrorNone)
            return StepRetry;
    }
    return StepFatal;
}

static Step wait_card(Nfc* nfc, volatile bool* cancel, CardResult* res) {
    while(!*cancel) {
        MfClassicType type;
        MfClassicError err = mf_classic_poller_sync_detect_type(nfc, &type);
        if(err == MfClassicErrorNone) {
            if(type == MfClassicType1k || type == MfClassicType4k) return StepOk;
            *res = CardWrongType;
            return StepFatal;
        }
        furi_delay_ms(RETRY_DELAY_MS);
    }
    *res = CardCancelled;
    return StepFatal;
}

static Step provision_sector(Nfc* nfc, const VaultSession* s, uint8_t sector, CardResult* res) {
    MfClassicKey key_a, key_b, auth_key;
    MfClassicBlock blk;
    uint8_t first = sector_first_data_block(sector);
    uint8_t trailer = sector_trailer(sector);
    Step st;

    sector_key(s, sector, MfClassicKeyTypeA, &key_a);
    sector_key(s, sector, MfClassicKeyTypeB, &key_b);

    /* Which key opens the sector: default (blank) or ours (resumed write)? */
    auth_key = DEFAULT_KEY;
    st = read_step(nfc, first, &auth_key, MfClassicKeyTypeA, &blk);
    if(st == StepFatal) {
        auth_key = key_a;
        st = read_step(nfc, first, &auth_key, MfClassicKeyTypeA, &blk);
        if(st == StepFatal) {
            *res = CardNotBlank;
            return StepFatal;
        }
    }
    if(st != StepOk) return st;

    for(uint8_t b = first; b < trailer; b++) {
        const uint8_t* want = s->card_secret + secret_offset(b);
        memcpy(blk.data, want, 16);
        st = classify(mf_classic_poller_sync_write_block(nfc, b, &auth_key, MfClassicKeyTypeA, &blk));
        if(st == StepOk) {
            st = read_step(nfc, b, &auth_key, MfClassicKeyTypeA, &blk);
        }
        if(st == StepOk && memcmp(blk.data, want, 16) != 0) {
            *res = CardWriteFailed;
            st = StepFatal;
        }
        if(st != StepOk) {
            if(st == StepFatal && *res == CardOk) *res = CardWriteFailed;
            secure_zero(&blk, sizeof(blk));
            return st;
        }
    }

    if(memcmp(auth_key.data, key_a.data, 6) != 0) {
        memcpy(blk.data, key_a.data, 6);
        memcpy(blk.data + 6, ACCESS_BITS, 4);
        memcpy(blk.data + 10, key_b.data, 6);
        st = classify(
            mf_classic_poller_sync_write_block(nfc, trailer, &auth_key, MfClassicKeyTypeA, &blk));
        if(st == StepFatal) *res = CardWriteFailed;
        if(st != StepOk) {
            secure_zero(&blk, sizeof(blk));
            return st;
        }
    }

    /* Confirm the new key works before moving on. */
    st = read_step(nfc, first, &key_a, MfClassicKeyTypeA, &blk);
    if(st == StepFatal) *res = CardWriteFailed;
    secure_zero(&blk, sizeof(blk));
    secure_zero(&key_a, sizeof(key_a));
    secure_zero(&key_b, sizeof(key_b));
    return st;
}

CardResult card_provision(Nfc* nfc, const VaultSession* s, volatile bool* cancel) {
    CardResult res = CardOk;
    for(;;) {
        if(wait_card(nfc, cancel, &res) != StepOk) return res;
        Step st = StepOk;
        for(uint8_t sector = 0; sector < CARD_SECTORS && st == StepOk; sector++) {
            if(*cancel) return CardCancelled;
            st = provision_sector(nfc, s, sector, &res);
        }
        if(st == StepOk) return CardOk;
        if(st == StepFatal) return res;
        FURI_LOG_D(TAG, "card lost during write, retrying");
        furi_delay_ms(RETRY_DELAY_MS);
    }
}

CardResult card_read(Nfc* nfc, VaultSession* s, volatile bool* cancel) {
    CardResult res = CardOk;
    for(;;) {
        if(wait_card(nfc, cancel, &res) != StepOk) return res;
        Step st = StepOk;
        MfClassicKey key;
        MfClassicBlock blk;
        for(uint8_t sector = 0; sector < CARD_SECTORS && st == StepOk; sector++) {
            if(*cancel) {
                st = StepFatal;
                res = CardCancelled;
                break;
            }
            sector_key(s, sector, MfClassicKeyTypeA, &key);
            for(uint8_t b = sector_first_data_block(sector); b < sector_trailer(sector); b++) {
                st = read_step(nfc, b, &key, MfClassicKeyTypeA, &blk);
                if(st != StepOk) break;
                memcpy(s->card_secret + secret_offset(b), blk.data, 16);
            }
        }
        secure_zero(&key, sizeof(key));
        secure_zero(&blk, sizeof(blk));

        if(st == StepOk) return CardOk;
        if(st == StepFatal) {
            secure_zero(s->card_secret, sizeof(s->card_secret));
            return res == CardOk ? CardAuthFailed : res;
        }
        furi_delay_ms(RETRY_DELAY_MS);
    }
}

CardResult card_check(Nfc* nfc, VaultSession* s, CardCheck* out, volatile bool* cancel) {
    memset(out, 0, sizeof(*out));
    CardResult res = card_read(nfc, s, cancel);
    if(res != CardOk) return res;
    out->blocks_read = CARD_SECRET_SIZE / 16;

    /* block-level properties */
    for(size_t i = 0; i < CARD_SECRET_SIZE / 16; i++) {
        const uint8_t* b = s->card_secret + i * 16;
        bool zero = true, ff = true, dup = false;
        for(size_t k = 0; k < 16; k++) {
            zero &= b[k] == 0x00;
            ff &= b[k] == 0xFF;
        }
        for(size_t j = 0; j < i && !dup; j++)
            dup = memcmp(b, s->card_secret + j * 16, 16) == 0;
        if(zero || ff) out->blocks_blank++;
        if(!dup) out->blocks_unique++;
    }

    /* bit balance and byte-value coverage */
    uint32_t ones = 0;
    uint8_t seen[32] = {0};
    for(size_t i = 0; i < CARD_SECRET_SIZE; i++) {
        uint8_t v = s->card_secret[i];
        ones += __builtin_popcount(v);
        seen[v >> 3] |= 1 << (v & 7);
    }
    out->ones_permille = (uint16_t)(ones * 1000 / (CARD_SECRET_SIZE * 8));
    for(size_t i = 0; i < sizeof(seen); i++)
        out->byte_values += __builtin_popcount(seen[i]);

    /* 32 sector keys must all differ */
    for(size_t i = 0; i < CARD_SECTORS * 2; i++) {
        bool dup = false;
        for(size_t j = 0; j < i && !dup; j++)
            dup = memcmp(s->card_keys + i * 6, s->card_keys + j * 6, 6) == 0;
        if(!dup) out->keys_unique++;
    }

    /* trailers: key A reads back as zeros, access bits + key B are ours */
    MfClassicKey key;
    MfClassicBlock blk;
    for(uint8_t sector = 0; sector < CARD_SECTORS; sector++) {
        sector_key(s, sector, MfClassicKeyTypeA, &key);
        if(read_step(nfc, sector_trailer(sector), &key, MfClassicKeyTypeA, &blk) == StepOk &&
           memcmp(blk.data + 6, ACCESS_BITS, 4) == 0 &&
           memcmp(blk.data + 10, s->card_keys + sector * 12 + 6, 6) == 0) {
            out->trailers_ok++;
        }
    }

    /* factory key must be refused on every sector */
    out->default_key = 1;
    for(uint8_t sector = 0; sector < CARD_SECTORS && out->default_key == 1 && !*cancel;
        sector++) {
        Step st = read_step(nfc, sector_first_data_block(sector), &DEFAULT_KEY, MfClassicKeyTypeA, &blk);
        if(st == StepOk)
            out->default_key = 0;
        else if(st == StepRetry)
            out->default_key = -1;
    }
    secure_zero(&key, sizeof(key));
    secure_zero(&blk, sizeof(blk));
    secure_zero(s->card_secret, sizeof(s->card_secret));
    return CardOk;
}

const char* card_result_text(CardResult r) {
    switch(r) {
    case CardOk:
        return "OK";
    case CardCancelled:
        return "Cancelled";
    case CardWrongType:
        return "Not a Mifare Classic\n1K/4K card";
    case CardNotBlank:
        return "Card is not blank\n(non-default keys)";
    case CardAuthFailed:
        return "Wrong card";
    case CardWriteFailed:
        return "Card write failed";
    }
    return "?";
}
