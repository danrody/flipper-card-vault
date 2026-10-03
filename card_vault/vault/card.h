#pragma once

#include "vault.h"

#include <nfc/nfc.h>

typedef enum {
    CardOk,
    CardCancelled,
    CardWrongType, /* not a Mifare Classic 1K/4K */
    CardNotBlank, /* provisioning: sector keys are neither default nor ours */
    CardAuthFailed, /* reading: sector keys do not match -> other card */
    CardWriteFailed,
} CardResult;

/* Both functions wait for a card to be presented until `cancel` is set,
 * and transparently restart if the card is pulled away mid-operation. */

/* Writes s->card_secret into all data blocks and s->card_keys into the
 * sector trailers of a blank card. Idempotent within one session, so an
 * interrupted write can be resumed with the same card. */
CardResult card_provision(Nfc* nfc, const VaultSession* s, volatile bool* cancel);

/* Reads the card secret into s->card_secret using s->card_keys. */
CardResult card_read(Nfc* nfc, VaultSession* s, volatile bool* cancel);

/* Diagnostics for a provisioned card; never exposes the secret itself. */
typedef struct {
    uint8_t blocks_read; /* of 47 data blocks */
    uint8_t blocks_unique;
    uint8_t blocks_blank; /* all 00 or all FF */
    uint16_t ones_permille; /* share of 1-bits, expected ~500 */
    uint16_t byte_values; /* distinct byte values, expected ~243 for 752 random bytes */
    uint8_t trailers_ok; /* sectors whose trailer holds our key B + access bits */
    uint8_t keys_unique; /* distinct among the 32 sector keys */
    int8_t default_key; /* 1 = rejected (auth error), 0 = ACCEPTED, -1 = no answer */
} CardCheck;

CardResult card_check(Nfc* nfc, VaultSession* s, CardCheck* out, volatile bool* cancel);

const char* card_result_text(CardResult r);
