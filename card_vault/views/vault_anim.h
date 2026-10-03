#pragma once

#include <gui/view.h>

/* Animated full-screen status view used for every long operation and for
 * the unlocked state. Runs its own ~12 FPS frame timer while visible. */

typedef enum {
    VaultAnimKeys, /* padlock + scrolling hex: key derivation / crypto */
    VaultAnimCard, /* card with pulsing NFC waves: waiting for a card */
    VaultAnimFormat, /* disk block grid filling up */
    VaultAnimWipe, /* blocks scattering away */
    VaultAnimUnlocked, /* padlock opening, then live drive statistics */
} VaultAnimKind;

#define VAULT_ANIM_NO_PROGRESS 0xFF

typedef struct VaultAnim VaultAnim;

VaultAnim* vault_anim_alloc(void);
void vault_anim_free(VaultAnim* anim);
View* vault_anim_get_view(VaultAnim* anim);

/* Switches the scene; restarts the frame counter when the kind changes. */
void vault_anim_set(VaultAnim* anim, VaultAnimKind kind, const char* title, const char* hint);
/* 0..100, or VAULT_ANIM_NO_PROGRESS for an indeterminate bar. */
void vault_anim_set_progress(VaultAnim* anim, uint8_t percent);
/* Unlocked screen numbers: drive size and cumulative traffic. */
void vault_anim_set_drive(VaultAnim* anim, uint32_t size_mb, uint64_t read, uint64_t written);
