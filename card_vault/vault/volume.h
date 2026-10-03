#pragma once

#include "vault.h"

typedef struct VaultVolume VaultVolume;

typedef void (*VolumeProgressCb)(uint32_t done, uint32_t total, void* ctx);

/* Creates vault.img of `sectors` and formats it as FAT32 through the cipher. */
VaultStatus volume_create(
    Storage* storage,
    const XtsKey* key,
    uint32_t sectors,
    VolumeProgressCb progress,
    void* ctx);

/* Opens the existing image; the volume keeps its own copy of the key. */
VaultVolume* volume_open(Storage* storage, const XtsKey* key, uint32_t sectors);
/* Flushes, closes and wipes the key. */
void volume_close(VaultVolume* vol);

bool volume_read(VaultVolume* vol, uint32_t lba, uint8_t* buf, uint32_t count);
/* Encrypts `buf` in place, then writes it. */
bool volume_write(VaultVolume* vol, uint32_t lba, uint8_t* buf, uint32_t count);
bool volume_sync(VaultVolume* vol);
uint32_t volume_sectors(const VaultVolume* vol);
void volume_stats(const VaultVolume* vol, uint64_t* read, uint64_t* written);

/* Largest image that fits: 4 GiB - 1 is the FatFs offset limit. */
#define VOLUME_MAX_SECTORS ((uint32_t)((4096ULL * 1024 * 1024 - 1) / XTS_SECTOR_SIZE) & ~7UL)
