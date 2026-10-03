#pragma once

#include <stdbool.h>
#include <stdint.h>

#define FAT32_SECTOR_SIZE 512

/* Minimal size for a valid FAT32 volume (65525 clusters at 512 B/cluster + overhead). */
#define FAT32_MIN_SECTORS (66600UL)

/* Writes `count` sectors starting at `sector`. The writer may clobber `buf`
 * (it is encrypted in place). */
typedef bool (*Fat32WriteFn)(void* ctx, uint32_t sector, uint8_t* buf, uint32_t count);

/* Number of sectors fat32_format() writes (for progress reporting). */
uint32_t fat32_format_sectors(uint32_t total_sectors);

/* Formats a superfloppy (no partition table) FAT32 volume of `total_sectors`.
 * Only metadata is written; the data area is left untouched. */
bool fat32_format(
    uint32_t total_sectors,
    const char* label,
    uint32_t serial,
    Fat32WriteFn write,
    void* ctx);
