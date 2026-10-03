/* FAT32 formatter following the Microsoft FAT specification (fatgen103). */
#include "fat32.h"

#include <stdlib.h>
#include <string.h>

#define FAT32_RESERVED_SECTORS 32
#define FAT32_NUM_FATS         2
#define FAT32_ROOT_CLUSTER     2
#define FAT32_FSINFO_SECTOR    1
#define FAT32_BACKUP_BOOT      6
#define FAT32_MIN_CLUSTERS     65525UL
#define FAT32_CHUNK_SECTORS    8

static inline void put16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void put32(uint8_t* p, uint32_t v) {
    put16(p, (uint16_t)v);
    put16(p + 2, (uint16_t)(v >> 16));
}

static void make_label(uint8_t out[11], const char* label) {
    memset(out, ' ', 11);
    for(size_t i = 0; i < 11 && label[i]; i++)
        out[i] = (uint8_t)label[i];
}

static void build_boot_sector(
    uint8_t* s,
    uint32_t total,
    uint8_t spc,
    uint32_t fat_sz,
    uint32_t serial,
    const char* label) {
    memset(s, 0, FAT32_SECTOR_SIZE);
    s[0] = 0xEB;
    s[1] = 0x58;
    s[2] = 0x90;
    memcpy(s + 3, "MSWIN4.1", 8);
    put16(s + 11, FAT32_SECTOR_SIZE);
    s[13] = spc;
    put16(s + 14, FAT32_RESERVED_SECTORS);
    s[16] = FAT32_NUM_FATS;
    s[21] = 0xF8; /* fixed media */
    put16(s + 24, 63); /* sectors per track (CHS geometry is informational only) */
    put16(s + 26, 255); /* heads */
    put32(s + 32, total);
    put32(s + 36, fat_sz);
    put32(s + 44, FAT32_ROOT_CLUSTER);
    put16(s + 48, FAT32_FSINFO_SECTOR);
    put16(s + 50, FAT32_BACKUP_BOOT);
    s[64] = 0x80; /* drive number */
    s[66] = 0x29; /* extended boot signature */
    put32(s + 67, serial);
    make_label(s + 71, label);
    memcpy(s + 82, "FAT32   ", 8);
    s[0x5A] = 0xF4; /* boot code: hlt - this volume is not bootable */
    s[510] = 0x55;
    s[511] = 0xAA;
}

static void build_fsinfo(uint8_t* s, uint32_t free_clusters) {
    memset(s, 0, FAT32_SECTOR_SIZE);
    put32(s + 0, 0x41615252);
    put32(s + 484, 0x61417272);
    put32(s + 488, free_clusters);
    put32(s + 492, FAT32_ROOT_CLUSTER + 1);
    put32(s + 508, 0xAA550000);
}

static uint8_t sectors_per_cluster(uint32_t total_sectors) {
    /* cluster size per Microsoft's FAT32 table: 512 B up to 260 MB, then 4 KB */
    return total_sectors <= 532480UL ? 1 : 8;
}

static uint32_t fat_size(uint32_t total_sectors, uint8_t spc) {
    uint32_t tmp1 = total_sectors - FAT32_RESERVED_SECTORS;
    uint32_t tmp2 = ((256UL * spc) + FAT32_NUM_FATS) / 2;
    return (tmp1 + tmp2 - 1) / tmp2;
}

uint32_t fat32_format_sectors(uint32_t total_sectors) {
    uint8_t spc = sectors_per_cluster(total_sectors);
    return FAT32_RESERVED_SECTORS + FAT32_NUM_FATS * fat_size(total_sectors, spc) + spc;
}

bool fat32_format(
    uint32_t total_sectors,
    const char* label,
    uint32_t serial,
    Fat32WriteFn write,
    void* ctx) {
    if(total_sectors < FAT32_MIN_SECTORS) return false;

    uint8_t spc = sectors_per_cluster(total_sectors);
    uint32_t fat_sz = fat_size(total_sectors, spc);
    uint32_t data_start = FAT32_RESERVED_SECTORS + FAT32_NUM_FATS * fat_sz;
    uint32_t clusters = (total_sectors - data_start) / spc;
    if(clusters < FAT32_MIN_CLUSTERS) return false;

    uint8_t* buf = malloc(FAT32_CHUNK_SECTORS * FAT32_SECTOR_SIZE);
    if(!buf) return false;
    bool ok = true;

    /* Reserved region: boot sector, FSInfo and their backups, rest zero. */
    for(uint32_t sec = 0; sec < FAT32_RESERVED_SECTORS && ok; sec += FAT32_CHUNK_SECTORS) {
        memset(buf, 0, FAT32_CHUNK_SECTORS * FAT32_SECTOR_SIZE);
        for(uint32_t i = 0; i < FAT32_CHUNK_SECTORS; i++) {
            uint32_t abs = sec + i;
            uint8_t* s = buf + i * FAT32_SECTOR_SIZE;
            if(abs == 0 || abs == FAT32_BACKUP_BOOT) {
                build_boot_sector(s, total_sectors, spc, fat_sz, serial, label);
            } else if(abs == FAT32_FSINFO_SECTOR || abs == FAT32_BACKUP_BOOT + 1) {
                build_fsinfo(s, clusters - 1);
            }
        }
        ok = write(ctx, sec, buf, FAT32_CHUNK_SECTORS);
    }

    /* Both FATs: media/EOC markers in entries 0-1, root directory chain end in entry 2. */
    for(uint32_t f = 0; f < FAT32_NUM_FATS && ok; f++) {
        uint32_t base = FAT32_RESERVED_SECTORS + f * fat_sz;
        for(uint32_t sec = 0; sec < fat_sz && ok; sec += FAT32_CHUNK_SECTORS) {
            uint32_t n = fat_sz - sec < FAT32_CHUNK_SECTORS ? fat_sz - sec : FAT32_CHUNK_SECTORS;
            memset(buf, 0, n * FAT32_SECTOR_SIZE);
            if(sec == 0) {
                put32(buf + 0, 0x0FFFFFF8);
                put32(buf + 4, 0x0FFFFFFF);
                put32(buf + 8, 0x0FFFFFFF);
            }
            ok = write(ctx, base + sec, buf, n);
        }
    }

    /* Root directory cluster with the volume label entry. */
    if(ok) {
        memset(buf, 0, (size_t)spc * FAT32_SECTOR_SIZE);
        make_label(buf, label);
        buf[11] = 0x08; /* ATTR_VOLUME_ID */
        ok = write(ctx, data_start, buf, spc);
    }

    memset(buf, 0, FAT32_CHUNK_SECTORS * FAT32_SECTOR_SIZE);
    free(buf);
    return ok;
}
