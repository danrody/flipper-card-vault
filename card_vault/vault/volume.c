#include "volume.h"
#include "fat32.h"
#include "../crypto/secure_mem.h"

#include <furi.h>
#include <furi_hal_random.h>

#define TAG "CardVaultVol"

#define ZERO_FILL_CHUNK (16 * XTS_SECTOR_SIZE)

/* Pipelining: one background I/O thread overlaps SD + crypto with the USB
 * transfer. Reads prefetch the next chunk of a sequential stream; writes are
 * acknowledged once copied and committed behind the next USB transfer.
 * Every foreground operation first waits for the background one, so the
 * file is never touched by two threads at once and ordering is preserved. */
#define AUX_MAX_SECTORS      64U /* 32 KiB, >= one MSC transfer chunk */
#define PREFETCH_MIN_SECTORS 16U
#define WORKER_FLAG_RUN      (1UL << 0)

typedef enum {
    BgNone,
    BgPrefetch,
    BgWrite,
} BgOp;

struct VaultVolume {
    XtsKey key __attribute__((aligned(4)));
    Storage* storage;
    File* file;
    uint32_t sectors;
    volatile uint64_t bytes_read;
    volatile uint64_t bytes_written;

    FuriThread* worker;
    FuriSemaphore* idle; /* taken while a background op runs */
    uint8_t* aux;
    BgOp op;
    uint32_t aux_lba;
    uint32_t aux_count;
    bool prefetch_valid;
    bool write_error; /* deferred write failure, reported on next write/sync */
    uint32_t last_read_end;
    volatile bool exit;
};

typedef struct {
    VaultVolume* vol;
    uint32_t written;
    uint32_t total;
    VolumeProgressCb progress;
    void* ctx;
} FormatCtx;

static bool format_write(void* ctx, uint32_t sector, uint8_t* buf, uint32_t count) {
    FormatCtx* f = ctx;
    bool ok = volume_write(f->vol, sector, buf, count);
    f->written += count;
    if(f->progress) f->progress(f->written, f->total, f->ctx);
    return ok;
}

/* Grows the file to `bytes`. FatFs extends on seek-past-EOF (no data
 * written); if the backend refuses, fall back to writing filler. */
static bool expand_file(File* file, uint64_t bytes, VolumeProgressCb progress, void* ctx) {
    uint32_t last = (uint32_t)(bytes - XTS_SECTOR_SIZE);
    uint8_t sector[XTS_SECTOR_SIZE];
    furi_hal_random_fill_buf(sector, sizeof(sector));

    if(storage_file_seek(file, last, true) && storage_file_tell(file) == last &&
       storage_file_write(file, sector, sizeof(sector)) == sizeof(sector) &&
       storage_file_size(file) == bytes) {
        return true;
    }

    FURI_LOG_W(TAG, "seek-extend unsupported, filling");
    uint8_t* buf = malloc(ZERO_FILL_CHUNK);
    bool ok = storage_file_seek(file, 0, true);
    for(uint64_t off = 0; ok && off < bytes; off += ZERO_FILL_CHUNK) {
        size_t n = bytes - off < ZERO_FILL_CHUNK ? (size_t)(bytes - off) : ZERO_FILL_CHUNK;
        furi_hal_random_fill_buf(buf, n);
        ok = storage_file_write(file, buf, n) == n;
        if(progress) progress((uint32_t)(off >> 20), (uint32_t)(bytes >> 20), ctx);
    }
    free(buf);
    return ok && storage_file_size(file) == bytes;
}

VaultStatus volume_create(
    Storage* storage,
    const XtsKey* key,
    uint32_t sectors,
    VolumeProgressCb progress,
    void* ctx) {
    uint64_t bytes = (uint64_t)sectors * XTS_SECTOR_SIZE;
    uint64_t total_space = 0, free_space = 0;

    if(sectors > VOLUME_MAX_SECTORS || sectors < FAT32_MIN_SECTORS) return VaultErrIo;
    storage_simply_mkdir(storage, VAULT_DIR);
    if(storage_common_fs_info(storage, EXT_PATH(""), &total_space, &free_space) != FSE_OK)
        return VaultErrIo;
    if(free_space < bytes + (8ULL << 20)) return VaultErrNoSpace;

    File* file = storage_file_alloc(storage);
    bool ok = storage_file_open(file, VAULT_IMAGE_PATH, FSAM_READ_WRITE, FSOM_CREATE_ALWAYS) &&
              expand_file(file, bytes, progress, ctx);
    storage_file_close(file);
    storage_file_free(file);
    if(!ok) {
        storage_common_remove(storage, VAULT_IMAGE_PATH);
        return VaultErrIo;
    }

    VaultVolume* vol = volume_open(storage, key, sectors);
    if(!vol) return VaultErrIo;

    uint32_t serial;
    furi_hal_random_fill_buf((uint8_t*)&serial, sizeof(serial));
    FormatCtx fc = {
        .vol = vol, .total = fat32_format_sectors(sectors), .progress = progress, .ctx = ctx};
    ok = fat32_format(sectors, "CARDVAULT", serial, format_write, &fc);
    ok = volume_sync(vol) && ok;
    volume_close(vol);

    if(!ok) {
        storage_common_remove(storage, VAULT_IMAGE_PATH);
        return VaultErrIo;
    }
    return VaultOk;
}

static bool io_read(VaultVolume* vol, uint32_t lba, uint8_t* buf, uint32_t count) {
    size_t len = (size_t)count * XTS_SECTOR_SIZE;
    bool ok = storage_file_seek(vol->file, lba * XTS_SECTOR_SIZE, true) &&
              storage_file_read(vol->file, buf, len) == len &&
              xts_crypt(&vol->key, lba, buf, count, false);
    if(ok) vol->bytes_read += len;
    return ok;
}

static bool io_write(VaultVolume* vol, uint32_t lba, uint8_t* buf, uint32_t count) {
    size_t len = (size_t)count * XTS_SECTOR_SIZE;
    bool ok = xts_crypt(&vol->key, lba, buf, count, true) &&
              storage_file_seek(vol->file, lba * XTS_SECTOR_SIZE, true) &&
              storage_file_write(vol->file, buf, len) == len;
    if(ok) vol->bytes_written += len;
    return ok;
}

static int32_t volume_worker(void* ctx) {
    VaultVolume* vol = ctx;
    for(;;) {
        furi_thread_flags_wait(WORKER_FLAG_RUN, FuriFlagWaitAny, FuriWaitForever);
        if(vol->exit) break;
        if(vol->op == BgPrefetch) {
            vol->prefetch_valid = io_read(vol, vol->aux_lba, vol->aux, vol->aux_count);
        } else if(vol->op == BgWrite) {
            if(!io_write(vol, vol->aux_lba, vol->aux, vol->aux_count)) {
                FURI_LOG_E(TAG, "deferred write failed at %lu", vol->aux_lba);
                vol->write_error = true;
            }
        }
        vol->op = BgNone;
        furi_semaphore_release(vol->idle);
    }
    return 0;
}

static void bg_wait(VaultVolume* vol) {
    furi_check(furi_semaphore_acquire(vol->idle, FuriWaitForever) == FuriStatusOk);
    furi_semaphore_release(vol->idle);
}

static void bg_start(VaultVolume* vol, BgOp op, uint32_t lba, uint32_t count) {
    furi_check(furi_semaphore_acquire(vol->idle, FuriWaitForever) == FuriStatusOk);
    vol->op = op;
    vol->aux_lba = lba;
    vol->aux_count = count;
    furi_thread_flags_set(furi_thread_get_id(vol->worker), WORKER_FLAG_RUN);
}

VaultVolume* volume_open(Storage* storage, const XtsKey* key, uint32_t sectors) {
    VaultVolume* vol = malloc(sizeof(VaultVolume));
    memset(vol, 0, sizeof(*vol));
    vol->storage = storage;
    vol->file = storage_file_alloc(storage);
    if(!storage_file_open(vol->file, VAULT_IMAGE_PATH, FSAM_READ_WRITE, FSOM_OPEN_EXISTING) ||
       storage_file_size(vol->file) < (uint64_t)sectors * XTS_SECTOR_SIZE) {
        storage_file_close(vol->file);
        storage_file_free(vol->file);
        free(vol);
        return NULL;
    }
    vol->key = *key;
    vol->sectors = sectors;
    vol->last_read_end = UINT32_MAX;
    vol->aux = malloc(AUX_MAX_SECTORS * XTS_SECTOR_SIZE);
    vol->idle = furi_semaphore_alloc(1, 1);
    vol->worker = furi_thread_alloc_ex("CardVaultIo", 2048, volume_worker, vol);
    furi_thread_set_priority(vol->worker, FuriThreadPriorityHigh);
    furi_thread_start(vol->worker);
    return vol;
}

void volume_close(VaultVolume* vol) {
    if(!vol) return;
    bg_wait(vol);
    vol->exit = true;
    furi_thread_flags_set(furi_thread_get_id(vol->worker), WORKER_FLAG_RUN);
    furi_thread_join(vol->worker);
    furi_thread_free(vol->worker);
    furi_semaphore_free(vol->idle);

    storage_file_sync(vol->file);
    storage_file_close(vol->file);
    storage_file_free(vol->file);
    secure_zero(vol->aux, AUX_MAX_SECTORS * XTS_SECTOR_SIZE);
    free(vol->aux);
    secure_zero(vol, sizeof(*vol));
    free(vol);
}

static bool in_range(const VaultVolume* vol, uint32_t lba, uint32_t count) {
    return lba < vol->sectors && count <= vol->sectors - lba;
}

bool volume_read(VaultVolume* vol, uint32_t lba, uint8_t* buf, uint32_t count) {
    if(!count || !in_range(vol, lba, count)) return false;
    size_t len = (size_t)count * XTS_SECTOR_SIZE;
    bool ok;

    bg_wait(vol);
    if(vol->prefetch_valid && vol->aux_lba == lba && count <= vol->aux_count) {
        memcpy(buf, vol->aux, len);
        ok = true;
    } else {
        ok = io_read(vol, lba, buf, count);
    }
    vol->prefetch_valid = false;

    /* read ahead only for streaming access, not for scattered metadata reads */
    bool sequential = lba == vol->last_read_end || count >= PREFETCH_MIN_SECTORS;
    vol->last_read_end = lba + count;
    if(ok && sequential && count <= AUX_MAX_SECTORS && in_range(vol, lba + count, count)) {
        bg_start(vol, BgPrefetch, lba + count, count);
    }

    if(!ok) memset(buf, 0, len);
    return ok;
}

bool volume_write(VaultVolume* vol, uint32_t lba, uint8_t* buf, uint32_t count) {
    if(!count || !in_range(vol, lba, count)) return false;

    bg_wait(vol);
    vol->prefetch_valid = false;
    if(vol->write_error) {
        vol->write_error = false;
        return false;
    }
    if(count > AUX_MAX_SECTORS) return io_write(vol, lba, buf, count);

    memcpy(vol->aux, buf, (size_t)count * XTS_SECTOR_SIZE);
    bg_start(vol, BgWrite, lba, count);
    return true;
}

bool volume_sync(VaultVolume* vol) {
    bg_wait(vol);
    bool ok = storage_file_sync(vol->file) && !vol->write_error;
    vol->write_error = false;
    return ok;
}

uint32_t volume_sectors(const VaultVolume* vol) {
    return vol->sectors;
}

void volume_stats(const VaultVolume* vol, uint64_t* read, uint64_t* written) {
    *read = vol->bytes_read;
    *written = vol->bytes_written;
}
