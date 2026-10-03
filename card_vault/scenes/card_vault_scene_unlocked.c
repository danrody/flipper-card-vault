#include "../card_vault_i.h"

#include <furi_hal_power.h>

#define VBUS_MIN_VOLTAGE 3.0f
#define VBUS_LOST_TICKS  2

/* ---- SCSI backend: the encrypted volume ---- */

static bool scsi_read(
    void* ctx,
    uint32_t lba,
    uint16_t count,
    uint8_t* out,
    uint32_t* out_len,
    uint32_t out_cap) {
    VaultVolume* vol = ctx;
    uint32_t n = MIN((uint32_t)count, out_cap / SCSI_BLOCK_SIZE);
    bool ok = n && volume_read(vol, lba, out, n);
    *out_len = ok ? n * SCSI_BLOCK_SIZE : 0;
    return ok;
}

static bool scsi_write(void* ctx, uint32_t lba, uint16_t count, uint8_t* buf, uint32_t len) {
    VaultVolume* vol = ctx;
    if(len != (uint32_t)count * SCSI_BLOCK_SIZE) return false;
    return volume_write(vol, lba, buf, count);
}

static uint32_t scsi_num_blocks(void* ctx) {
    return volume_sectors(ctx);
}

static bool scsi_sync(void* ctx) {
    return volume_sync(ctx);
}

/* eject comes from the USB thread; context is the app via a static, since
 * the SCSI context is the volume itself */
static CardVaultApp* eject_target = NULL;

static void scsi_eject(void* ctx) {
    UNUSED(ctx);
    if(eject_target) {
        view_dispatcher_send_custom_event(eject_target->view_dispatcher, CardVaultEventEject);
    }
}

void card_vault_lock(CardVaultApp* app) {
    eject_target = NULL;
    if(app->usb) {
        mass_storage_usb_stop(app->usb);
        app->usb = NULL;
    }
    if(app->volume) {
        volume_close(app->volume);
        app->volume = NULL;
    }
}

/* ---- UI ---- */

static void render(CardVaultApp* app) {
    uint64_t rd = 0, wr = 0;
    volume_stats(app->volume, &rd, &wr);
    vault_anim_set_drive(
        app->anim,
        (uint32_t)((uint64_t)volume_sectors(app->volume) * XTS_SECTOR_SIZE >> 20),
        rd,
        wr);
}

static void locked_message(CardVaultApp* app, const char* why) {
    card_vault_lock(app);
    notification_message(app->notifications, &sequence_single_vibro);
    card_vault_show_message(app, "Locked", why, "OK", MsgActionStart, MsgActionStart);
}

void card_vault_scene_unlocked_on_enter(void* context) {
    CardVaultApp* app = context;

    if(!app->volume) {
        VaultSession* s = app->session;
        app->volume = volume_open(app->storage, &s->mk, (uint32_t)s->hdr.volume_sectors);
        /* the volume holds its own key copy; nothing else stays in RAM */
        card_vault_wipe_secrets(app);
        if(!app->volume) {
            card_vault_show_message(
                app, "Error", "Cannot open vault.img", "OK", MsgActionStart, MsgActionStart);
            return;
        }
        SCSIDeviceFunc fn = {
            .ctx = app->volume,
            .read = scsi_read,
            .write = scsi_write,
            .num_blocks = scsi_num_blocks,
            .eject = scsi_eject,
            .sync = scsi_sync,
        };
        eject_target = app;
        app->vbus_lost_ticks = 0;
        app->usb = mass_storage_usb_start("CardVault", fn);
        if(!app->usb) {
            card_vault_lock(app);
            card_vault_show_message(
                app,
                "USB busy",
                "Close other USB apps\n(qFlipper, BadUSB...)",
                "OK",
                MsgActionStart,
                MsgActionStart);
            return;
        }
    }
    vault_anim_set(app->anim, VaultAnimUnlocked, NULL, NULL);
    render(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, CardVaultViewAnim);
}

bool card_vault_scene_unlocked_on_event(void* context, SceneManagerEvent event) {
    CardVaultApp* app = context;
    switch(event.type) {
    case SceneManagerEventTypeTick:
        if(!app->volume) return true;
        /* physical disconnect: lock so a grabbed Flipper is not left open */
        if(furi_hal_power_get_usb_voltage() < VBUS_MIN_VOLTAGE) {
            if(++app->vbus_lost_ticks >= VBUS_LOST_TICKS) {
                locked_message(app, "USB disconnected.");
                return true;
            }
        } else {
            app->vbus_lost_ticks = 0;
        }
        render(app);
        return true;
    case SceneManagerEventTypeCustom:
        if(event.event == CardVaultEventEject) {
            locked_message(app, "Drive ejected on PC.");
            return true;
        }
        return false;
    case SceneManagerEventTypeBack:
        app->confirm = ConfirmLock;
        scene_manager_next_scene(app->scene_manager, CardVaultSceneConfirm);
        return true;
    default:
        return false;
    }
}

void card_vault_scene_unlocked_on_exit(void* context) {
    UNUSED(context);
}
