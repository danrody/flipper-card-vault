#include "card_vault_i.h"
#include "crypto/selftest.h"
#include "crypto/secure_mem.h"

#include <furi_hal_random.h>

#define TAG "CardVault"

#define KDF_TARGET_MS     2500
#define TICK_PERIOD_MS    250
#define WORKER_STACK_SIZE (6 * 1024)

/* ---------- background jobs ---------- */

static bool kdf_progress(uint32_t done, uint32_t total, void* ctx) {
    CardVaultApp* app = ctx;
    app->progress_done = done;
    app->progress_total = total;
    return !app->cancel;
}

static void volume_progress(uint32_t done, uint32_t total, void* ctx) {
    CardVaultApp* app = ctx;
    app->progress_done = done;
    app->progress_total = total;
}

void card_vault_wipe_passwords(CardVaultApp* app) {
    secure_zero(app->password, sizeof(app->password));
    secure_zero(app->password_repeat, sizeof(app->password_repeat));
}

static VaultStatus job_unlock_password(CardVaultApp* app) {
    VaultSession* s = app->session;
    VaultStatus st = vault_header_load(app->storage, &s->hdr);
    if(st != VaultOk) return st;

    if(s->hdr.failed_attempts >= VAULT_MAX_ATTEMPTS) {
        vault_wipe(app->storage);
        return VaultErrWiped;
    }
    /* count the attempt durably *before* checking, so cutting power
     * mid-check cannot be used to get unlimited tries */
    st = vault_attempt_begin(app->storage, &s->hdr);
    if(st != VaultOk) return st;

    st = vault_derive_password(s, app->password, true, kdf_progress, app);
    card_vault_wipe_passwords(app);
    if(st == VaultErrWrongPassword && s->hdr.failed_attempts >= VAULT_MAX_ATTEMPTS) {
        vault_wipe(app->storage);
        return VaultErrWiped;
    }
    if(st != VaultOk) return st;
    return vault_attempt_reset(app->storage, &s->hdr);
}

static VaultStatus job_card_finish(CardVaultApp* app, bool with_recovery) {
    VaultSession* s = app->session;
    app->card_result = card_provision(app->nfc, s, &app->cancel);
    if(app->card_result == CardCancelled) return VaultErrCancelled;
    if(app->card_result != CardOk) return VaultErrWrongCard;

    VaultStatus st = vault_wrap_mk(s);
    if(st == VaultOk) st = vault_header_save(app->storage, &s->hdr);
    if(st == VaultOk && with_recovery) st = vault_recovery_write(app->storage, s);
    return st;
}

static VaultStatus job_load_recovery(CardVaultApp* app) {
    VaultSession* s = app->session;
    if(!vault_image_exists(app->storage)) {
        vault_recovery_erase(app->storage);
        return VaultErrNoVault;
    }
    VaultStatus st = vault_recovery_read(app->storage, s);
    /* the plaintext key never stays on the SD longer than needed */
    vault_recovery_erase(app->storage);
    return st;
}

static int32_t card_vault_worker(void* ctx) {
    CardVaultApp* app = ctx;
    VaultSession* s = app->session;
    VaultStatus st = VaultOk;
    app->card_result = CardOk;

    switch(app->job) {
    case JobCreatePrepare:
        app->phase = "Deriving keys";
        vault_session_new(s, app->new_sectors, vault_calibrate_iterations(KDF_TARGET_MS));
        furi_hal_random_fill_buf(s->card_secret, sizeof(s->card_secret));
        st = vault_derive_password(s, app->password, false, kdf_progress, app);
        card_vault_wipe_passwords(app);
        if(st == VaultOk) {
            app->progress_done = app->progress_total = 0;
            app->phase = "Formatting";
            st = volume_create(app->storage, &s->mk, app->new_sectors, volume_progress, app);
        }
        break;
    case JobCreateCard:
        st = job_card_finish(app, true);
        break;
    case JobUnlockPassword:
        st = job_unlock_password(app);
        break;
    case JobUnlockCard:
        app->card_result = card_read(app->nfc, s, &app->cancel);
        if(app->card_result == CardOk) app->phase = "Decrypting key";
        if(app->card_result == CardCancelled)
            st = VaultErrCancelled;
        else if(app->card_result != CardOk)
            st = VaultErrWrongCard;
        else
            st = vault_unwrap_mk(s);
        break;
    case JobRecoveryUnlock:
        st = job_load_recovery(app);
        /* proving ownership with the recovery key clears failed attempts */
        if(st == VaultOk && vault_exists(app->storage)) {
            vault_attempt_reset(app->storage, &s->hdr);
        }
        break;
    case JobRestoreLoad:
        st = job_load_recovery(app);
        break;
    case JobRestorePrepare:
        app->phase = "Deriving keys";
        vault_session_rekey(s, vault_calibrate_iterations(KDF_TARGET_MS));
        furi_hal_random_fill_buf(s->card_secret, sizeof(s->card_secret));
        st = vault_derive_password(s, app->password, false, kdf_progress, app);
        card_vault_wipe_passwords(app);
        break;
    case JobRestoreCard:
        st = job_card_finish(app, false);
        break;
    case JobEraseRecovery:
        vault_recovery_erase(app->storage);
        break;
    case JobWipe:
        vault_wipe(app->storage);
        break;
    case JobCardCheck: {
        CardCheck cc;
        app->card_result = card_check(app->nfc, s, &cc, &app->cancel);
        if(app->card_result == CardCancelled)
            st = VaultErrCancelled;
        else if(app->card_result != CardOk)
            st = VaultErrWrongCard;
        snprintf(
            app->report_text,
            sizeof(app->report_text),
            "Data blocks read: %u/47\nUnique: %u  Blank: %u\n1-bits: %u.%u%%\n"
            "Byte values: %u/256\nTrailers OK: %u/16\nSector keys unique: %u/32\n"
            "Default key: %s",
            cc.blocks_read,
            cc.blocks_unique,
            cc.blocks_blank,
            cc.ones_permille / 10,
            cc.ones_permille % 10,
            cc.byte_values,
            cc.trailers_ok,
            cc.keys_unique,
            cc.default_key > 0 ? "rejected x16" : cc.default_key == 0 ? "ACCEPTED!" : "no answer");
        break;
    }
    }

    app->status = st;
    view_dispatcher_send_custom_event(app->view_dispatcher, CardVaultEventJobDone);
    return 0;
}

void card_vault_job_start(CardVaultApp* app, CardVaultJob job) {
    furi_check(!app->worker);
    app->job = job;
    app->cancel = false;
    app->phase = NULL;
    app->progress_done = app->progress_total = 0;
    app->worker = furi_thread_alloc_ex("CardVaultWorker", WORKER_STACK_SIZE, card_vault_worker, app);
    furi_thread_start(app->worker);
}

bool card_vault_job_cancelable(CardVaultJob job) {
    return job == JobCreateCard || job == JobUnlockCard || job == JobRestoreCard ||
           job == JobCardCheck;
}

const char* card_vault_job_title(CardVaultJob job) {
    switch(job) {
    case JobCreatePrepare:
        return "Creating vault";
    case JobCreateCard:
    case JobRestoreCard:
        return "Blank card";
    case JobUnlockPassword:
        return "Verifying password";
    case JobUnlockCard:
        return "Vault card";
    case JobRecoveryUnlock:
        return "Recovery unlock";
    case JobRestoreLoad:
        return "Reading recovery key";
    case JobRestorePrepare:
        return "Deriving keys";
    case JobEraseRecovery:
        return "Erasing key from SD";
    case JobWipe:
        return "Destroying vault";
    case JobCardCheck:
        return "Vault card";
    }
    return "";
}

/* ---------- helpers ---------- */

void card_vault_show_message(
    CardVaultApp* app,
    const char* title,
    const char* text,
    const char* button,
    CardVaultMsgAction action,
    CardVaultMsgAction back_action) {
    furi_string_set(app->msg_title, title);
    furi_string_set(app->msg_text, text);
    app->msg_button = button;
    app->msg_action = action;
    app->msg_back_action = back_action;
    scene_manager_next_scene(app->scene_manager, CardVaultSceneMessage);
}

void card_vault_wipe_secrets(CardVaultApp* app) {
    vault_session_wipe(app->session);
    card_vault_wipe_passwords(app);
}

/* ---------- lifecycle ---------- */

static bool custom_event_cb(void* ctx, uint32_t event) {
    CardVaultApp* app = ctx;
    return scene_manager_handle_custom_event(app->scene_manager, event);
}

static bool back_event_cb(void* ctx) {
    CardVaultApp* app = ctx;
    return scene_manager_handle_back_event(app->scene_manager);
}

static void tick_event_cb(void* ctx) {
    CardVaultApp* app = ctx;
    scene_manager_handle_tick_event(app->scene_manager);
}

static CardVaultApp* card_vault_alloc(void) {
    CardVaultApp* app = malloc(sizeof(CardVaultApp));
    memset(app, 0, sizeof(*app));

    app->gui = furi_record_open(RECORD_GUI);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->nfc = nfc_alloc();
    app->session = malloc(sizeof(VaultSession));
    vault_session_wipe(app->session);
    app->msg_title = furi_string_alloc();
    app->msg_text = furi_string_alloc();

    app->view_dispatcher = view_dispatcher_alloc();
    app->scene_manager = scene_manager_alloc(&card_vault_scene_handlers, app);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, custom_event_cb);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, back_event_cb);
    view_dispatcher_set_tick_event_callback(app->view_dispatcher, tick_event_cb, TICK_PERIOD_MS);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    app->submenu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, CardVaultViewSubmenu, submenu_get_view(app->submenu));
    app->text_input = text_input_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, CardVaultViewTextInput, text_input_get_view(app->text_input));
    app->popup = popup_alloc();
    view_dispatcher_add_view(app->view_dispatcher, CardVaultViewPopup, popup_get_view(app->popup));
    app->widget = widget_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, CardVaultViewWidget, widget_get_view(app->widget));
    app->dialog = dialog_ex_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, CardVaultViewDialog, dialog_ex_get_view(app->dialog));
    app->anim = vault_anim_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, CardVaultViewAnim, vault_anim_get_view(app->anim));

    return app;
}

static void card_vault_free(CardVaultApp* app) {
    if(app->worker) {
        app->cancel = true;
        furi_thread_join(app->worker);
        furi_thread_free(app->worker);
    }
    card_vault_lock(app);

    view_dispatcher_remove_view(app->view_dispatcher, CardVaultViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, CardVaultViewTextInput);
    view_dispatcher_remove_view(app->view_dispatcher, CardVaultViewPopup);
    view_dispatcher_remove_view(app->view_dispatcher, CardVaultViewWidget);
    view_dispatcher_remove_view(app->view_dispatcher, CardVaultViewDialog);
    view_dispatcher_remove_view(app->view_dispatcher, CardVaultViewAnim);
    vault_anim_free(app->anim);
    submenu_free(app->submenu);
    text_input_free(app->text_input);
    popup_free(app->popup);
    widget_free(app->widget);
    dialog_ex_free(app->dialog);
    scene_manager_free(app->scene_manager);
    view_dispatcher_free(app->view_dispatcher);

    card_vault_wipe_secrets(app);
    free(app->session);
    furi_string_free(app->msg_title);
    furi_string_free(app->msg_text);
    nfc_free(app->nfc);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_GUI);

    secure_zero(app, sizeof(*app));
    free(app);
}

/* Launch arguments (used by tools/cardvault.py via `loader open`):
 *   "recovery-unlock"  unlock with recovery.key on SD, no card/password
 *   "restore"          re-key: new password + new blank card */
int32_t card_vault_app(void* p) {
    const char* args = p;
    CardVaultApp* app = card_vault_alloc();

    const char* failed = crypto_selftest();
    if(failed) {
        FURI_LOG_E(TAG, "self-test failed: %s", failed);
        FuriString* text = furi_string_alloc_printf(
            "%s known-answer test\nfailed. Refusing to run\nto protect your data.", failed);
        scene_manager_next_scene(app->scene_manager, CardVaultSceneStart);
        card_vault_show_message(
            app, "Self-test failed", furi_string_get_cstr(text), "Exit", MsgActionExit, MsgActionExit);
        furi_string_free(text);
    } else {
        scene_manager_next_scene(app->scene_manager, CardVaultSceneStart);
        if(args && !strcmp(args, "recovery-unlock")) {
            app->flow = FlowUnlock;
            app->job = JobRecoveryUnlock;
            scene_manager_next_scene(app->scene_manager, CardVaultSceneWork);
        } else if(args && !strcmp(args, "cardcheck")) {
            app->flow = FlowUnlock;
            app->card_check_mode = true;
            app->password_stage = 0;
            scene_manager_next_scene(app->scene_manager, CardVaultScenePassword);
        } else if(args && !strcmp(args, "restore")) {
            app->flow = FlowRestore;
            app->job = JobRestoreLoad;
            scene_manager_next_scene(app->scene_manager, CardVaultSceneWork);
        }
    }

    view_dispatcher_run(app->view_dispatcher);
    card_vault_free(app);
    return 0;
}
