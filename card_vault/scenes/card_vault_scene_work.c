#include "../card_vault_i.h"

static const char* card_hint(CardVaultJob job) {
    return job == JobUnlockCard || job == JobCardCheck ? "Hold card to the back" :
                                                         "Hold a BLANK card still";
}

static VaultAnimKind job_anim(CardVaultApp* app) {
    const char* phase = app->phase;
    if(card_vault_job_cancelable(app->job) && !phase) return VaultAnimCard;
    if(app->job == JobWipe || app->job == JobEraseRecovery) return VaultAnimWipe;
    if(phase && !strcmp(phase, "Formatting")) return VaultAnimFormat;
    return VaultAnimKeys;
}

static void render(CardVaultApp* app) {
    VaultAnimKind kind = job_anim(app);
    const char* phase = app->phase;
    const char* title = phase ? phase : card_vault_job_title(app->job);
    vault_anim_set(app->anim, kind, title, kind == VaultAnimCard ? card_hint(app->job) : NULL);
    uint32_t total = app->progress_total;
    if(total) {
        vault_anim_set_progress(
            app->anim, (uint8_t)((uint64_t)app->progress_done * 100 / total));
    }
}

static void start_job(CardVaultApp* app, CardVaultJob job) {
    app->job = job;
    app->phase = NULL;
    app->progress_total = 0;
    vault_anim_set_progress(app->anim, VAULT_ANIM_NO_PROGRESS);
    render(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, CardVaultViewAnim);
    if(card_vault_job_cancelable(job)) {
        notification_message(app->notifications, &sequence_blink_start_cyan);
    }
    card_vault_job_start(app, job);
}

static void to_start(CardVaultApp* app) {
    scene_manager_search_and_switch_to_previous_scene(app->scene_manager, CardVaultSceneStart);
}

static void fail(CardVaultApp* app, const char* title, const char* text, bool retry) {
    notification_message(app->notifications, &sequence_error);
    card_vault_show_message(
        app,
        title,
        text,
        retry ? "Retry" : "OK",
        retry ? MsgActionRetryJob : MsgActionStart,
        MsgActionStart);
}

/* Drives every multi-step flow from the result of the finished job. */
static void on_job_done(CardVaultApp* app) {
    VaultStatus st = app->status;
    CardVaultJob job = app->job;

    if(card_vault_job_cancelable(job)) {
        notification_message(app->notifications, &sequence_blink_stop);
    }

    if(st == VaultErrCancelled) {
        if(job == JobCreateCard) storage_common_remove(app->storage, VAULT_IMAGE_PATH);
        to_start(app);
        return;
    }

    switch(job) {
    case JobCreatePrepare:
        if(st == VaultOk)
            start_job(app, JobCreateCard);
        else
            fail(app, "Create failed", vault_status_text(st), false);
        break;

    case JobCreateCard:
    case JobRestoreCard:
        if(st == VaultErrWrongCard) {
            fail(app, "Card error", card_result_text(app->card_result), true);
        } else if(st != VaultOk) {
            fail(app, "Failed", vault_status_text(st), false);
        } else if(job == JobCreateCard) {
            notification_message(app->notifications, &sequence_success);
            scene_manager_next_scene(app->scene_manager, CardVaultSceneRecovery);
        } else {
            notification_message(app->notifications, &sequence_success);
            card_vault_show_message(
                app,
                "Re-keyed",
                "New password and card set.\nThe old card no longer\nopens this vault.",
                "OK",
                MsgActionStart,
                MsgActionStart);
        }
        break;

    case JobUnlockPassword:
        if(st == VaultOk) {
            start_job(app, app->card_check_mode ? JobCardCheck : JobUnlockCard);
        } else if(st == VaultErrWrongPassword) {
            char text[80];
            uint8_t left = VAULT_MAX_ATTEMPTS - app->session->hdr.failed_attempts;
            snprintf(
                text,
                sizeof(text),
                "Wrong password.\n%u attempt%s left before\nthe vault is destroyed.",
                left,
                left == 1 ? "" : "s");
            fail(app, "Denied", text, false);
        } else if(st == VaultErrWiped) {
            fail(app, "Vault destroyed", "Too many wrong passwords.\nAll vault data erased.", false);
        } else {
            fail(app, "Error", vault_status_text(st), false);
        }
        break;

    case JobUnlockCard:
    case JobRecoveryUnlock:
        if(st == VaultOk) {
            notification_message(app->notifications, &sequence_success);
            scene_manager_next_scene(app->scene_manager, CardVaultSceneUnlocked);
        } else if(st == VaultErrWrongCard && job == JobUnlockCard) {
            fail(app, "Card error", card_result_text(app->card_result), true);
        } else {
            fail(app, "Unlock failed", vault_status_text(st), false);
        }
        break;

    case JobRestoreLoad:
        if(st == VaultOk) {
            app->password_stage = 0;
            scene_manager_next_scene(app->scene_manager, CardVaultScenePassword);
        } else {
            fail(app, "Restore failed", vault_status_text(st), false);
        }
        break;

    case JobRestorePrepare:
        if(st == VaultOk)
            start_job(app, JobRestoreCard);
        else
            fail(app, "Failed", vault_status_text(st), false);
        break;

    case JobEraseRecovery:
        card_vault_show_message(
            app,
            "Vault ready",
            "Recovery key erased\nfrom SD. Use Unlock\nto open the vault.",
            "OK",
            MsgActionStart,
            MsgActionStart);
        break;

    case JobCardCheck:
        if(st == VaultOk) {
            card_vault_show_message(
                app, "Card check", app->report_text, NULL, MsgActionStart, MsgActionStart);
        } else {
            fail(app, "Card error", card_result_text(app->card_result), true);
        }
        break;

    case JobWipe:
        card_vault_show_message(
            app, "Deleted", "Vault destroyed.", "OK", MsgActionStart, MsgActionStart);
        break;
    }
}

void card_vault_scene_work_on_enter(void* context) {
    CardVaultApp* app = context;
    start_job(app, app->job);
}

bool card_vault_scene_work_on_event(void* context, SceneManagerEvent event) {
    CardVaultApp* app = context;
    switch(event.type) {
    case SceneManagerEventTypeCustom:
        if(event.event != CardVaultEventJobDone) return false;
        furi_thread_join(app->worker);
        furi_thread_free(app->worker);
        app->worker = NULL;
        on_job_done(app);
        return true;
    case SceneManagerEventTypeTick:
        if(app->worker) render(app);
        return true;
    case SceneManagerEventTypeBack:
        /* jobs that touch the card can be cancelled; the rest must finish */
        if(app->worker && card_vault_job_cancelable(app->job)) app->cancel = true;
        return true;
    default:
        return false;
    }
}

void card_vault_scene_work_on_exit(void* context) {
    UNUSED(context);
}
