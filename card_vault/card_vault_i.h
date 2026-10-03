#pragma once

#include "vault/vault.h"
#include "vault/card.h"
#include "vault/volume.h"
#include "usb/msc_usb.h"
#include "crypto/secure_mem.h"
#include "scenes/card_vault_scene.h"
#include "views/vault_anim.h"

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <gui/modules/popup.h>
#include <gui/modules/widget.h>
#include <gui/modules/dialog_ex.h>
#include <notification/notification_messages.h>
#include <nfc/nfc.h>

typedef enum {
    CardVaultViewSubmenu,
    CardVaultViewTextInput,
    CardVaultViewPopup,
    CardVaultViewWidget,
    CardVaultViewDialog,
    CardVaultViewAnim,
} CardVaultView;

typedef enum {
    CardVaultEventJobDone = 100,
    CardVaultEventPassword,
    CardVaultEventButtonRight,
    CardVaultEventButtonCenter,
    CardVaultEventEject,
} CardVaultEvent;

typedef enum {
    FlowCreate,
    FlowUnlock,
    FlowRestore,
} CardVaultFlow;

typedef enum {
    JobCreatePrepare, /* calibrate KDF, derive keys, create + format image */
    JobCreateCard, /* write blank card, wrap MK, save header + recovery key */
    JobUnlockPassword, /* attempt counter, verify password */
    JobUnlockCard, /* read card, unwrap MK */
    JobRecoveryUnlock, /* MK from recovery key on SD */
    JobRestoreLoad, /* recovery key -> MK, for re-keying */
    JobRestorePrepare, /* new salt + password keys */
    JobRestoreCard, /* write blank card, wrap MK, save header */
    JobEraseRecovery,
    JobWipe,
    JobCardCheck, /* diagnostics: read card, report randomness stats */
} CardVaultJob;

/* What the message screen's buttons do. */
typedef enum {
    MsgActionStart,
    MsgActionExit,
    MsgActionRetryJob, /* re-run app->job */
    MsgActionPassword, /* back to first password prompt */
} CardVaultMsgAction;

typedef enum {
    ConfirmDelete,
    ConfirmLock,
} CardVaultConfirm;

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    SceneManager* scene_manager;
    Storage* storage;
    NotificationApp* notifications;
    Nfc* nfc;

    Submenu* submenu;
    TextInput* text_input;
    Popup* popup;
    Widget* widget;
    DialogEx* dialog;
    VaultAnim* anim;

    VaultSession* session;
    char password[VAULT_PW_MAX_LEN + 1];
    char password_repeat[VAULT_PW_MAX_LEN + 1];
    uint8_t password_stage;

    CardVaultFlow flow;
    uint32_t new_sectors;

    /* background job */
    FuriThread* worker;
    CardVaultJob job;
    volatile bool cancel;
    VaultStatus status;
    CardResult card_result;
    volatile uint32_t progress_done;
    volatile uint32_t progress_total;
    const char* volatile phase;
    char work_text[64];
    char report_text[200];
    bool card_check_mode;

    /* message screen */
    FuriString* msg_title;
    FuriString* msg_text;
    const char* msg_button;
    CardVaultMsgAction msg_action;
    CardVaultMsgAction msg_back_action;

    CardVaultConfirm confirm;

    /* unlocked state */
    VaultVolume* volume;
    MassStorageUsb* usb;
    uint8_t vbus_lost_ticks;
} CardVaultApp;

void card_vault_job_start(CardVaultApp* app, CardVaultJob job);
bool card_vault_job_cancelable(CardVaultJob job);
const char* card_vault_job_title(CardVaultJob job);

void card_vault_show_message(
    CardVaultApp* app,
    const char* title,
    const char* text,
    const char* button,
    CardVaultMsgAction action,
    CardVaultMsgAction back_action);

void card_vault_wipe_secrets(CardVaultApp* app);
void card_vault_wipe_passwords(CardVaultApp* app);

/* Stops the USB drive and wipes the volume key. Idempotent. */
void card_vault_lock(CardVaultApp* app);
