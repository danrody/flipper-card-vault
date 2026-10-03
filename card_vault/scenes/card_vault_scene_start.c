#include "../card_vault_i.h"

enum {
    ItemCreate,
    ItemUnlock,
    ItemRecoveryUnlock,
    ItemRestore,
    ItemCheckCard,
    ItemDelete,
    ItemHelp,
};

static const char* const HELP_TEXT =
    "Unlock: password, then the\n"
    "vault card. The vault shows\n"
    "up on the PC as a USB drive.\n"
    "Back = lock (eject on PC\n"
    "first). Unplugging USB locks\n"
    "too.\n"
    "5 wrong passwords destroy\n"
    "the vault.\n"
    "Check card: verifies all 47\n"
    "blocks and 32 keys.\n\n"
    "Recovery key (on PC):\n"
    " cardvault.py unlock\n"
    " cardvault.py rekey\n"
    " cardvault.py decrypt\n"
    "Keep recovery.key offline.";

static void submenu_cb(void* ctx, uint32_t index) {
    CardVaultApp* app = ctx;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void card_vault_scene_start_on_enter(void* context) {
    CardVaultApp* app = context;
    /* every flow starts from scratch: drive stopped, keys gone */
    card_vault_lock(app);
    card_vault_wipe_secrets(app);

    bool vault = vault_exists(app->storage);
    bool recovery = vault_recovery_exists(app->storage) && vault_image_exists(app->storage);

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, vault ? "Card Vault: locked" : "Card Vault: no vault");
    if(vault) {
        submenu_add_item(app->submenu, "Unlock", ItemUnlock, submenu_cb, app);
    } else {
        submenu_add_item(app->submenu, "Create vault", ItemCreate, submenu_cb, app);
    }
    if(recovery) {
        submenu_add_item(
            app->submenu, "Unlock with recovery key", ItemRecoveryUnlock, submenu_cb, app);
        submenu_add_item(app->submenu, "New card + password", ItemRestore, submenu_cb, app);
    }
    if(vault) {
        submenu_add_item(app->submenu, "Check card", ItemCheckCard, submenu_cb, app);
        submenu_add_item(app->submenu, "Delete vault", ItemDelete, submenu_cb, app);
    }
    submenu_add_item(app->submenu, "Help", ItemHelp, submenu_cb, app);

    submenu_set_selected_item(
        app->submenu, scene_manager_get_scene_state(app->scene_manager, CardVaultSceneStart));
    view_dispatcher_switch_to_view(app->view_dispatcher, CardVaultViewSubmenu);
}

bool card_vault_scene_start_on_event(void* context, SceneManagerEvent event) {
    CardVaultApp* app = context;
    if(event.type == SceneManagerEventTypeBack) {
        scene_manager_stop(app->scene_manager);
        view_dispatcher_stop(app->view_dispatcher);
        return true;
    }
    if(event.type != SceneManagerEventTypeCustom) return false;

    scene_manager_set_scene_state(app->scene_manager, CardVaultSceneStart, event.event);
    switch(event.event) {
    case ItemCreate:
        app->flow = FlowCreate;
        scene_manager_next_scene(app->scene_manager, CardVaultSceneSize);
        break;
    case ItemUnlock:
    case ItemCheckCard:
        app->flow = FlowUnlock;
        app->card_check_mode = event.event == ItemCheckCard;
        app->password_stage = 0;
        scene_manager_next_scene(app->scene_manager, CardVaultScenePassword);
        break;
    case ItemRecoveryUnlock:
        app->flow = FlowUnlock;
        app->job = JobRecoveryUnlock;
        scene_manager_next_scene(app->scene_manager, CardVaultSceneWork);
        break;
    case ItemRestore:
        app->flow = FlowRestore;
        app->job = JobRestoreLoad;
        scene_manager_next_scene(app->scene_manager, CardVaultSceneWork);
        break;
    case ItemDelete:
        app->confirm = ConfirmDelete;
        scene_manager_next_scene(app->scene_manager, CardVaultSceneConfirm);
        break;
    case ItemHelp:
        card_vault_show_message(app, "Help", HELP_TEXT, NULL, MsgActionStart, MsgActionStart);
        break;
    default:
        return false;
    }
    return true;
}

void card_vault_scene_start_on_exit(void* context) {
    CardVaultApp* app = context;
    submenu_reset(app->submenu);
}
