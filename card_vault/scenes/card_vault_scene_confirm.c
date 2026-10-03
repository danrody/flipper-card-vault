#include "../card_vault_i.h"

static void dialog_cb(DialogExResult result, void* ctx) {
    CardVaultApp* app = ctx;
    if(result == DialogExResultRight) {
        view_dispatcher_send_custom_event(app->view_dispatcher, CardVaultEventButtonRight);
    } else if(result == DialogExResultLeft) {
        view_dispatcher_send_custom_event(app->view_dispatcher, CardVaultEventButtonCenter);
    }
}

void card_vault_scene_confirm_on_enter(void* context) {
    CardVaultApp* app = context;
    DialogEx* d = app->dialog;
    dialog_ex_reset(d);
    if(app->confirm == ConfirmDelete) {
        dialog_ex_set_header(d, "Delete vault?", 64, 0, AlignCenter, AlignTop);
        dialog_ex_set_text(
            d, "All data will be\ndestroyed forever.", 64, 26, AlignCenter, AlignCenter);
        dialog_ex_set_right_button_text(d, "Delete");
    } else {
        dialog_ex_set_header(d, "Lock vault?", 64, 0, AlignCenter, AlignTop);
        dialog_ex_set_text(
            d, "Eject the drive on\nthe PC first!", 64, 26, AlignCenter, AlignCenter);
        dialog_ex_set_right_button_text(d, "Lock");
    }
    dialog_ex_set_left_button_text(d, "Cancel");
    dialog_ex_set_result_callback(d, dialog_cb);
    dialog_ex_set_context(d, app);
    view_dispatcher_switch_to_view(app->view_dispatcher, CardVaultViewDialog);
}

bool card_vault_scene_confirm_on_event(void* context, SceneManagerEvent event) {
    CardVaultApp* app = context;
    if(event.type != SceneManagerEventTypeCustom) return false;
    if(event.event == CardVaultEventButtonCenter) {
        scene_manager_previous_scene(app->scene_manager);
    } else if(event.event == CardVaultEventButtonRight) {
        if(app->confirm == ConfirmDelete) {
            app->job = JobWipe;
            scene_manager_next_scene(app->scene_manager, CardVaultSceneWork);
        } else {
            /* leaving the unlocked scene stops USB and wipes the key */
            scene_manager_search_and_switch_to_previous_scene(
                app->scene_manager, CardVaultSceneStart);
        }
    } else {
        return false;
    }
    return true;
}

void card_vault_scene_confirm_on_exit(void* context) {
    CardVaultApp* app = context;
    dialog_ex_reset(app->dialog);
}
