#include "../card_vault_i.h"

/* Shown once after creation: the recovery key sits on the SD until the user
 * has copied it to the PC, then it is shredded. */

static void button_cb(GuiButtonType type, InputType input, void* ctx) {
    CardVaultApp* app = ctx;
    if(input == InputTypeShort && type == GuiButtonTypeRight) {
        view_dispatcher_send_custom_event(app->view_dispatcher, CardVaultEventButtonRight);
    }
}

void card_vault_scene_recovery_on_enter(void* context) {
    CardVaultApp* app = context;
    widget_reset(app->widget);
    widget_add_string_element(
        app->widget, 64, 0, AlignCenter, AlignTop, FontPrimary, "Save recovery key!");
    widget_add_string_multiline_element(
        app->widget,
        0,
        13,
        AlignLeft,
        AlignTop,
        FontSecondary,
        "On PC run:\n cardvault.py fetch-key\nthen press Erase.");
    widget_add_button_element(app->widget, GuiButtonTypeRight, "Erase", button_cb, app);
    view_dispatcher_switch_to_view(app->view_dispatcher, CardVaultViewWidget);
}

bool card_vault_scene_recovery_on_event(void* context, SceneManagerEvent event) {
    CardVaultApp* app = context;
    if(event.type == SceneManagerEventTypeCustom && event.event == CardVaultEventButtonRight) {
        app->job = JobEraseRecovery;
        scene_manager_next_scene(app->scene_manager, CardVaultSceneWork);
        return true;
    }
    /* Back is swallowed: leaving without erasing would strand the key on SD */
    return event.type == SceneManagerEventTypeBack;
}

void card_vault_scene_recovery_on_exit(void* context) {
    CardVaultApp* app = context;
    widget_reset(app->widget);
}
