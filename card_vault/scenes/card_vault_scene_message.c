#include "../card_vault_i.h"

static void button_cb(GuiButtonType type, InputType input, void* ctx) {
    CardVaultApp* app = ctx;
    if(input == InputTypeShort && type == GuiButtonTypeRight) {
        view_dispatcher_send_custom_event(app->view_dispatcher, CardVaultEventButtonRight);
    }
}

static void run_action(CardVaultApp* app, CardVaultMsgAction action) {
    switch(action) {
    case MsgActionExit:
        scene_manager_stop(app->scene_manager);
        view_dispatcher_stop(app->view_dispatcher);
        break;
    case MsgActionRetryJob:
        scene_manager_previous_scene(app->scene_manager);
        break;
    case MsgActionPassword:
        if(!scene_manager_search_and_switch_to_previous_scene(
               app->scene_manager, CardVaultScenePassword)) {
            scene_manager_next_scene(app->scene_manager, CardVaultScenePassword);
        }
        break;
    case MsgActionStart:
        /* an aborted creation leaves an image without header: drop it */
        if(app->flow == FlowCreate && !vault_exists(app->storage)) {
            storage_common_remove(app->storage, VAULT_IMAGE_PATH);
        }
        scene_manager_search_and_switch_to_previous_scene(app->scene_manager, CardVaultSceneStart);
        break;
    }
}

void card_vault_scene_message_on_enter(void* context) {
    CardVaultApp* app = context;
    widget_reset(app->widget);
    widget_add_string_element(
        app->widget,
        64,
        0,
        AlignCenter,
        AlignTop,
        FontPrimary,
        furi_string_get_cstr(app->msg_title));
    if(app->msg_button) {
        widget_add_text_box_element(
            app->widget,
            0,
            13,
            128,
            38,
            AlignCenter,
            AlignCenter,
            furi_string_get_cstr(app->msg_text),
            false);
        widget_add_button_element(
            app->widget, GuiButtonTypeRight, app->msg_button, button_cb, app);
    } else {
        widget_add_text_scroll_element(
            app->widget, 0, 13, 128, 51, furi_string_get_cstr(app->msg_text));
    }
    view_dispatcher_switch_to_view(app->view_dispatcher, CardVaultViewWidget);
}

bool card_vault_scene_message_on_event(void* context, SceneManagerEvent event) {
    CardVaultApp* app = context;
    if(event.type == SceneManagerEventTypeCustom && event.event == CardVaultEventButtonRight) {
        run_action(app, app->msg_action);
        return true;
    }
    if(event.type == SceneManagerEventTypeBack) {
        run_action(app, app->msg_back_action);
        return true;
    }
    return false;
}

void card_vault_scene_message_on_exit(void* context) {
    CardVaultApp* app = context;
    widget_reset(app->widget);
}
