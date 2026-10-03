#include "../card_vault_i.h"

static void text_input_cb(void* ctx) {
    CardVaultApp* app = ctx;
    view_dispatcher_send_custom_event(app->view_dispatcher, CardVaultEventPassword);
}

static void setup_input(CardVaultApp* app) {
    bool repeat = app->password_stage == 1;
    char* buf = repeat ? app->password_repeat : app->password;
    const char* header;

    if(app->flow == FlowUnlock) {
        header = "Vault password";
    } else if(repeat) {
        header = "Repeat password";
    } else {
        header = "New password (min 4)";
    }

    text_input_reset(app->text_input);
    text_input_set_header_text(app->text_input, header);
    text_input_set_minimum_length(app->text_input, app->flow == FlowUnlock ? 1 : VAULT_PW_MIN_LEN);
    memset(buf, 0, VAULT_PW_MAX_LEN + 1);
    text_input_set_result_callback(
        app->text_input, text_input_cb, app, buf, VAULT_PW_MAX_LEN + 1, true);
    view_dispatcher_switch_to_view(app->view_dispatcher, CardVaultViewTextInput);
}

void card_vault_scene_password_on_enter(void* context) {
    CardVaultApp* app = context;
    app->password_stage = 0;
    setup_input(app);
}

bool card_vault_scene_password_on_event(void* context, SceneManagerEvent event) {
    CardVaultApp* app = context;
    if(event.type != SceneManagerEventTypeCustom || event.event != CardVaultEventPassword)
        return false;

    if(app->flow == FlowUnlock) {
        app->job = JobUnlockPassword;
        scene_manager_next_scene(app->scene_manager, CardVaultSceneWork);
    } else if(app->password_stage == 0) {
        app->password_stage = 1;
        setup_input(app);
    } else if(strcmp(app->password, app->password_repeat) != 0) {
        card_vault_wipe_passwords(app);
        card_vault_show_message(
            app,
            "Mismatch",
            "Passwords do not match.",
            "Retry",
            MsgActionPassword,
            MsgActionStart);
    } else {
        secure_zero(app->password_repeat, sizeof(app->password_repeat));
        app->job = app->flow == FlowCreate ? JobCreatePrepare : JobRestorePrepare;
        scene_manager_next_scene(app->scene_manager, CardVaultSceneWork);
    }
    return true;
}

void card_vault_scene_password_on_exit(void* context) {
    CardVaultApp* app = context;
    text_input_reset(app->text_input);
}
