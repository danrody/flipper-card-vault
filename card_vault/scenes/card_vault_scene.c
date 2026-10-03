#include "card_vault_scene.h"

#define ADD_SCENE(prefix, name, id) prefix##_scene_##name##_on_enter,
static void (*const card_vault_on_enter_handlers[])(void*) = {
#include "card_vault_scene_config.h"
};
#undef ADD_SCENE

#define ADD_SCENE(prefix, name, id) prefix##_scene_##name##_on_event,
static bool (*const card_vault_on_event_handlers[])(void* context, SceneManagerEvent event) = {
#include "card_vault_scene_config.h"
};
#undef ADD_SCENE

#define ADD_SCENE(prefix, name, id) prefix##_scene_##name##_on_exit,
static void (*const card_vault_on_exit_handlers[])(void* context) = {
#include "card_vault_scene_config.h"
};
#undef ADD_SCENE

const SceneManagerHandlers card_vault_scene_handlers = {
    .on_enter_handlers = card_vault_on_enter_handlers,
    .on_event_handlers = card_vault_on_event_handlers,
    .on_exit_handlers = card_vault_on_exit_handlers,
    .scene_num = CardVaultSceneNum,
};
