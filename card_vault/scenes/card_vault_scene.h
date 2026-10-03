#pragma once

#include <gui/scene_manager.h>

#define ADD_SCENE(prefix, name, id) CardVaultScene##id,
typedef enum {
#include "card_vault_scene_config.h"
    CardVaultSceneNum,
} CardVaultScene;
#undef ADD_SCENE

extern const SceneManagerHandlers card_vault_scene_handlers;

#define ADD_SCENE(prefix, name, id) void prefix##_scene_##name##_on_enter(void*);
#include "card_vault_scene_config.h"
#undef ADD_SCENE

#define ADD_SCENE(prefix, name, id) \
    bool prefix##_scene_##name##_on_event(void* context, SceneManagerEvent event);
#include "card_vault_scene_config.h"
#undef ADD_SCENE

#define ADD_SCENE(prefix, name, id) void prefix##_scene_##name##_on_exit(void* context);
#include "card_vault_scene_config.h"
#undef ADD_SCENE
