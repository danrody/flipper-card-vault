#include "../card_vault_i.h"

typedef struct {
    const char* label;
    uint32_t mib;
} SizeOption;

static const SizeOption SIZES[] = {
    {"128 MB", 128},
    {"512 MB", 512},
    {"1 GB", 1024},
    {"2 GB", 2048},
    {"4 GB (max)", 4096},
};

#define SIZE_COUNT (sizeof(SIZES) / sizeof(SIZES[0]))

static uint32_t option_sectors(size_t i) {
    uint64_t sectors = (uint64_t)SIZES[i].mib * 1024 * 1024 / XTS_SECTOR_SIZE;
    return sectors > VOLUME_MAX_SECTORS ? VOLUME_MAX_SECTORS : (uint32_t)sectors;
}

static void submenu_cb(void* ctx, uint32_t index) {
    CardVaultApp* app = ctx;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void card_vault_scene_size_on_enter(void* context) {
    CardVaultApp* app = context;
    uint64_t total = 0, free_space = 0;
    storage_common_fs_info(app->storage, EXT_PATH(""), &total, &free_space);

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Vault size");
    size_t shown = 0;
    for(size_t i = 0; i < SIZE_COUNT; i++) {
        if((uint64_t)option_sectors(i) * XTS_SECTOR_SIZE + (8ULL << 20) <= free_space) {
            submenu_add_item(app->submenu, SIZES[i].label, i, submenu_cb, app);
            shown++;
        }
    }
    if(!shown) {
        submenu_add_item(app->submenu, "Not enough SD space", SIZE_COUNT, NULL, NULL);
    }
    view_dispatcher_switch_to_view(app->view_dispatcher, CardVaultViewSubmenu);
}

bool card_vault_scene_size_on_event(void* context, SceneManagerEvent event) {
    CardVaultApp* app = context;
    if(event.type != SceneManagerEventTypeCustom || event.event >= SIZE_COUNT) return false;
    app->new_sectors = option_sectors(event.event);
    app->password_stage = 0;
    scene_manager_next_scene(app->scene_manager, CardVaultScenePassword);
    return true;
}

void card_vault_scene_size_on_exit(void* context) {
    CardVaultApp* app = context;
    submenu_reset(app->submenu);
}
