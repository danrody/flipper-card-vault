#include "vault_anim.h"

#include <furi.h>
#include <gui/elements.h>
#include <stdio.h>

#define FRAME_MS      80
#define GRID_COLS     16
#define GRID_ROWS     4
#define LIFT_FRAMES   5 /* padlock opening: frames spent lifting the shackle */
#define ACTIVITY_HOLD 6 /* frames an R/W arrow stays lit after traffic */

struct VaultAnim {
    View* view;
    FuriTimer* timer;
};

typedef struct {
    VaultAnimKind kind;
    uint32_t frame;
    uint8_t progress;
    char title[32];
    char hint[48];
    uint32_t size_mb;
    uint64_t read;
    uint64_t written;
    uint64_t last_read;
    uint64_t last_written;
    uint8_t read_glow;
    uint8_t write_glow;
} VaultAnimModel;

/* Cheap deterministic hash: the "random" pictures are stable per frame. */
static inline uint32_t mix(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

/* ---------- primitives ---------- */

/* Classic pixel padlock. Body 20x15 at (x, y).
 * `lift`  raises the shackle (0 = closed).
 * `swing` offset of the free (left) leg from the pivot (right) leg:
 *         13 = closed, 0 = edge-on, -13 = swung fully open (classic 🔓). */
#define LOCK_W     20
#define LOCK_H     15
#define SHACKLE_H  11
#define SWING_FULL 13

static void draw_shackle(Canvas* canvas, int left, int right, int top, int bottom) {
    int w = right - left + 1;
    if(w <= 5) {
        /* seen edge-on: a solid bar */
        canvas_draw_box(canvas, left, top, w, bottom - top);
        return;
    }
    /* chamfered 2px arch:   ..######..
     *                       .########.
     *                       ###....###
     *                       ##......## (legs) */
    canvas_draw_box(canvas, left + 2, top, w - 4, 1);
    canvas_draw_box(canvas, left + 1, top + 1, w - 2, 1);
    canvas_draw_box(canvas, left, top + 2, 3, 1);
    canvas_draw_box(canvas, right - 2, top + 2, 3, 1);
    canvas_draw_box(canvas, left, top + 3, 2, bottom - top - 3);
    canvas_draw_box(canvas, right - 1, top + 3, 2, bottom - top - 3);
}

static void draw_padlock(Canvas* canvas, int x, int y, int lift, int swing) {
    int pivot_right = x + 16; /* rightmost column of the pivot leg */
    int free_right = pivot_right - swing;
    int left = (swing >= 0 ? free_right : pivot_right) - 1;
    int right = swing >= 0 ? pivot_right : free_right;
    int top = y - SHACKLE_H - lift;

    draw_shackle(canvas, left, right, top, y + 2 - lift);
    /* the pivot leg is longer: it never leaves the body */
    canvas_draw_box(canvas, pivot_right - 1, top + 3, 2, y + 2 - (top + 3));

    /* body with keyhole */
    canvas_draw_rbox(canvas, x, y, LOCK_W, LOCK_H, 1);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_box(canvas, x + 9, y + 4, 2, 1);
    canvas_draw_box(canvas, x + 8, y + 5, 4, 2);
    canvas_draw_box(canvas, x + 9, y + 7, 2, 4);
    canvas_set_color(canvas, ColorBlack);
}

/* Opening: lift the shackle, then swing it around the pivot leg. */
static void padlock_open_pose(uint32_t frame, int* lift, int* swing) {
    /* SWING_FULL * cos(k * 22.5 deg), k = 0..8: ~1 s for the whole opening */
    static const int8_t swing_cos[] = {13, 12, 9, 5, 0, -5, -9, -12, -13};
    if(frame < LIFT_FRAMES) {
        *lift = (int)frame * 5 / LIFT_FRAMES;
        *swing = SWING_FULL;
    } else {
        uint32_t i = frame - LIFT_FRAMES;
        if(i >= sizeof(swing_cos)) i = sizeof(swing_cos) - 1;
        *lift = 5;
        *swing = swing_cos[i];
    }
}

static void draw_progress(Canvas* canvas, const VaultAnimModel* m, int y) {
    canvas_draw_rframe(canvas, 4, y, 120, 9, 3);
    if(m->progress != VAULT_ANIM_NO_PROGRESS) {
        int w = 116 * m->progress / 100;
        if(w > 0) canvas_draw_rbox(canvas, 6, y + 2, w, 5, 1);
        char pct[8];
        snprintf(pct, sizeof(pct), "%u%%", m->progress);
        canvas_set_font(canvas, FontKeyboard);
        int tw = canvas_string_width(canvas, pct) + 4;
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_box(canvas, 64 - tw / 2, y + 1, tw, 7);
        canvas_set_color(canvas, ColorBlack);
        canvas_draw_str_aligned(canvas, 64, y + 1, AlignCenter, AlignTop, pct);
    } else {
        /* indeterminate: a bouncing segment */
        int span = 116 - 24;
        int pos = (int)(m->frame * 4 % (2 * span));
        if(pos > span) pos = 2 * span - pos;
        canvas_draw_rbox(canvas, 6 + pos, y + 2, 24, 5, 1);
    }
}

static void draw_title(Canvas* canvas, const VaultAnimModel* m) {
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 0, AlignCenter, AlignTop, m->title);
}

/* ---------- scenes ---------- */

static void draw_keys(Canvas* canvas, const VaultAnimModel* m) {
    draw_title(canvas, m);
    draw_padlock(canvas, 54, 30, 0, SWING_FULL);

    /* three dots orbiting below the lock: calm "working" indicator */
    for(int i = 0; i < 3; i++) {
        bool on = (m->frame / 3) % 3 == (uint32_t)i;
        if(on)
            canvas_draw_disc(canvas, 58 + i * 6, 47, 1);
        else
            canvas_draw_dot(canvas, 58 + i * 6, 47);
    }
    draw_progress(canvas, m, 53);
}

static void draw_card(Canvas* canvas, const VaultAnimModel* m) {

    /* NFC waves travelling from the card toward the Flipper: right halves of
     * expanding circles, clipped to the band between the two devices */
    int ox = 50, oy = 30;
    for(int i = 0; i < 3; i++) {
        int phase = (int)((m->frame + i * 4) % 12);
        if(phase < 10) canvas_draw_circle(canvas, ox, oy, 4 + phase * 3);
    }
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_box(canvas, 0, 12, ox, 40);
    canvas_draw_box(canvas, 0, 46, 128, 18);
    canvas_draw_box(canvas, 92, 12, 36, 40);
    canvas_draw_box(canvas, 0, 0, 128, 15);
    canvas_set_color(canvas, ColorBlack);
    draw_title(canvas, m);

    /* card with contactless chip */
    int cx = 8, cy = 18;
    canvas_draw_rframe(canvas, cx, cy, 38, 25, 3);
    canvas_draw_rframe(canvas, cx + 5, cy + 6, 10, 8, 1);
    canvas_draw_line(canvas, cx + 5, cy + 10, cx + 14, cy + 10);
    canvas_draw_line(canvas, cx + 10, cy + 6, cx + 10, cy + 13);
    canvas_draw_line(canvas, cx + 20, cy + 17, cx + 33, cy + 17);
    canvas_draw_line(canvas, cx + 20, cy + 20, cx + 29, cy + 20);

    /* Flipper silhouette, screen blinking while it listens */
    int fx = 96, fy = 20;
    canvas_draw_rframe(canvas, fx, fy, 28, 20, 4);
    canvas_draw_rframe(canvas, fx + 4, fy + 4, 13, 10, 1);
    canvas_draw_disc(canvas, fx + 22, fy + 9, 2);
    if((m->frame / 3) % 2) canvas_draw_box(canvas, fx + 6, fy + 6, 9, 6);

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 52, AlignCenter, AlignTop, m->hint);
}

static void draw_grid(Canvas* canvas, const VaultAnimModel* m, bool wipe) {
    draw_title(canvas, m);
    int cells = GRID_COLS * GRID_ROWS;
    int done = m->progress == VAULT_ANIM_NO_PROGRESS ? (int)(m->frame % (cells + 1)) :
                                                       m->progress * cells / 100;
    for(int i = 0; i < cells; i++) {
        int x = 4 + (i % GRID_COLS) * 7 + 2, y = 15 + (i / GRID_COLS) * 8;
        /* wipe erases cells in a scattered order, format fills them in order */
        int order = wipe ? (int)(mix(i * 2654435761U) % cells) : i;
        bool filled = wipe ? order >= done : order < done;
        bool cursor = !wipe && order == done && (m->frame / 2) % 2;
        if(filled) {
            canvas_draw_box(canvas, x, y, 6, 6);
        } else {
            canvas_draw_frame(canvas, x, y, 6, 6);
        }
        if(cursor) canvas_draw_box(canvas, x + 1, y + 1, 4, 4);
        if(wipe && !filled && (mix(i + m->frame * 31) & 7) == 0) {
            canvas_draw_dot(canvas, x + 2, y + 7 + (int)(m->frame % 3));
        }
    }
    draw_progress(canvas, m, 53);
}

static void draw_arrow(Canvas* canvas, int x, int y, bool up, bool lit) {
    if(up) {
        canvas_draw_triangle(canvas, x, y, 7, 4, CanvasDirectionBottomToTop);
    } else {
        canvas_draw_triangle(canvas, x, y, 7, 4, CanvasDirectionTopToBottom);
    }
    if(lit) canvas_draw_disc(canvas, x, up ? y + 3 : y - 3, 1);
}

static void format_mb(char* out, size_t n, uint64_t bytes) {
    uint32_t mb = (uint32_t)(bytes >> 20);
    uint32_t frac = (uint32_t)(((bytes & 0xFFFFF) * 10) >> 20);
    snprintf(out, n, "%lu.%lu MB", mb, frac);
}

static void draw_unlocked(Canvas* canvas, const VaultAnimModel* m) {
    int lift, swing;
    padlock_open_pose(m->frame, &lift, &swing);
    draw_padlock(canvas, 3, 32, lift, swing);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 38, 12, "UNLOCKED");
    canvas_set_font(canvas, FontSecondary);
    char line[32];
    snprintf(line, sizeof(line), "USB drive %lu MB", m->size_mb);
    canvas_draw_str(canvas, 38, 23, line);

    format_mb(line, sizeof(line), m->read);
    draw_arrow(canvas, 42, 30, true, m->read_glow > 0);
    canvas_draw_str(canvas, 50, 35, line);
    format_mb(line, sizeof(line), m->written);
    draw_arrow(canvas, 42, 44, false, m->write_glow > 0);
    canvas_draw_str(canvas, 50, 47, line);

    /* status bar */
    canvas_draw_line(canvas, 0, 52, 127, 52);
    canvas_set_font(canvas, FontKeyboard);
    bool busy = m->read_glow || m->write_glow;
    canvas_draw_str_aligned(
        canvas,
        64,
        55,
        AlignCenter,
        AlignTop,
        busy ? ((m->frame / 3) % 2 ? "XTS-AES-256 >>>" : "XTS-AES-256  >>") :
               "Back/unplug = lock");
}

static void draw_callback(Canvas* canvas, void* model) {
    VaultAnimModel* m = model;
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    switch(m->kind) {
    case VaultAnimKeys:
        draw_keys(canvas, m);
        break;
    case VaultAnimCard:
        draw_card(canvas, m);
        break;
    case VaultAnimFormat:
        draw_grid(canvas, m, false);
        break;
    case VaultAnimWipe:
        draw_grid(canvas, m, true);
        break;
    case VaultAnimUnlocked:
        draw_unlocked(canvas, m);
        break;
    }
}

static void timer_callback(void* ctx) {
    VaultAnim* anim = ctx;
    with_view_model(
        anim->view,
        VaultAnimModel * m,
        {
            m->frame++;
            if(m->read_glow) m->read_glow--;
            if(m->write_glow) m->write_glow--;
        },
        true);
}

static void enter_callback(void* ctx) {
    VaultAnim* anim = ctx;
    furi_timer_start(anim->timer, furi_ms_to_ticks(FRAME_MS));
}

static void exit_callback(void* ctx) {
    VaultAnim* anim = ctx;
    furi_timer_stop(anim->timer);
}

VaultAnim* vault_anim_alloc(void) {
    VaultAnim* anim = malloc(sizeof(VaultAnim));
    anim->view = view_alloc();
    view_allocate_model(anim->view, ViewModelTypeLocking, sizeof(VaultAnimModel));
    view_set_context(anim->view, anim);
    view_set_draw_callback(anim->view, draw_callback);
    view_set_enter_callback(anim->view, enter_callback);
    view_set_exit_callback(anim->view, exit_callback);
    anim->timer = furi_timer_alloc(timer_callback, FuriTimerTypePeriodic, anim);
    return anim;
}

void vault_anim_free(VaultAnim* anim) {
    furi_timer_stop(anim->timer);
    furi_timer_free(anim->timer);
    view_free(anim->view);
    free(anim);
}

View* vault_anim_get_view(VaultAnim* anim) {
    return anim->view;
}

void vault_anim_set(VaultAnim* anim, VaultAnimKind kind, const char* title, const char* hint) {
    with_view_model(
        anim->view,
        VaultAnimModel * m,
        {
            if(m->kind != kind) {
                m->frame = 0;
                m->progress = VAULT_ANIM_NO_PROGRESS;
            }
            m->kind = kind;
            strlcpy(m->title, title ? title : "", sizeof(m->title));
            strlcpy(m->hint, hint ? hint : "", sizeof(m->hint));
        },
        true);
}

void vault_anim_set_progress(VaultAnim* anim, uint8_t percent) {
    with_view_model(anim->view, VaultAnimModel * m, { m->progress = percent; }, true);
}

void vault_anim_set_drive(VaultAnim* anim, uint32_t size_mb, uint64_t read, uint64_t written) {
    with_view_model(
        anim->view,
        VaultAnimModel * m,
        {
            m->size_mb = size_mb;
            if(read != m->last_read) m->read_glow = ACTIVITY_HOLD;
            if(written != m->last_written) m->write_glow = ACTIVITY_HOLD;
            m->last_read = m->read = read;
            m->last_written = m->written = written;
        },
        false);
}
