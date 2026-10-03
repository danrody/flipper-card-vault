#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* memset that the optimizer cannot elide: the asm barrier makes the
 * cleared memory observable, so dead-store elimination does not apply. */
static inline void secure_zero(void* p, size_t len) {
    memset(p, 0, len);
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

/* Constant-time comparison; returns true when equal. */
static inline int secure_equal(const void* a, const void* b, size_t len) {
    const volatile uint8_t* x = a;
    const volatile uint8_t* y = b;
    uint8_t acc = 0;
    for(size_t i = 0; i < len; i++) {
        acc |= x[i] ^ y[i];
    }
    return acc == 0;
}
