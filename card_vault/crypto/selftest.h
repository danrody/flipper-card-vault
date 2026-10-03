#pragma once

#include <stdbool.h>

/* Power-on known-answer tests for SHA-512, AES-256, XTS and GCM.
 * Returns the name of the first failing test, or NULL when all pass. */
const char* crypto_selftest(void);
