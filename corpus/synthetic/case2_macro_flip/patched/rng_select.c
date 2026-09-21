// Synthetic mutation case 2 (spike/PHASE_D.md, D1): one source file, one
// #if, selecting a different implementation depending on a single -D flag
// -- the Coldcard shape (MICROPY_HW_ENABLE_RNG gating ports/stm32/rng.c's
// own #if/#else) minimized to its essence: same file compiles differently
// entirely because of a board-level macro, no cross-TU resolution
// involved (that's case 3).
#ifdef USE_HW_RNG
#include <sys/random.h>
int read_entropy(void) {
    unsigned int buf = 0;
    getrandom(&buf, sizeof(buf), 0);
    return (int)buf;
}
#else
#include <stdlib.h>
int read_entropy(void) {
    return rand();
}
#endif
