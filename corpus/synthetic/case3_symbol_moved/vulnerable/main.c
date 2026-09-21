// Synthetic mutation case 3 (spike/PHASE_D.md, D1): the Coldcard shape
// (rng_get() resolving to a different translation unit depending on which
// tree is analysed, spike/PHASE_B.md) minimized to its essence -- the same
// extern call, cross-TU, resolving to whichever .c file this variant's
// Makefile happens to compile alongside it.
extern int get_random(void);

int generate_seed_bytes(void) {
    return get_random();
}
