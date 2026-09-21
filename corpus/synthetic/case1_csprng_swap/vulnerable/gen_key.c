// Synthetic mutation case 1 (vulnerable): a CSPRNG call swapped for a
// seeded non-crypto PRNG at the terminal. Deliberately a straight-line,
// single-call delegation -- no #if, no cross-TU resolution -- so this case
// isolates exactly the terminal-classification step from everything else
// D1's other cases already cover. `rand()` has no source definition
// anywhere in this (or any real) build set; classifying it correctly
// anyway is itself a real fix this synthetic case caught -- see
// spike/PHASE_D.md, D1.
#include <stdlib.h>

int generate_key_material(void) {
    return rand();
}
