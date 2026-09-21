// Patched variant only: get_random() moved here -- main.c is byte-identical
// to the vulnerable variant's main.c; only which .c file supplies the
// symbol changed. This is exactly the shape resolve()/walk_c_chain exist
// to catch: a clean, unambiguous, single-definition RESOLVED verdict in
// both variants, pointing at two different files.
#include <sys/random.h>

int get_random(void) {
    unsigned int buf = 0;
    getrandom(&buf, sizeof(buf), 0);
    return (int)buf;
}
