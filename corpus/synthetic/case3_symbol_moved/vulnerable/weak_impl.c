// Vulnerable variant only: this is the file that actually gets compiled
// and linked alongside main.c, so get_random() resolves here.
#include <stdlib.h>

int get_random(void) {
    return rand();
}
