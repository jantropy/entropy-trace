// Synthetic mutation case 1 (patched): the same entry point, now backed by
// an OS CSPRNG. getrandom(2), like rand() in the vulnerable variant, has no
// source definition in this build set -- both are library-terminal
// classifications by name, not by walking into a body.
#include <sys/random.h>

int generate_key_material(void) {
    unsigned int buf = 0;
    getrandom(&buf, sizeof(buf), 0);
    return (int)buf;
}
