# USE_HW_RNG is NOT defined here -- the #else (rand()) branch is live.
# rng_select.c is byte-identical to patched/rng_select.c -- the only
# difference between these two variants is this Makefile's -D flag.
all: rng_select.o

rng_select.o: rng_select.c
	echo "CC rng_select.c"
	gcc -c -o rng_select.o rng_select.c
