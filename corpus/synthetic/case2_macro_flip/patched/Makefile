# USE_HW_RNG=1 -- the #if branch (getrandom()) is live. rng_select.c is
# byte-identical to vulnerable/rng_select.c -- only this Makefile's -D flag
# differs.
all: rng_select.o

rng_select.o: rng_select.c
	echo "CC rng_select.c"
	gcc -DUSE_HW_RNG=1 -c -o rng_select.o rng_select.c
