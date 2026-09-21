# Trivial synthetic Makefile (spike/PHASE_D.md, D1) -- shaped exactly like
# the recipe pattern buildset.py's make -n parser expects (echo "CC <file>"
# immediately followed by the compiler invocation, spike/PHASE_A.md, A3),
# so buildset.py's existing make-dry-run path works completely unchanged.
all: gen_key.o

gen_key.o: gen_key.c
	echo "CC gen_key.c"
	gcc -c -o gen_key.o gen_key.c
