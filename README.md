# entropy-trace

## Work in Progress (WIP)

**Note:** This repository is actively under development. Features are incomplete, and things will break.
It is currently public for hackathon purposes only.

**Where does your wallet's randomness actually come from?**

An analyser that traces the provenance of entropy reaching key-material
generation in Bitcoin wallet codebases, across wrappers, language boundaries,
conditional compilation, etc. It then reports what source it resolves to under
each declared build configuration.

## The problem

Bitcoin wallets have repeatedly shipped with key generation that reached a
predictable source. The shape is the same every time: entropy was meant to come
from one place and came from another, and nothing in the build, the tests, or the
generated output revealed the substitution.


Three documented cases:

#### Coldcard

The hardware RNG was present and working in every device; the seed path simply
never reached it. A board configuration macro selected a software fallback, and
the guard meant to prevent exactly that tested whether the macro was *defined*
rather than what it was *set to*. Both the vulnerable and the fixed firmware
compile and link cleanly - no error, no warning, no ambiguous symbol. The only
difference is which file one function resolves to. Undetected for five years;
exploited at scale on 30 July 2026, with reported losses of 1,082-1,367 BTC.

#### Trust Wallet Core

A 32-bit seed admits roughly four billion possible mnemonics - small enough to
enumerate. The generator's output passes standard statistical randomness tests,
so the defect is invisible at the point most people would think to look for it:
the numbers themselves. Exploited December 2022 and March 2023.

#### Libbitcoin Explorer

The weak generator lived in a helper in libbitcoin-system rather than in Explorer
itself, so reading the seed command's own source would not have revealed it -
the defect was one repository away from the code under review. Disclosed in
August 2023 by the Milk Sad research group and exploited in the wild.


## Architecture

Layers:

**1. Build set:** _which source files actually compile for this build?_  
`buildset.py`. Two backends: `make -n`, which prints the compile commands without
running them, and `compile_commands.json`, which CMake emits at configure time.
Output is a list of translation units, each with its real flags. This layer exists
because you cannot analyse "the repo" - you analyse "the build." Coldcard's fix was
literally a file being swapped out of the build set, visible in `make -n` output
before any analysis runs.

**2. Preprocessing:** _what does this file actually look like once the macros are gone?_  
`symbols.py`. Runs each translation unit through a real C preprocessor - the host
compiler standing in for the cross-compiler that may not even be installed - then
walks the output with tree-sitter to record every function definition and every
extern declaration, each with its real file and line. Reading the raw source isn't
enough here: which branch of an `#if` actually compiled is exactly the kind of fact
Coldcard's bug hinged on, and that only exists after preprocessing, not before it.

**3. Resolution:** _which of these definitions does the linker actually pick?_  
`resolve.py`. Takes a symbol name and the symbol table from the step above and
decides what a real linker would have done, without running one: exactly one
external-linkage definition, none, or more than one. This is particularly important
because the Coldcard bug was invisible to anyone reading one file at a time
because it was never a fact about any single file. It was a fact about which of two
files won at link time.

**4. Classification:** _once we've reached a terminal, what kind of source is it?_  
`analysis/registry.py`, backed by `data/sources.yaml`. A small, deliberately dumb
lookup table: a symbol name or a literal substring in its body maps to one of a
handful of source classes - hardware TRNG, OS CSPRNG, library CSPRNG, non-crypto
PRNG, time-seeded, constant, user-supplied. No model, no scoring, no heuristics.
Anything not in the table comes back UNKNOWN rather than a guess, because a wrong
guess here is worse than admitting the tool doesn't know.

