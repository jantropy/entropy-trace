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