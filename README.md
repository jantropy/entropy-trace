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

**5. Sink location:** _where does key material actually get generated?_  
`analysis/sinks.py`. Two ways in: a small YAML catalogue of named entry points
(`data/sinks.yaml`) for cases with no distinguishing feature to anchor on, and
structural anchors - a literal constant that only ever shows up at one semantic
spot in a real wallet codebase. Only one anchor is implemented: BIP-32's
`"Bitcoin seed"` HMAC key, checked directly against a real tree before writing
any code for it. A second candidate (BIP-39's salt prefix) was checked the same
way and never actually appears in production source, so it isn't implemented at
all rather than faked.

**6. The Python/C boundary:** _the seed call is Python; the bug is in C. How do
you cross that?_  
`adapters/micropython.py`. Coldcard's `generate_seed()` calls `ngu.random.bytes`,
a dotted Python attribute with no source of its own - it's bound to a real C
function through MicroPython's own module-registration machinery. This module
walks that machinery backwards: given a dotted name, it resolves the actual C
function it calls, by recognising the same four struct shapes MicroPython's
build always produces. Anything outside those four shapes comes back an
explicit UNKNOWN, never a guess.

`adapters/` holds a second, different kind of adapter too: `coldcard.py` does
nothing about Python or C at all - it just symlinks board directories into
place and supplies the make variables Coldcard's build always passes, so the
generic `make -n` backend from layer 1 can run against Coldcard's checkout
without any of that being layer 1's problem.

**7. The backward slice:** _tying it all together - walk from the sink until you
hit something classifiable._  
`analysis/slice.py`. Starts at a sink, and for each call it makes, decides
whether to cross the FFI boundary, resolve it as a local definition, or hand it
to the linker-resolution step - checking the registry at every hop before
following it further. This is the actual trace: sink -> `ngu.random.bytes` ->
`random_bytes` -> `my_random_bytes` -> `rng_get` -> whichever file wins at link
time. Every hop that can't be followed comes back an explicit UNKNOWN with a
reason, never a plausible-looking guess at what happens next.

**8. Policy:** _given where a chain ended up, does that pass?_  
`analysis/policy.py`. A plain lookup table: (mode, terminal category) -> PASS,
WARN, or FAIL. Nothing here re-derives a verdict from a category by hand
anywhere else in the project - SARIF, the HTML report, CI's exit code, and the
web UI all read the one `policy` object this module builds. A PASS only means
a sink resolved, under this mode, to a source class the policy accepts - never
that the resulting keys are actually safe.

**9. The profile:** _what does "analyse this project" actually mean, in one file?_  
`profiles.py`. A profile YAML says where the checkout lives, how to get its build
set (plain `make -n`, `compile_commands.json`, or a named adapter), which target
macros and sysroot apply, and which sinks to look for beyond the shared catalogue.
Loading one never silently fills in a missing field - a profile that's missing
something required fails with the exact field name, not a guess.

**10. The entrypoint:** _run everything above as one command._  
`cli.py`. Loads a profile, runs every layer above it in order, and writes out
`findings.json` plus a SARIF file - the same two artifacts a GitHub Action would
attach to a pull request. This is the actual tool: `python -m entropytrace.cli
--profile <profile.yaml> --output findings.json` runs the whole pipeline end to
end and exits non-zero on a real finding, tested here against four small,
self-contained corpus cases under `corpus/synthetic/` (a swapped CSPRNG, a
flipped build macro, a symbol resolving to a different file depending on the
build, and a deterministic nonce that must never be flagged at all).

**11. Output:** _turn a finding into something a human or a CI system can act on._  
`emit/sarif.py`. A pure function of `findings.json` - reads it, writes SARIF
2.1.0, the format GitHub code scanning understands natively. One result per
entropy-critical sink, checked against the official SARIF schema rather than a
hand-guessed shape. Sysroot provenance (was this analysed against a real target,
or the host's own headers?) lives at the run level, not attached to any one
result - it's context about how the analysis ran, not a finding of its own.

`emit/report.py` does the same job for a person instead of a CI system: one
self-contained HTML file, no CDN, no external fonts, nothing loaded over the
network - it has to open correctly straight off disk. A hop that couldn't be
classified renders as its own hollow, dashed state, never red and never the
same colour as a real failure, because uncertainty isn't a failure and must
never be drawn like one.

## The real cases, computed

`fixtures/` holds the actual, computed `findings.json` (plus SARIF and HTML)
for both real incidents described above, at both the vulnerable and patched
commit - not hand-typed, not simulated. `corpus/` holds the evidence each
one is built from: real commit SHAs, real code quoted from the actual repos,
confidence levels, and what was and wasn't independently verified.
`profiles/` holds the profile YAML that produced each fixture - the same
kind of file `cli.py` takes for any project.

libsodium's fixture is there too - the held-out generalisation test: a real,
general-purpose crypto library, never examined before it was added, run
through the exact same pipeline as the two disclosed vulnerabilities, with
a clean result (its own randomness call resolves to a real library CSPRNG).
A clean result is a good result; the point wasn't to find a third bug; it
was to check whether the tool actually generalises past the two cases it was
built against, or just happened to fit them.

## Running the tests

```
pytest                    # full suite
pytest -m "not slow"      # fast suite - skips the tests that need a real,
                           # full-size checkout on disk
```

Most of this project's own tests are self-contained - synthetic C sources,
hand-built symbol tables, the small corpus under `corpus/synthetic/`. A
handful genuinely need a real checkout of Coldcard's firmware or Trust
Wallet Core sitting on disk at a path this project doesn't ship (see each
differential test file's own docstring for how to set one up) - those are
skipped automatically when the checkout isn't present, and marked `slow`
so a normal test run doesn't wait on them even when it is.

