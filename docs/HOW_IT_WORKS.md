# How Entropy Trace works

This is the design write-up. For what the tool does and how to run it, see the
[README](../README.md).

## The problem, in detail

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
exploited at scale on 30 July 2026, with reported losses of about 1,800 BTC.

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

## The pipeline

The analysis is a chain of layers, each answering one question.

**1. Build set:** _which source files actually compile for this build?_  
`buildset.py`. Three backends: `make -n`, which prints the compile commands
without running them, `scons --dry-run`, the same idea for an SCons-based
build, and `compile_commands.json`, which CMake emits at configure time.
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

The anchor finds where a seed is *consumed* (the key-derivation step), not where
one is generated, and following what flows into it upstream is not implemented. An
anchor sink therefore always ends UNKNOWN today. It is reported as "not yet
traced" and takes no part in the verdict, so only sinks that generate entropy
decide PASS, WARN or FAIL. A result whose only sink is such an anchor is never a
PASS.

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

A dotted call doesn't always point straight at a registered C module, either.
`analysis/slice.py`'s `_resolve_ffi_with_fallbacks` tries two further shapes
before giving up: an import-aliased re-export (`from trezor.crypto import
random` where `trezor.crypto` itself just re-exports `trezorcrypto`'s own
module one level down), and a plain Python wrapper file sitting next to the
caller (Coldcard's `callgate.py`) - re-entering the same dotted-call walk one
level deeper inside it rather than a second, separate walker. And a dotted
call can also terminate without ever crossing into C at all: if the registry
recognises it by name (e.g. `hashlib.sha256`), the walk stops right there,
classified, the same way a bare C library call already does in `walk_c_chain`.

**7. The backward slice:** _tying it all together - walk from the sink until you
hit something classifiable._  
`analysis/slice.py`. Starts at a sink, and for each call it makes, decides
whether to cross the FFI boundary, resolve it as a local definition, or hand it
to the linker-resolution step - checking the registry at every hop before
following it further. This is the actual trace: sink -> `ngu.random.bytes` ->
`random_bytes` -> `my_random_bytes` -> `rng_get` -> whichever file wins at link
time. Every hop that can't be followed comes back an explicit UNKNOWN with a
reason, never a plausible-looking guess at what happens next.

A sink isn't always a single chain, either. Some real wallets combine more than
one independent entropy source before hashing (e.g. an MCU TRNG read
concatenated with a secure-element read). Each independent source is walked and
classified completely separately, and the sink's own result carries every one
of them - never silently collapsed into whichever happens to resolve first.

**8. Policy:** _given where a chain ended up, does that pass?_  
`analysis/policy.py`. A plain lookup table: (mode, terminal category) -> PASS,
WARN, or FAIL. Nothing here re-derives a verdict from a category by hand
anywhere else in the project - SARIF, the HTML report, CI's exit code, and the
web UI all read the one `policy` object this module builds. A PASS only means
a sink resolved, under this mode, to a source class the policy accepts - never
that the resulting keys are actually safe.

For a sink with more than one independent source, the verdict takes the
*maximum* of the contributors, not the minimum: a cryptographic transform over
a mix doesn't create entropy, it only combines what's already there, so one
genuinely good source is not weakened by a co-located bad one when the two are
independent. An UNKNOWN contributor next to a good one is no different: the
good source is enough on its own, so in pr mode the sink passes. It is never
silent, though: the verdict carries a note saying how many sources could not be
traced and which (a PASS with that caveat), and the UI, the reports, SARIF and
the CI summary all show it. audit mode keeps the strictest reading and fails it.

**9. The profile:** _what does "analyse this project" actually mean, in one file?_  
`profiles.py`. A profile says how to analyse a project (never where its checkout
is; the caller supplies that): how to get its build
set (plain `make -n`, `scons --dry-run`, `compile_commands.json`, or a named adapter), which target
macros and sysroot apply, and which sinks to look for beyond the shared catalogue.
Loading one never silently fills in a missing field - a profile that's missing
something required fails with the exact field name, not a guess.

**10. The entrypoint:** _run everything above as one step._  
`cli.py`. The engine the web runner (and the GitHub Action below) starts as a
subprocess, not an interface meant to be used by hand. Loads a profile, runs every
layer above it in order, and writes out `findings.json` plus a SARIF file - the
same two artifacts a GitHub Action would attach to a pull request. It runs the
whole pipeline end to end and exits non-zero on a real finding, tested here against four small,
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

## Adding a project

A project is described by a short profile and one entry in the allowlist:

1. `profiles/<name>.yaml` says how to read the project's build (`make`, `scons` or
   a CMake `compile_commands.json`), which target macros apply, and where seed
   generation starts (the "sink": a function name and file). It never says where
   the checkout is; the caller supplies that.
2. `data/projects.yaml` gets an entry with the project's GitHub URL, that profile,
   and the refs that have been run (with a label each). Anything not listed there
   is never cloned or analysed.
3. `docs/generate_reports.py` gets a line saying which ref each profile is a report
   of, and running it writes the static report under `docs/reports/`.

Only a project whose entropy functions the tool does not already recognise needs
more: an entry in `data/sources.yaml`, a target in `data/targets/`, or an adapter.

## The real cases, computed

`fixtures/` holds the actual, computed `findings.json` (plus SARIF and HTML)
for both real incidents described above, at both the vulnerable and patched
commit - not hand-typed, not simulated. `corpus/` holds the evidence each
one is built from: real commit SHAs, real code quoted from the actual repos,
confidence levels, and what was and wasn't independently verified.
`profiles/` holds the profile YAML that produced each fixture - the same
kind of file the runner takes for any project.

libsodium's fixture is there too - the held-out generalisation test: a real,
general-purpose crypto library, never examined before it was added, run
through the exact same pipeline as the two disclosed vulnerabilities, with
a clean result (its own randomness call resolves to a real library CSPRNG).
A clean result is a good result; the point wasn't to find a third bug; it
was to check whether the tool actually generalises past the two cases it was
built against, or just happened to fit them.

## The web runner

`web/` holds the API and the UI. The API clones an allowlisted project into
`~/.cache/entropy-trace` (set `ENTROPY_TRACE_CACHE_DIR` to move it), makes a
worktree for the ref, runs the analysis in a subprocess with a time limit, and
classifies how it ended. See [web/README.md](../web/README.md) for the API and the
details.
