# Entropy Trace

**Where does your wallet's randomness actually come from?**

Entropy Trace reads a Bitcoin wallet's source code and follows its seed generation
all the way down to whatever really supplies the randomness: a hardware random
number generator, the operating system, a library, or something it should never
be, like a plain predictable generator. Then it tells you PASS, WARN or FAIL, and
shows the exact chain of functions it followed, so you can check it yourself.

**Demo video:** _\<TODO\>_

## Why this exists

Wallets have shipped with weak randomness before, and nothing looked wrong. The
code built, the tests passed, and the output looked random. Three notable events:

- **Coldcard:** every device had a working hardware random number generator, but a
  build setting quietly made the seed code use a software fallback instead. Both
  the broken and the fixed firmware compile without a single warning. The only
  difference is which file one function ends up calling.
- **Trust Wallet Core:** the seed came from a 32-bit generator, so there were only
  about four billion possible wallets. Its output passes the usual randomness
  tests.
- **Libbitcoin Explorer:** the weak generator wasn't in the wallet's own code. It was
  in a library the wallet calls, so reviewing the wallet alone would never have
  found it.

You can't catch this by reading one file or by testing the output. You have to
follow where the randomness really comes from, which is what this tool does.

## Run it yourself

You need:

- Python 3.11 or newer
- Node 20.19 or newer
- git, make and a C compiler

Then:

```bash
git clone https://github.com/jantropy/entropy-trace
cd entropy-trace
python3 -m venv .venv
make -C web install
make -C web dev
```

Open the address the terminal prints (usually <http://localhost:5173>), paste a
GitHub address and press **Trace**:

- `https://github.com/Coldcard/firmware` traces the default branch.
- `https://github.com/Coldcard/firmware/tree/<tag>` traces a specific tag, branch or
  commit.

The first time you start it, it downloads the supported projects (about 700 MB)
in the background. After that, a run takes a minute or two.

**Supported projects:** Coldcard firmware, Trust Wallet Core and libsodium. Each one
also needs a few tools on your machine:

| Project | Also needs |
|---|---|
| Coldcard firmware | Docker (running), to fetch the ARM headers its build uses |
| Trust Wallet Core | cmake, boost and a C++ compiler (clang) |
| libsodium | autoconf, automake and libtool |

Built and tested on macOS. The analysis also runs on Linux inside the GitHub
Action below. Windows isn't supported.

More detail on the web app is in [web/README.md](web/README.md).

## Use it in your own CI

The repo is also a GitHub Action. In a wallet's repository, add a short profile that
says how to build it and where the seed is generated, then:

```yaml
- uses: actions/checkout@v4
  with:
    submodules: recursive
- uses: jantropy/entropy-trace@main
  with:
    profile: .entropy-trace/profile.yaml
    mode: pr   # "pr" fails only on a weak source; "audit" also fails when it can't tell
```

It fails the check when the randomness ends at a weak source, and it can upload its
findings to GitHub's code scanning. `.github/workflows/example-audit-with-sarif-upload.yml`
shows the full setup.

## See a result without installing anything

Each of these is a real run, saved as one HTML page. Open them from a clone of this
repo, in your browser (GitHub shows `.html` files as source).

| Project | Result | Report |
|---|---|---|
| Coldcard, the vulnerable release | **FAIL**: the seed ends at a predictable generator | [open](docs/reports/coldcard-vulnerable.html) |
| Coldcard, the fixed release | **PASS**: the seed ends at the hardware generator | [open](docs/reports/coldcard-patched.html) |
| Trust Wallet Core 3.1.0 | **FAIL** | [open](docs/reports/trustwallet-vulnerable.html) |
| Trust Wallet Core 3.1.1 | **WARN** | [open](docs/reports/trustwallet-patched.html) |
| libsodium 1.0.20 | **PASS** | [open](docs/reports/libsodium.html) |

## What the answer means

- **PASS:** the randomness ends at a source the tool accepts: hardware, the
  operating system, a well-known library, or the user.
- **WARN:** the tool couldn't follow it all the way. It says where it stopped and
  why. It never guesses.
- **FAIL:** the randomness ends at a weak source: a predictable generator, a
  constant, or the clock.

PASS does not mean "secure". It only means the randomness comes from a source the
tool accepts.

## What it can't do

- It reads **C, C++ and MicroPython** wallets built with `make` or CMake. Other
  languages (Rust, Go, and so on) aren't supported yet.
- It follows ordinary function calls. When the randomness crosses into something
  that isn't one, such as a call into a bootloader or an operating-system call, it
  stops and says so.
- Each project needs a short recipe saying how to build it and where the seed is
  generated.

## Tests

```bash
pytest -m "not slow"      # fast: offline, a few seconds
pytest --real-checkouts   # everything, including runs on real Coldcard and Trust Wallet code
```

The slow tests download those projects themselves the first time.

## How it works, and adding a project

The design, step by step, and how to add another project are in
[docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## What's where

| Folder | What's in it |
|---|---|
| `entropytrace/` | the core source code |
| `web/` | the web app: the API and the UI |
| `data/` | what counts as a hardware, OS or weak source; the supported-projects list |
| `profiles/` | the short recipe for each supported project |
| `docs/` | how it works, and the saved reports |
| `fixtures/` | saved results for the real cases |
| `corpus/` | evidence for each case, and small test wallets |
| `tests/` | the test suite |

## Licence

MIT. See [LICENSE](LICENSE). Fonts and the SARIF schema that ship with the repo keep
their own terms, listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
