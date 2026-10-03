"""Trezor at core/v2.9.2, against the real tree.

`reset_device` imports `from trezor.crypto import random` and calls
`random.bytes(32, True)`. Following that import, one level through
trezor/crypto/__init__.py, reaches the registered `trezorcrypto` module and
its C function `mod_trezorcrypto_random_bytes`. The chain then stops, for a
reason unrelated to the alias: the C walker follows the first call it can
resolve (`trezor_obj_get_uint`, a MicroPython argument-conversion helper)
and never backtracks to `rng_fill_buffer_strong` / `rng_fill_buffer`.

The first two tests pin what works and exactly where it stops. The third is
the thing this project would like to be true, kept as a strict xfail so that
fixing the walker flips it loudly instead of silently.

Skipped if the scratch checkout is missing. Preprocesses a full build set, so
it is excluded from the fast suite by `-m "not slow"`.
"""

import os
import shutil
import sys

import pytest

from entropytrace.cli import run_profile

pytestmark = pytest.mark.slow

TREZOR_REPO = "/Users/satadel/scratch-entropy/trezor"
PROFILE = os.path.join(os.path.dirname(__file__), "..", "profiles", "trezor.yaml")

def _have_scons() -> bool:
    return bool(shutil.which("scons")) or os.path.exists(os.path.join(os.path.dirname(sys.executable), "scons"))


_needs_scons = pytest.mark.skipif(not _have_scons(), reason="scons is not installed (pip install scons)")
_needs_checkout = pytest.mark.skipif(
    not os.path.isdir(os.path.join(TREZOR_REPO, "core", "src")),
    reason=(
        "scratch checkout not present: clone trezor/trezor-firmware to "
        "/Users/satadel/scratch-entropy/trezor at core/v2.9.2 (ff1c4a3) and "
        "`git submodule update --init vendor/secp256k1-zkp`"
    ),
)


@pytest.fixture(scope="module")
def trezor_entry():
    # `scons` is installed next to this interpreter in the venv
    os.environ["PATH"] = os.path.dirname(sys.executable) + os.pathsep + os.environ["PATH"]
    findings = run_profile(PROFILE, mode="pr")
    return next(e for e in findings["coverage"]["chains"] if e["sink_name"] == "reset_device")


@_needs_checkout
@_needs_scons
def test_the_import_alias_is_followed_and_explains_itself(trezor_entry):
    ffi = next(h for h in trezor_entry["chain"] if h["kind"] == "ffi")
    assert ffi["symbol"] == "random.bytes"
    assert ffi["file"] == "core/src/apps/management/reset_device/__init__.py"
    assert ffi["line"] == 87
    assert "-> mod_trezorcrypto_random_bytes" in ffi["detail"]
    assert "resolved via 'trezorcrypto.random.bytes'" in ffi["detail"]
    assert "`random` is imported from trezor.crypto at core/src/apps/management/reset_device/__init__.py:35" in ffi["detail"]
    assert "re-exports it from trezorcrypto at core/src/trezor/crypto/__init__.py:9" in ffi["detail"]

    c_first = next(h for h in trezor_entry["chain"] if h["kind"] == "c_call")
    assert c_first["symbol"] == "mod_trezorcrypto_random_bytes"
    assert c_first["file"] == "core/embed/upymod/modtrezorcrypto/modtrezorcrypto-random.h"
    assert c_first["line"] == 49


@_needs_checkout
@_needs_scons
def test_the_chain_stops_at_the_argument_helper_not_at_the_alias(trezor_entry):
    assert trezor_entry["status"] == "UNKNOWN"
    assert trezor_entry["broke_at_hop"] == "trezor_obj_get_uint"
    assert "no MP_REGISTER_MODULE" not in trezor_entry["unknown_reason"]  # the alias is no longer the problem
    assert "matched no registry entry" in trezor_entry["unknown_reason"]
    assert trezor_entry["entropy_shape"] == "single"


@_needs_checkout
@_needs_scons
@pytest.mark.xfail(
    strict=True,
    reason=(
        "walk_c_chain follows the first resolvable call (trezor_obj_get_uint) and never "
        "backtracks to rng_fill_buffer_strong; see corpus/trezor.yaml"
    ),
)
def test_the_chain_closes_end_to_end(trezor_entry):
    assert trezor_entry["status"] == "CLASSIFIED"
