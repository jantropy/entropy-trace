"""Trezor at core/v2.9.2, against the real tree, three builds.

`reset_device` imports `from trezor.crypto import random` and calls
`random.bytes(32, True)`. Following that import (one level, through
trezor/crypto/__init__.py) reaches the registered `trezorcrypto` module and its C
function `mod_trezorcrypto_random_bytes`. What the chain does after that depends
on which build is analysed:

  * the unix EMULATOR build (profiles/trezor.yaml): the walk tries the function's
    later calls after the argument helper dead-ends, reaches `rng_fill_buffer`
    and ends at the emulator's insecure LCG. Closed, and a FAIL, because the
    emulator selects USE_INSECURE_PRNG.
  * the device FIRMWARE build (profiles/trezor-firmware.yaml): `rng_fill_buffer_strong`
    is a syscall stub, so the chain stops at the privilege boundary.
  * the device KERNEL build (profiles/trezor-kernel.yaml): the kernel's own RNG
    entry point ends at the STM32 TRNG. It is not connected to reset_device.

Skipped if the scratch checkout is missing or `scons` is not installed. Preprocesses
full build sets, so it is excluded from the fast suite by `-m "not slow"`.
"""

import os
import shutil
import sys

import pytest

from entropytrace.cli import run_profile

pytestmark = pytest.mark.slow

TREZOR_REPO = "/Users/satadel/scratch-entropy/trezor"
PROFILES = os.path.join(os.path.dirname(__file__), "..", "profiles")

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


def _run(profile: str, sink: str):
    # `scons` is installed next to this interpreter in the venv
    os.environ["PATH"] = os.path.dirname(sys.executable) + os.pathsep + os.environ["PATH"]
    findings = run_profile(os.path.join(PROFILES, profile), mode="pr")
    return findings, next(e for e in findings["coverage"]["chains"] if e["sink_name"] == sink)


@pytest.fixture(scope="module")
def emulator():
    return _run("trezor.yaml", "reset_device")


@pytest.fixture(scope="module")
def firmware():
    return _run("trezor-firmware.yaml", "reset_device")


@pytest.fixture(scope="module")
def kernel():
    return _run("trezor-kernel.yaml", "rng_fill_buffer_strong")


def _ffi(entry):
    return next(h for h in entry["chain"] if h["kind"] == "ffi")


def _assert_alias_followed(entry):
    ffi = _ffi(entry)
    assert ffi["symbol"] == "random.bytes"
    assert ffi["file"] == "core/src/apps/management/reset_device/__init__.py"
    assert ffi["line"] == 87
    assert "-> mod_trezorcrypto_random_bytes" in ffi["detail"]
    assert "resolved via 'trezorcrypto.random.bytes'" in ffi["detail"]
    assert "`random` is imported from trezor.crypto at core/src/apps/management/reset_device/__init__.py:35" in ffi["detail"]
    assert "re-exports it from trezorcrypto at core/src/trezor/crypto/__init__.py:9" in ffi["detail"]
    c_first = next(h for h in entry["chain"] if h["kind"] == "c_call")
    assert c_first["symbol"] == "mod_trezorcrypto_random_bytes"
    assert c_first["file"] == "core/embed/upymod/modtrezorcrypto/modtrezorcrypto-random.h"
    assert c_first["line"] == 49


@_needs_checkout
@_needs_scons
def test_emulator_the_alias_is_followed_and_explains_itself(emulator):
    _assert_alias_followed(emulator[1])


@_needs_checkout
@_needs_scons
def test_emulator_the_walk_skips_the_argument_helper_and_reaches_the_insecure_prng(emulator):
    findings, entry = emulator
    assert entry["status"] == "CLASSIFIED"
    assert entry["terminal_category"] == "NON_CRYPTO_PRNG"
    assert findings["policy"]["overall_verdict"] == "FAIL"  # a FAIL for the emulator build, by design
    symbols = [h["symbol"] for h in entry["chain"]]
    assert "trezor_obj_get_uint" not in symbols  # the dead-end branch is not in the chain
    assert symbols[2:] == [
        "mod_trezorcrypto_random_bytes", "rng_fill_buffer_strong", "rng_fill_buffer", "random_buffer", "lcg_get_u32",
    ]
    hops = {h["symbol"]: (h["file"], h["line"]) for h in entry["chain"]}
    assert hops["rng_fill_buffer"] == ("core/embed/sec/rng/unix/rng.c", 26)
    assert hops["lcg_get_u32"][1] == 35 and hops["lcg_get_u32"][0].endswith("rand_insecure.c")
    assert entry["entropy_shape"] == "single"


@_needs_checkout
@_needs_scons
def test_firmware_the_alias_is_followed_and_the_chain_stops_at_the_syscall_boundary(firmware):
    _, entry = firmware
    _assert_alias_followed(entry)
    assert entry["status"] == "UNKNOWN"
    stub = next(h for h in entry["chain"] if h["symbol"] == "rng_fill_buffer_strong")
    assert stub["file"] == "core/embed/sys/syscall/stm32/syscall_stubs.c"  # a stub, not the RNG
    assert entry["broke_at_hop"] == "syscall_invoke2"


@_needs_checkout
@_needs_scons
@pytest.mark.xfail(
    strict=True,
    reason=(
        "the device's RNG read is in the kernel build; following a syscall from the firmware "
        "stub into the kernel dispatcher is a boundary this tool does not resolve"
    ),
)
def test_firmware_the_reset_device_chain_reaches_the_hardware_rng(firmware):
    _, entry = firmware
    assert entry["status"] == "CLASSIFIED" and entry["terminal_category"] == "HW_TRNG"


@_needs_checkout
@_needs_scons
def test_kernel_the_devices_rng_entry_point_ends_at_the_stm32_trng(kernel):
    findings, entry = kernel
    assert entry["status"] == "CLASSIFIED"
    assert entry["terminal_category"] == "HW_TRNG"
    assert findings["policy"]["overall_verdict"] == "PASS"
    symbols = [h["symbol"] for h in entry["chain"]]
    assert symbols[:2] == ["rng_fill_buffer_strong", "rng_fill_buffer"]
    rng = next(h for h in entry["chain"] if h["symbol"] == "rng_fill_buffer")
    assert rng["file"] == "core/embed/sec/rng/stm32/rng.c"  # the device's file, not .../unix/rng.c
