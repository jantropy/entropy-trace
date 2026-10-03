| Project | Build backend | Sink | Mechanism | Shape | Coverage | UNKNOWN | Result |
|---|---|---|---|---|---|---|---|
| Coldcard (coldcard-vulnerable.yaml) | make (adapter: coldcard) | s_hdnode_from_master (boards/COLDCARD_MK4/c-modules/libngu/hdnode.c:297) | structural_anchor | single | 50.0% | 1 | UNKNOWN (stopped at master_secret_in) |
| Coldcard (coldcard-vulnerable.yaml) | make (adapter: coldcard) | generate_seed (shared/seed.py:602) | catalogue | single | 50.0% | 1 | NON_CRYPTO_PRNG |
| Coldcard (coldcard-patched.yaml) | make (adapter: coldcard) | s_hdnode_from_master (boards/COLDCARD_MK4/c-modules/libngu/hdnode.c:297) | structural_anchor | single | 50.0% | 1 | UNKNOWN (stopped at master_secret_in) |
| Coldcard (coldcard-patched.yaml) | make (adapter: coldcard) | generate_seed (shared/seed.py:602) | catalogue | single | 50.0% | 1 | HW_TRNG |
| Trust Wallet Core (trustwallet-vulnerable.yaml) | compile_commands | random32 (wasm/src/Random.cpp:14) | catalogue | single | 100.0% | 0 | NON_CRYPTO_PRNG |
| Trust Wallet Core (trustwallet-vulnerable.yaml) | compile_commands | random_buffer (wasm/src/Random.cpp:19) | catalogue | single | 100.0% | 0 | NON_CRYPTO_PRNG |
| Trust Wallet Core (trustwallet-patched.yaml) | compile_commands | random32 (wasm/src/Random.cpp:78) | catalogue | single | 0.0% | 2 | UNKNOWN (stopped at random32) |
| Trust Wallet Core (trustwallet-patched.yaml) | compile_commands | random_buffer (wasm/src/Random.cpp:83) | catalogue | single | 0.0% | 2 | UNKNOWN (stopped at random_buffer) |
| libsodium (libsodium.yaml) | make | crypto_sign_ed25519_keypair (src/libsodium/crypto_sign/ed25519/ref10/keypair.c:33) | catalogue | single | 100.0% | 0 | LIB_CSPRNG |
| Trezor (core/v2.9.2) (trezor.yaml) | scons | reset_device (core/src/apps/management/reset_device/__init__.py:33) | catalogue | single | 100.0% | 0 | NON_CRYPTO_PRNG |
| Trezor (core/v2.9.2) (trezor-firmware.yaml) | scons | reset_device (core/src/apps/management/reset_device/__init__.py:33) | catalogue | single | 0.0% | 1 | UNKNOWN (stopped at syscall_invoke2) |
| Trezor (core/v2.9.2) (trezor-kernel.yaml) | scons | rng_fill_buffer_strong (core/embed/sec/rng/rng_common.c:37) | catalogue | single | 100.0% | 0 | HW_TRNG |
