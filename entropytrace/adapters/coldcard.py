"""entropytrace.adapters.coldcard - Coldcard-specific build-set glue.

What this adapter does, and only this: makes Coldcard's own checkout
layout resolvable by the generic `make -n` backend (board symlinks), and
supplies the documented default make variables for its one build. It
doesn't locate sinks, walk chains, classify terminals, or touch policy -
see adapters/__init__.py for the contract every adapter must follow.
"""

import os

from entropytrace.buildset import TranslationUnit, run_make_dry_run

# Boards whose top-level directories (repo_root/stm32/<BOARD>) must be
# symlinked into external/micropython/ports/stm32/boards/ before `make -n`
# can find them. Mirrors the `setup` target in stm32/shared.mk, which a
# fresh checkout has usually not run. Idempotent and side-effect-free if
# the symlinks already exist and are correct.
COLDCARD_BOARDS = ("COLDCARD", "COLDCARD_MK4", "COLDCARD_Q1")

# Default make variables the documented build always passes. Omitting
# DEBUG_BUILD=0 leaves COLDCARD_DEBUG defined but empty, which breaks any
# `#if COLDCARD_DEBUG` in the tree - not a preprocessing problem, an
# invocation bug, so it's always supplied here.
DEFAULT_MAKE_VARS = {"DEBUG_BUILD": "0", "EXCLUDE_NGU_TESTS": "1"}


def ensure_board_symlinks(repo_root: str) -> None:
    """Symlink repo_root/stm32/<BOARD> into the mpy fork's boards/ dir.

    Mirrors `make -f MK-Makefile setup` for just the board-directory step
    - the step that actually determines whether `make -n BOARD=<name>`
    can resolve BOARD_DIR at all.
    """
    boards_dir = os.path.join(
        repo_root, "external", "micropython", "ports", "stm32", "boards"
    )
    for board in COLDCARD_BOARDS:
        target = os.path.join(boards_dir, board)
        src_relative = os.path.join("..", "..", "..", "..", "..", "stm32", board)
        if os.path.islink(target) or os.path.exists(target):
            continue
        if not os.path.isdir(os.path.join(repo_root, "stm32", board)):
            continue
        os.symlink(src_relative, target)


def get_build_set(
    repo_root: str, board: str, extra_make_vars: dict[str, str] | None = None
) -> list[TranslationUnit]:
    """Coldcard-specific convenience wrapper around run_make_dry_run:
    resolves the port directory, ensures the board symlinks make -n needs
    to resolve BOARD_DIR at all, and supplies the documented default make
    variables.

    `repo_root` is a Coldcard/firmware checkout already at the commit/tag
    you want - this module doesn't check out anything, that's the
    caller's job. Runs `make -n` for real, never a full build: -n never
    executes a recipe, it only prints what it would run.
    """
    ensure_board_symlinks(repo_root)
    port_dir = os.path.join(repo_root, "external", "micropython", "ports", "stm32")
    make_vars = dict(DEFAULT_MAKE_VARS)
    make_vars["BOARD"] = board
    if extra_make_vars:
        make_vars.update(extra_make_vars)
    # make -n can print one harmless diagnostic to stderr from a variable
    # probe when no cross-compiler is installed - this doesn't affect the
    # recipe text and isn't treated as fatal here. A genuinely broken
    # BOARD_DIR (missing symlink) makes make -n itself fail with a
    # nonzero exit and an early "Invalid BOARD specified", which we do
    # surface, via fail_substring.
    return run_make_dry_run(port_dir, make_vars, fail_substring="Invalid BOARD specified")
