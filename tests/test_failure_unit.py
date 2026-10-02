"""web/api/failure.py decides how a run ended and, if it failed, in which
pipeline stage. Pure unit tests: the CLI's stage markers, the exit status and
the result document go in, an outcome comes out.
"""

import os
import sys

WEB_API_DIR = os.path.join(os.path.dirname(__file__), "..", "web", "api")
sys.path.insert(0, WEB_API_DIR)

import failure  # noqa: E402



def _markers(**stages):
    """Build the CLI's stage lines for the stages given, each as a dict of
    its `done` facts. Order is the pipeline's own."""
    lines = []
    for name in failure.STAGES[1:]:
        if name not in stages:
            break
        lines.append(f"entropy-trace: stage={name} phase=start")
        facts = stages[name]
        if facts is not None:
            lines.append(
                f"entropy-trace: stage={name} phase=done" + "".join(f" {k}={v}" for k, v in facts.items())
            )
    return lines


def _findings(sinks_found=1, chains_closed=1, chains=None):
    if chains is None:  # one sink of the project's own (catalogue) kind
        chains = [{"sink_name": "own", "mechanism": "catalogue", "status": "CLASSIFIED" if chains_closed else "UNKNOWN"}] if sinks_found else []
    return {"coverage": {"sinks_found": sinks_found, "chains_closed": chains_closed, "chains": chains}}


def _classify(lines, findings=None, verified=False, backend="make", **kw):
    return failure.classify(lines=lines, exit_code=0 if findings else 1, findings=findings, verified=verified, backend=backend, **kw)


GOOD_RUN = _markers(
    build_set={"units": 120},
    preprocess={"units": 120, "failed": 2},
    sink_location={"sinks": 1},
    chain_walk={"closed": 1, "unknown": 0},
)


def test_marker_lines_are_parsed():
    trace = failure.build_trace(GOOD_RUN)
    assert trace.done["build_set"] == {"units": 120}
    assert trace.done["preprocess"] == {"units": 120, "failed": 2}
    assert trace.current is None
    assert trace.last_completed == "chain_walk"


def test_a_stage_that_started_and_never_finished_is_the_current_one():
    trace = failure.build_trace(_markers(build_set={"units": 5}, preprocess=None))
    assert trace.current == "preprocess"


def test_verified_ref_that_completes_is_a_normal_result():
    out = _classify(GOOD_RUN, _findings(), verified=True)
    assert out.kind == "verified_ok"


def test_unverified_ref_that_completes_gets_the_not_verified_note():
    out = _classify(GOOD_RUN, _findings(), verified=False)
    assert out.kind == "unverified_ok"
    assert "not in our verified set" in out.message
    assert "applied cleanly" in out.message


def test_build_set_failure_is_an_empty_build_set_even_though_a_result_was_written():
    lines = _markers(build_set={"units": 0}, preprocess={"units": 0, "failed": 0}, sink_location={"sinks": 1}, chain_walk={"closed": 0, "unknown": 1})
    out = _classify(lines, _findings(chains_closed=0), backend="scons", build_evidence="There is no SConstruct in core/ at this ref.")
    assert out.kind == "failed" and out.stage == "build_set"
    assert "scons --dry-run produced no compile lines" in out.message
    assert "build changed between the verified ref and this one" in out.message
    assert out.evidence == "There is no SConstruct in core/ at this ref."


def test_build_set_message_names_the_backend_that_ran():
    for backend, tool in (("make", "make -n"), ("compile_commands", "the CMake configure"), ("scons", "scons --dry-run")):
        out = _classify(_markers(build_set={"units": 0}), None, backend=backend)
        assert tool in out.message


def test_build_set_crash_is_attributed_to_the_stage_that_was_running():
    out = _classify(["entropy-trace: stage=build_set phase=start", "Traceback (most recent call last):", "FileNotFoundError: 'scons'"])
    assert out.stage == "build_set"
    assert "FileNotFoundError" in out.detail


def test_preprocessing_failure_when_no_translation_unit_preprocessed():
    lines = _markers(build_set={"units": 40}, preprocess={"units": 40, "failed": 40})
    out = _classify(lines, _findings())
    assert out.kind == "failed" and out.stage == "preprocess"
    assert "no translation unit preprocessed" in out.message
    assert "generated headers" in out.message


def test_some_preprocess_failures_are_not_a_preprocessing_failure():
    lines = _markers(build_set={"units": 40}, preprocess={"units": 40, "failed": 39}, sink_location={"sinks": 1}, chain_walk={"closed": 1, "unknown": 0})
    assert _classify(lines, _findings()).kind == "unverified_ok"


def test_sink_location_failure_when_nothing_was_found():
    lines = _markers(build_set={"units": 40}, preprocess={"units": 40, "failed": 0}, sink_location={"sinks": 0}, chain_walk={"closed": 0, "unknown": 0})
    out = _classify(lines, _findings(sinks_found=0, chains_closed=0))
    assert out.kind == "failed" and out.stage == "sink_location"
    assert "no entropy-critical sink was found" in out.message
    assert "moved or was renamed" in out.message


def test_sink_location_failure_when_only_the_structural_anchor_matched():
    """Coldcard at an old tag: the BIP-32 anchor still matches (and is
    unresolvable by design), but generate_seed is gone. That is the entry
    point having moved, not a chain that could not be followed."""
    anchor = [{"sink_name": "s_hdnode_from_master", "mechanism": "structural_anchor", "status": "UNKNOWN", "broke_at_hop": "master_secret_in"}]
    lines = _markers(build_set={"units": 40}, preprocess={"units": 40, "failed": 0}, sink_location={"sinks": 1}, chain_walk={"closed": 0, "unknown": 1})
    out = _classify(lines, _findings(chains_closed=0, chains=anchor), sink_evidence="shared/seed.py exists at this ref but does not define generate_seed.")
    assert out.kind == "failed" and out.stage == "sink_location"
    assert "only the BIP-32 structural anchor matched" in out.detail
    assert out.evidence == "shared/seed.py exists at this ref but does not define generate_seed."


def test_chain_walk_failure_names_the_projects_own_sink_not_the_anchor():
    chains = [
        {"sink_name": "s_hdnode_from_master", "mechanism": "structural_anchor", "status": "UNKNOWN", "broke_at_hop": "master_secret_in"},
        {"sink_name": "generate_seed", "mechanism": "catalogue", "status": "UNKNOWN", "broke_at_hop": "ngu.random.bytes", "unknown_reason": "no MP_REGISTER_MODULE found for 'ngu'"},
    ]
    out = _classify(GOOD_RUN, _findings(sinks_found=2, chains_closed=0, chains=chains))
    assert out.stage == "chain_walk" and out.broke_at == "ngu.random.bytes"
    assert "generate_seed" in out.detail


def test_chain_walk_failure_reports_the_exact_hop_it_broke_at():
    chains = [{"sink_name": "reset_device", "mechanism": "catalogue", "status": "UNKNOWN", "broke_at_hop": "random.bytes", "unknown_reason": "no MP_REGISTER_MODULE found for 'random'"}]
    out = _classify(GOOD_RUN, _findings(chains_closed=0, chains=chains))
    assert out.kind == "failed" and out.stage == "chain_walk"
    assert "chain could not be followed" in out.message
    assert out.broke_at == "random.bytes"
    assert "no MP_REGISTER_MODULE" in out.detail


def test_a_verified_ref_with_an_unknown_chain_is_a_result_not_a_failure():
    """Passport's and Trezor's own honest UNKNOWNs are results: an
    unclosed chain only counts as a failure for a ref that was never run."""
    chains = [{"sink_name": "new_seed_task", "mechanism": "catalogue", "status": "UNKNOWN", "broke_at_hop": "new_seed_task"}]
    out = _classify(GOOD_RUN, _findings(chains_closed=0, chains=chains), verified=True)
    assert out.kind == "verified_ok"


def test_a_partly_closed_unverified_run_is_a_success_with_a_note():
    out = _classify(GOOD_RUN, _findings(sinks_found=2, chains_closed=1), verified=False)
    assert out.kind == "unverified_ok"


def test_prepare_failure_never_reaches_the_pipeline_stages():
    out = _classify([], None, prepare_error="prepare step failed (exit 1): cmake -S . -B build")
    assert out.kind == "failed" and out.stage == "prepare"
    assert "exit 1" in out.detail


def test_verified_ref_failures_do_not_claim_the_project_changed():
    out = _classify(_markers(build_set={"units": 0}), None, verified=True)
    assert "environment problem" in out.message
    assert "build changed" not in out.message


def test_timeout_names_the_stage_it_stopped_in():
    lines = _markers(build_set={"units": 40}, preprocess=None)
    out = _classify(lines, None, timed_out=True, timeout=600)
    assert out.kind == "failed" and out.stage == "preprocess"
    assert "600s" in out.message


def test_a_crash_after_the_chain_walk_is_the_catch_all():
    lines = GOOD_RUN + ["ProfileError: declares config_values entry 'X'"]
    out = failure.classify(lines=lines, exit_code=1, findings=None, verified=False, backend="make")
    assert out.kind == "failed" and out.stage == "unexpected"
    assert "ProfileError" in out.detail


def test_no_failure_message_shows_a_stack_trace_or_the_old_file_name():
    for stage in ("prepare", "build_set", "preprocess", "sink_location", "chain_walk", "unexpected"):
        for verified in (True, False):
            msg = failure._message(stage, verified, "make", False, 0)
            assert "Traceback" not in msg and "findings.json" not in msg
