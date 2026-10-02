import os

from entropytrace.cli import main, run_profile

CASE = os.path.join(
    os.path.dirname(__file__), "..", "corpus", "synthetic", "case1_csprng_swap", "vulnerable", "ci-profile.yaml"
)


def test_run_profile_reports_each_stage_in_order_with_facts():
    seen = []
    run_profile(CASE, progress=lambda stage, phase, **facts: seen.append((stage, phase, facts)))
    assert [(s, p) for s, p, _ in seen] == [
        ("build_set", "start"), ("build_set", "done"),
        ("preprocess", "start"), ("preprocess", "done"),
        ("sink_location", "start"), ("sink_location", "done"),
        ("chain_walk", "start"), ("chain_walk", "done"),
    ]
    done = {s: facts for s, p, facts in seen if p == "done"}
    assert done["build_set"] == {"units": 1}
    assert done["preprocess"] == {"units": 1, "failed": 0}
    assert done["sink_location"] == {"sinks": 1}
    assert done["chain_walk"] == {"closed": 1, "unknown": 0}


def test_run_profile_without_progress_is_unchanged():
    assert run_profile(CASE)["policy"]["overall_verdict"] == "FAIL"


def test_report_stages_prints_to_stderr_only_when_asked(tmp_path, capsys):
    out = str(tmp_path / "result.json")
    main(["--profile", CASE, "--output", out, "--report-stages"])
    captured = capsys.readouterr()
    assert "entropy-trace: stage=build_set phase=start" in captured.err
    assert "entropy-trace: stage=chain_walk phase=done closed=1 unknown=0" in captured.err
    assert "stage=" not in captured.out

    main(["--profile", CASE, "--output", out])
    assert "stage=" not in capsys.readouterr().err
