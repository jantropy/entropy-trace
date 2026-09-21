"""entropytrace.cli - profile-driven pipeline entrypoint.

Glue, not new analysis: every step here already exists (buildset.py's two
backends, symbols.py, analysis/{sinks,slice,registry,policy}.py,
emit/sarif.py). This module just loads a profile and orchestrates the
pipeline steps around it.
"""

import argparse
import datetime
import json
import os
import sys

from entropytrace.analysis.policy import evaluate as evaluate_policy
from entropytrace.analysis.sinks import (
    find_bip32_master_seed_sink,
    locate_c_catalogue_sink,
    locate_python_catalogue_sink,
)
from entropytrace.analysis.slice import slice_from_sink
from entropytrace.emit.sarif import build_sarif
from entropytrace.profiles import (
    PROJECT_ROOT,
    Profile,
    build_translation_units,
    load_catalogue_for_profile,
    load_profile,
    load_registry_for_profile,
    resolve_config_values,
)
from entropytrace.symbols import build_symbol_index, get_sysroot_provenance


def _effective_make_vars(profile: Profile) -> dict:
    """The build variables to report in findings.json's build_profile,
    honest about where they actually come from - not always
    profile.build.get("make_vars", {}), because a coldcard-adapter
    profile never redeclares the adapter's own DEFAULT_MAKE_VARS in its
    own YAML. BOARD itself is excluded since it's already reported
    separately via build_profile.board."""
    if profile.adapter == "coldcard":
        from entropytrace.adapters.coldcard import DEFAULT_MAKE_VARS

        merged = dict(DEFAULT_MAKE_VARS)
        merged.update(profile.build.get("extra_make_vars", {}))
        return merged
    return profile.build.get("make_vars", {})


def _serialize_chain(hops) -> list[dict]:
    chain = []
    for i, hop in enumerate(hops):
        verdict = None
        if hop.kind == "c_call":
            verdict = "RESOLVED" if hop.detail == "resolve()" else ("local" if hop.detail == "local" else None)
        chain.append(
            {
                "index": i,
                "kind": hop.kind,
                "symbol": hop.symbol,
                "file": hop.file,
                "line": hop.line,
                "detail": hop.detail,
                "resolution_verdict": verdict,
            }
        )
    return chain


def _locate_sink(entry: dict, repo_root: str, build_dir: str = ""):
    if entry["language"] == "python":
        return locate_python_catalogue_sink(entry, repo_root)
    return locate_c_catalogue_sink(entry, repo_root, build_dir)


def _prefix_build_dir(path: str | None, build_dir: str) -> str | None:
    """Rebase a build.dir-relative path back to repo-root-relative, so
    findings.json reports every project's paths the same way regardless
    of whether its profile needed build.dir.

    locate_c_catalogue_sink and every c_call Hop's file are build.dir-
    relative for such a profile, matching TranslationUnit.source (needed
    so preprocess_tu's cwd=tu.cwd resolves correctly) - slice.py's
    matching logic and TranslationUnit.source aren't touched here, this
    only affects what gets written into findings.json's own fields. A
    no-op when build_dir is "" (every profile without it) or path is None
    (a library call with no source).
    """
    if not build_dir or path is None:
        return path
    return os.path.join(build_dir, path)


def _normalize_build_dir_paths(chains: list[dict], build_dir: str) -> None:
    """Rebase every path-bearing field in a findings.json chains list in
    place: each entry's own file, and every hop's file inside its chain.
    Not applied to config_values[].file (already repo_root-relative by
    definition) or target_macros (relative to this project's own root, a
    different path space entirely)."""
    if not build_dir:
        return
    for entry in chains:
        entry["file"] = _prefix_build_dir(entry["file"], build_dir)
        for hop in entry["chain"]:
            hop["file"] = _prefix_build_dir(hop.get("file"), build_dir)


def run_profile(profile_path: str, mode: str = "pr", stub_dir: str | None = None) -> dict:
    """Run the whole pipeline for one profile YAML and return the
    findings.json dict (with `policy` already attached). Writes nothing;
    callers decide what to do with the result."""
    profile = load_profile(profile_path)

    stub_dir = stub_dir or profile.stub_dir
    if stub_dir is None:
        stub_dir = os.path.join(profile.repo_root, ".entropytrace-stub")
    os.makedirs(stub_dir, exist_ok=True)

    units = build_translation_units(profile)
    symbol_index = build_symbol_index(units, stub_dir, **profile.target_kwargs)
    registry = load_registry_for_profile(profile)

    found_sinks = []
    if profile.run_bip32_anchor:
        anchor = find_bip32_master_seed_sink(units, stub_dir, **profile.target_kwargs)
        if anchor is not None:
            found_sinks.append(anchor)
    for entry in load_catalogue_for_profile(profile):
        sink = _locate_sink(entry, profile.repo_root, profile.build.get("dir", ""))
        if sink is not None:
            found_sinks.append(sink)

    chains = []
    results = []
    for sink in found_sinks:
        result = slice_from_sink(sink, profile.repo_root, units, symbol_index, registry, stub_dir, **profile.target_kwargs)
        results.append(result)
        entry = {
            "sink_name": sink.name,
            "sink_category": sink.category.value,
            "entropy_critical": sink.entropy_critical,
            "mechanism": sink.mechanism,
            "file": sink.file,
            "line": sink.line,
            "status": result.status,
            "chain": _serialize_chain(result.hops),
        }
        if result.status == "CLASSIFIED":
            entry["terminal_category"] = result.classification.category.value
        else:
            entry["unknown_reason"] = result.unknown_reason
            entry["broke_at_hop"] = result.hops[-1].symbol if result.hops else sink.entry_symbol
        chains.append(entry)

    # Normalize build.dir-relative paths back to repo_root-relative here,
    # once, so findings.json itself is consistent and every emitter
    # inherits it without needing to know about build.dir at all.
    _normalize_build_dir_paths(chains, profile.build.get("dir", ""))

    closed = sum(1 for e in chains if e["status"] == "CLASSIFIED")
    by_category: dict[str, int] = {}
    for sink in found_sinks:
        by_category[sink.category.value] = by_category.get(sink.category.value, 0) + 1

    coverage = {
        "sinks_found": len(found_sinks),
        "sinks_found_by_category": by_category,
        "chains_closed": closed,
        "chains_unknown": len(found_sinks) - closed,
        "percentage_resolved": round(100.0 * closed / len(found_sinks), 1) if found_sinks else 0.0,
        "chains": chains,
    }

    if found_sinks:
        # A catalogue entry is a project's own declared, intended entry
        # point; the BIP-32 structural anchor is a supplementary
        # heuristic that opportunistically traces a different semantic
        # target when a distinguishing literal exists. The top-level
        # head sink/chain/terminal/status fields reflect the project's
        # actual primary finding - fall back to found_sinks[0] only when
        # no catalogue sink exists.
        head_idx = next((i for i, s in enumerate(found_sinks) if s.mechanism == "catalogue"), 0)
        head_sink, head_result, head_entry = found_sinks[head_idx], results[head_idx], chains[head_idx]
        head_chain = head_entry["chain"]
        head_terminal = (
            {
                "symbol": head_chain[-1]["symbol"] if head_chain else head_sink.entry_symbol,
                "category": head_result.classification.category.value,
                "matched_entry": head_result.classification.matched_entry,
                "match_kind": head_result.classification.match_kind,
            }
            if head_result.status == "CLASSIFIED"
            else None
        )
        head_sink_obj = {
            "name": head_sink.name,
            "language": head_sink.language,
            # head_entry["file"] is the already-rebased twin of
            # head_sink.file (both come from the same Sink.file) - reused
            # here instead of rebasing a second time, so there's exactly
            # one place this happens.
            "file": head_entry["file"],
            "line": head_sink.line,
            "category": head_sink.category.value,
            "entropy_critical": head_sink.entropy_critical,
            "mechanism": head_sink.mechanism,
        }
        head_status = head_entry["status"]
        head_unknown_reason = head_entry.get("unknown_reason")
        unknown_count = 1 if head_status == "UNKNOWN" else 0
    else:
        head_chain, head_terminal, head_sink_obj = [], None, None
        head_status, head_unknown_reason, unknown_count = "UNKNOWN", "no sinks found in this profile", 0

    # profile.target_kwargs is {} for "unset, use the callee's own
    # default" and {"target_yaml": ...} otherwise - both an unset
    # target_yaml and an explicit null report the same honest "no target
    # macro table, no sysroot" findings fields.
    target_yaml = profile.target_kwargs.get("target_yaml")
    # load_profile() resolves a relative target_yaml to an absolute path
    # so it works regardless of cwd - relativize it back against this
    # project's own root before storing, so findings.json doesn't leak
    # this machine's absolute directory layout.
    target_macros = os.path.relpath(target_yaml, PROJECT_ROOT) if target_yaml else None

    findings = {
        "schema_version": "1.3.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "label": profile.label or os.path.basename(profile.repo_root),
        "build_profile": {
            "repo": profile.repo or profile.repo_root,
            "commit": profile.commit or "unknown",
            "board": profile.board or profile.build.get("backend", "make"),
            "make_vars": _effective_make_vars(profile),
            **({"target_macros": target_macros} if target_macros else {}),
            "sysroot": get_sysroot_provenance(target_yaml),
        },
        "sink": head_sink_obj,
        "config_values": resolve_config_values(profile),
        "chain": head_chain,
        "terminal": head_terminal,
        "status": head_status,
        "unknown_reason": head_unknown_reason,
        "confidence": "high" if head_status == "CLASSIFIED" else "low",
        "unknown_count": unknown_count,
        "coverage": coverage,
    }
    findings["policy"] = evaluate_policy(findings, mode=mode)
    return findings


def exit_code_for(overall_verdict: str, mode: str) -> int:
    """Non-zero on FAIL always; non-zero on WARN only in audit mode; zero
    otherwise. A pure function of the two strings, so tests can exercise
    this directly without Docker."""
    if overall_verdict == "FAIL":
        return 1
    if overall_verdict == "WARN":
        return 1 if mode == "audit" else 0
    return 0


def write_step_summary(findings: dict, path: str) -> None:
    """Markdown for $GITHUB_STEP_SUMMARY: coverage numbers, then every
    finding's chain in short form."""
    cov = findings["coverage"]
    policy = findings["policy"]
    lines = [
        f"# Entropy Trace -- {findings.get('label', '')}",
        "",
        f"**Overall verdict: {policy['overall_verdict']}** (mode: {policy['mode']})",
        "",
        "## Coverage",
        "",
        f"- Sinks found: {cov['sinks_found']}",
        f"- Chains closed: {cov['chains_closed']}",
        f"- Chains unknown: {cov['chains_unknown']}",
        f"- Percentage resolved: {cov['percentage_resolved']}%",
        "",
        "## Findings",
        "",
    ]
    verdict_by_name = {v["sink_name"]: v["verdict"] for v in policy["verdicts"]}
    for entry in cov["chains"]:
        verdict = verdict_by_name.get(entry["sink_name"], "n/a (not entropy-critical)")
        terminal = entry.get("terminal_category", entry.get("unknown_reason", "UNKNOWN"))
        chain_str = " -> ".join(h["symbol"] for h in entry.get("chain", [])) or "(no hops traced)"
        lines.append(f"- **{entry['sink_name']}** ({entry['file']}:{entry['line']}) -- {verdict}: {terminal}")
        lines.append(f"  - chain: {chain_str}")
    with open(path, "a") as f:
        f.write("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Entropy Trace pipeline for one profile.")
    parser.add_argument("--profile", required=True, help="Path to a profile YAML")
    parser.add_argument("--mode", choices=["pr", "audit"], default="pr")
    parser.add_argument("--output", required=True, help="Path to write findings.json")
    parser.add_argument("--sarif-output", help="Path to write SARIF (default: <output>.sarif)")
    parser.add_argument("--step-summary", help="Path to append a Markdown step summary to")
    args = parser.parse_args(argv)

    findings = run_profile(args.profile, mode=args.mode)

    with open(args.output, "w") as f:
        json.dump(findings, f, indent=2)
        f.write("\n")

    sarif = build_sarif(findings)
    sarif_output = args.sarif_output or (os.path.splitext(args.output)[0] + ".sarif")
    with open(sarif_output, "w") as f:
        json.dump(sarif, f, indent=2)
        f.write("\n")

    step_summary_path = args.step_summary or os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_path:
        write_step_summary(findings, step_summary_path)

    overall = findings["policy"]["overall_verdict"]
    print(f"entropy-trace: overall verdict {overall} (mode={args.mode})")
    return exit_code_for(overall, args.mode)


if __name__ == "__main__":
    sys.exit(main())
