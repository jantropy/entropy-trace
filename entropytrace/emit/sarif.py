"""entropytrace.emit.sarif - findings.json -> SARIF 2.1.0.

A pure function of an already-computed findings.json: reads
coverage.chains (every entropy-critical sink this project's own
mechanisms found, each already carrying its own hop-by-hop chain) and the
already-computed policy object. Runs no analysis, calls nothing else in
the engine.

Checked against the official SARIF 2.1.0 JSON schema, vendored at
fixtures/schemas/sarif-schema-2.1.0.json - not a hand-guessed shape.

One rule worth being explicit about: message text says a sink resolved
to a source class under a policy mode, or that it couldn't be resolved -
never "secure", "safe", or "verified".
"""

import argparse
import json
import os

TOOL_NAME = "EntropyTrace"
TOOL_INFORMATION_URI = "https://github.com/entropy-trace/entropy-trace"
TOOL_VERSION = "0.1.0"

# One SARIF rule per possible outcome a sink can have: the seven source
# classes, plus the pseudo-category "UNKNOWN" for a sink whose walk never
# reached a terminal at all.
_RULE_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "NON_CRYPTO_PRNG": (
        "Entropy-critical sink resolves to a non-cryptographic PRNG",
        "The traced provenance chain for this entropy-critical sink terminates in a "
        "non-cryptographic pseudo-random number generator (e.g. a Mersenne Twister or "
        "similarly seeded, statistically-uniform-but-predictable generator). This class of "
        "source is forbidden for wallet seed, private key, or security-salt generation "
        "regardless of policy mode.",
    ),
    "CONSTANT": (
        "Entropy-critical sink resolves to a constant value",
        "The traced provenance chain for this entropy-critical sink terminates in a fixed, "
        "compile-time or hardcoded value rather than any source of randomness.",
    ),
    "TIME_SEEDED": (
        "Entropy-critical sink resolves to a time-seeded source",
        "The traced provenance chain for this entropy-critical sink terminates in a source "
        "seeded from wall-clock or monotonic time, which has far less entropy than its bit "
        "width suggests and is guessable within a practical search space.",
    ),
    "UNKNOWN": (
        "Entropy-critical sink could not be resolved to a classified terminal",
        "The backward trace from this entropy-critical sink stopped before reaching a "
        "terminal this project's registry (data/sources.yaml) recognises. This is reported "
        "as its own outcome, never silently treated as a pass -- see the `unknown_reason` "
        "on the associated result for exactly what was tried and why it stopped.",
    ),
    "HW_TRNG": (
        "Entropy-critical sink resolves to a hardware TRNG",
        "The traced provenance chain for this entropy-critical sink terminates in a "
        "hardware true-random-number generator (e.g. an on-chip RNG peripheral).",
    ),
    "OS_CSPRNG": (
        "Entropy-critical sink resolves to an OS-provided CSPRNG",
        "The traced provenance chain for this entropy-critical sink terminates in an "
        "operating-system-provided CSPRNG source (e.g. "
        "getrandom(2), /dev/urandom, or a platform CSPRNG API).",
    ),
    "LIB_CSPRNG": (
        "Entropy-critical sink resolves to a library CSPRNG",
        "The traced provenance chain for this entropy-critical sink terminates in a "
        "userspace cryptographic library's random-generation API (e.g. OpenSSL's "
        "RAND_bytes, libsodium's randombytes_buf).",
    ),
    "USER_ENTROPY": (
        "Entropy-critical sink resolves to user-supplied entropy",
        "The traced provenance chain for this entropy-critical sink terminates in "
        "entropy supplied directly by the user (e.g. dice rolls, card shuffles, or "
        "similar user-provided randomness). Reported for visibility, not withheld, even "
        "though this class passes under both policy modes.",
    ),
}

_VERDICT_TO_LEVEL = {"FAIL": "error", "WARN": "warning", "PASS": "note"}


def _rule_id(category: str) -> str:
    return "entropy-trace/" + category.lower().replace("_", "-")


def _build_rules() -> list[dict]:
    rules = []
    for category, (short, full) in _RULE_DESCRIPTIONS.items():
        rules.append(
            {
                "id": _rule_id(category),
                "name": category,
                "shortDescription": {"text": short},
                "fullDescription": {"text": full},
                "help": {"text": full},
            }
        )
    return rules


def _hop_message(hop: dict, index: int) -> str:
    kind = hop.get("kind")
    symbol = hop.get("symbol")
    verdict = hop.get("resolution_verdict")
    detail = hop.get("detail") or ""
    bits = [f"hop {index}: {symbol} ({kind})"]
    if verdict:
        bits.append(f"resolution: {verdict}")
    elif detail:
        bits.append(detail)
    return " -- ".join(bits)


def _location_for(file_: str | None, line: int | None, text: str) -> dict:
    loc: dict = {"message": {"text": text}}
    if file_ is not None:
        physical: dict = {"artifactLocation": {"uri": file_}}
        if line is not None:
            physical["region"] = {"startLine": line}
        loc["physicalLocation"] = physical
    return loc


def _thread_flow_locations(entry: dict) -> list[dict]:
    """One threadFlowLocation per hop in entry["chain"], in order, plus -
    when the sink's status is UNKNOWN - one more carrying the exact
    recorded unknown_reason, anchored at the last real hop's location (or
    the sink's own declared file:line if the walk never produced a single
    hop). Never truncates an unknown hop out of the flow."""
    locations = []
    chain = entry.get("chain") or []
    for i, hop in enumerate(chain):
        locations.append({"location": _location_for(hop.get("file"), hop.get("line"), _hop_message(hop, i))})

    if entry["status"] == "UNKNOWN":
        reason = entry.get("unknown_reason") or "no reason recorded"
        if chain:
            last = chain[-1]
            anchor_file, anchor_line = last.get("file"), last.get("line")
        else:
            anchor_file, anchor_line = entry.get("file"), entry.get("line")
        locations.append(
            {"location": _location_for(anchor_file, anchor_line, f"UNKNOWN: {reason}")}
        )
    return locations


def _fingerprint(entry: dict) -> dict:
    """Sink identity + terminal classification, deliberately excluding
    line numbers, which move across commits/tags."""
    key = "|".join(
        [
            entry.get("mechanism", ""),
            entry.get("sink_category", ""),
            entry["sink_name"],
            entry["status"],
            entry.get("terminal_category") or "",
        ]
    )
    return {"entropyTrace/sinkTerminal/v1": key}


def _message_for(entry: dict, verdict: str, mode: str) -> str:
    sink_name = entry["sink_name"]
    if entry["status"] == "UNKNOWN":
        return (
            f"Entropy-critical sink '{sink_name}' could not be resolved to a classified "
            f"terminal under policy mode '{mode}': {entry.get('unknown_reason') or 'no reason recorded'}"
        )
    category = entry["terminal_category"]
    if verdict == "FAIL":
        return (
            f"Entropy-critical sink '{sink_name}' resolved to {category}, a forbidden "
            f"source class under policy mode '{mode}'."
        )
    return f"Entropy-critical sink '{sink_name}' resolved to {category} under policy mode '{mode}'."


def _result_for(entry: dict, verdict: str, mode: str) -> dict:
    status = entry["status"]
    category = entry.get("terminal_category") if status == "CLASSIFIED" else "UNKNOWN"
    rule_id = _rule_id(category)
    message_text = _message_for(entry, verdict, mode)
    return {
        "ruleId": rule_id,
        "level": _VERDICT_TO_LEVEL[verdict],
        "message": {"text": message_text},
        "locations": [_location_for(entry.get("file"), entry.get("line"), message_text)],
        "codeFlows": [{"threadFlows": [{"locations": _thread_flow_locations(entry)}]}],
        "partialFingerprints": _fingerprint(entry),
    }


def build_sarif(findings: dict) -> dict:
    """Build one SARIF 2.1.0 log (single run) from a findings.json
    document. One result per entropy-critical sink in
    findings["coverage"]["chains"]: FAIL -> level "error", WARN ->
    "warning", PASS -> "note" (so a clean run still carries evidence, not
    an empty results array). Sinks with entropy_critical=False never
    appear here, matching findings["policy"], which they're also absent
    from.

    Whether a target sysroot was used is run-level context, not a defect
    - it goes in runs[0].invocations[0].properties, never as its own
    per-result finding. executionSuccessful is always true: build_sarif
    only ever runs on a findings.json a successful pipeline run already
    produced.
    """
    policy = findings["policy"]
    mode = policy["mode"]
    verdict_by_name = {v["sink_name"]: v["verdict"] for v in policy["verdicts"]}

    results = []
    for entry in findings["coverage"]["chains"]:
        verdict = verdict_by_name.get(entry["sink_name"])
        if verdict is None:
            continue  # entropy_critical=False -- never evaluated, never reported
        results.append(_result_for(entry, verdict, mode))

    sysroot = (findings.get("build_profile") or {}).get("sysroot")

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFORMATION_URI,
                        "version": TOOL_VERSION,
                        "rules": _build_rules(),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {"sysroot": sysroot if sysroot is not None else {"used": False}},
                    }
                ],
                "results": results,
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Emit SARIF 2.1.0 from a findings.json file.")
    parser.add_argument("findings_json")
    parser.add_argument("-o", "--output", help="Output path (default: <input>.sarif)")
    args = parser.parse_args()

    with open(args.findings_json) as f:
        findings = json.load(f)

    sarif = build_sarif(findings)
    out_path = args.output or (os.path.splitext(args.findings_json)[0] + ".sarif")
    with open(out_path, "w") as f:
        json.dump(sarif, f, indent=2)
        f.write("\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
