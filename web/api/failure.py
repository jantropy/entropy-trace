"""Decide how a run ended, and if it failed, in which pipeline stage.

Three outcomes:
  verified_ok    a verified ref that completed: a normal result
  unverified_ok  an unverified ref that completed: a result, plus a note
  failed         no result; classified by the stage it stopped in

The stages are the pipeline's real ones (checkout, build set, preprocessing,
sink location, chain walk) plus one catch-all for a crash after the chain
walk. Six messages, no general error taxonomy.

Pure: it reads the CLI's stage markers (--report-stages), the exit status and
the result document. Every `detail` and `evidence` string is copied from
something the run printed or from a check made on the checkout.
"""

import dataclasses
import re

STAGES = ("prepare", "build_set", "preprocess", "sink_location", "chain_walk")

_MARKER_RE = re.compile(r"^entropy-trace: stage=(\w+) phase=(start|done)((?: \w+=\S+)*)\s*$")


@dataclasses.dataclass
class StageTrace:
    """What the CLI said about its own progress."""

    started: list[str] = dataclasses.field(default_factory=list)
    done: dict[str, dict[str, int]] = dataclasses.field(default_factory=dict)

    @property
    def current(self) -> str | None:
        """The stage that was running when the output stopped: started,
        never reported done."""
        for stage in reversed(self.started):
            if stage not in self.done:
                return stage
        return None

    @property
    def last_completed(self) -> str | None:
        for stage in reversed(self.started):
            if stage in self.done:
                return stage
        return None


def parse_marker(line: str) -> tuple[str, str, dict[str, int]] | None:
    m = _MARKER_RE.match(line)
    if not m:
        return None
    info = {k: int(v) for k, v in (kv.split("=") for kv in m.group(3).split())} if m.group(3).strip() else {}
    return m.group(1), m.group(2), info


def build_trace(lines: list[str]) -> StageTrace:
    trace = StageTrace()
    for line in lines:
        parsed = parse_marker(line)
        if parsed is None:
            continue
        stage, phase, info = parsed
        if phase == "start":
            trace.started.append(stage)
        else:
            trace.done[stage] = info
    return trace


@dataclasses.dataclass
class Outcome:
    kind: str  # "verified_ok" | "unverified_ok" | "failed"
    stage: str | None = None
    title: str = ""
    message: str = ""
    detail: str = ""  # what actually broke, copied from the run
    evidence: str = ""  # a checked fact about the checkout, when we have one
    broke_at: str | None = None  # chain-walk failures: the exact hop

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


# What a failure in each stage implies. A verified ref that fails points at
# the environment, not at the project having changed, so the wording differs.

_TITLES = {
    "prepare": "Could not prepare this checkout",
    "build_set": "No build set for this ref",
    "preprocess": "Nothing preprocessed for this ref",
    "sink_location": "No entropy-critical sink found at this ref",
    "chain_walk": "The chain could not be followed at this ref",
    "unexpected": "The analysis stopped unexpectedly",
}


def _build_tool(backend: str) -> str:
    return {
        "make": "make -n",
        "scons": "scons --dry-run",
        "compile_commands": "the CMake configure",
    }.get(backend, "the build system's dry run")


def _message(stage: str, verified: bool, backend: str, timed_out: bool, timeout: int) -> str:
    tool = _build_tool(backend)
    if stage == "prepare":
        text = (
            "Fetching this ref, checking it out or running this project's own configure step failed "
            "before any analysis started. "
        ) + (
            "This ref is verified, so this is an environment problem, not a change in the project."
            if verified
            else "That is most often a ref this project's configure step was never written for."
        )
    elif stage == "build_set":
        text = (
            f"{tool} produced no compile lines for this ref. "
            + (
                "This ref is verified, so this is an environment problem (a missing tool or an "
                "unconfigured checkout), not a change in the project."
                if verified
                else "This project's build changed between the verified ref and this one."
            )
        )
    elif stage == "preprocess":
        text = (
            "The build set resolved but no translation unit preprocessed. "
            + (
                "This ref is verified, so check the toolchain and generated headers in this environment."
                if verified
                else "Missing generated headers or a changed include layout."
            )
        )
    elif stage == "sink_location":
        text = (
            "The build preprocessed but no entropy-critical sink was found. "
            + (
                "This ref is verified, so the sink catalogue and this checkout disagree."
                if verified
                else "The entry point moved or was renamed at this ref."
            )
        )
    elif stage == "chain_walk":
        text = "The sink was found but the chain could not be followed. The exact hop it broke at is shown below."
    else:
        text = "The pipeline stopped after the chain walk, while assembling the result."
    if timed_out:
        text += f" It also hit the {timeout}s limit for a run, so it was stopped."
    return text


def _last_lines(lines: list[str], n: int = 3) -> str:
    useful = [l for l in lines if l.strip() and not l.startswith("entropy-trace: stage=")]
    return "\n".join(useful[-n:])


def classify(
    *,
    lines: list[str],
    exit_code: int | None,
    findings: dict | None,
    verified: bool,
    backend: str,
    timed_out: bool = False,
    timeout: int = 0,
    prepare_error: str | None = None,
    build_evidence: str | None = None,
    sink_evidence: str | None = None,
) -> Outcome:
    """Decide what a run was. `findings` is the parsed result document, or
    None when the CLI never wrote one."""

    def failed(stage: str, detail: str = "", broke_at: str | None = None, evidence: str = "") -> Outcome:
        return Outcome(
            "failed",
            stage,
            _TITLES[stage],
            _message(stage, verified, backend, timed_out, timeout),
            detail,
            evidence,
            broke_at,
        )

    if prepare_error is not None:
        return failed("prepare", prepare_error)

    trace = build_trace(lines)

    # Zero translation units is a build-set failure even though the CLI
    # carries on to a result: a Python sink needs no build set to be found.
    build = trace.done.get("build_set")
    if build is not None and build.get("units", 1) == 0:
        return failed("build_set", evidence=build_evidence or "")
    pre = trace.done.get("preprocess")
    if pre is not None and pre.get("units", 0) > 0 and pre.get("failed", 0) >= pre["units"]:
        return failed("preprocess", f"all {pre['units']} translation units failed to preprocess")

    if findings is None:
        # Never wrote a result: it stopped inside whichever stage was open.
        stage = trace.current
        if timed_out:
            return failed(stage or "prepare", _last_lines(lines))
        if stage in STAGES:
            evidence = (build_evidence or "") if stage == "build_set" else ""
            return failed(stage, _last_lines(lines), evidence=evidence)
        return failed("unexpected" if trace.last_completed else "prepare", _last_lines(lines))

    coverage = findings.get("coverage", {})
    # A project's own entry point is a catalogue sink. The BIP-32 anchor can
    # match alone and, being unresolvable by design, would hide that the
    # entry point is gone. A project whose correct answer is "no sinks"
    # would be misreported here, so none is in the allowlist.
    if not any(c.get("mechanism") == "catalogue" for c in coverage.get("chains", [])):
        found = coverage.get("sinks_found", 0)
        detail = (
            "only the BIP-32 structural anchor matched; none of this project's own entry points did"
            if found
            else "no catalogue entry or structural anchor matched at this ref"
        )
        return failed("sink_location", detail, evidence=sink_evidence)

    if not verified and coverage.get("chains_closed", 0) == 0:
        unknown = [c for c in coverage.get("chains", []) if c.get("status") == "UNKNOWN"]
        own = [c for c in unknown if c.get("mechanism") == "catalogue"]
        head = (own or unknown or [{}])[0]
        reason = head.get("unknown_reason", "")
        return failed(
            "chain_walk",
            f"{head.get('sink_name', 'sink')}: {reason}".strip(": "),
            broke_at=head.get("broke_at_hop"),
        )

    if verified:
        return Outcome("verified_ok")
    return Outcome(
        "unverified_ok",
        message="This ref is not in our verified set; the profile applied cleanly anyway.",
    )
