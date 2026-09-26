#!/bin/sh
# Entrypoint for the entropy-trace Docker action.
# Args, in order (from action.yml): profile, mode, output.
set -eu

PROFILE="$1"
MODE="${2:-pr}"
OUTPUT="${3:-entropy-trace-findings.json}"

cd "$GITHUB_WORKSPACE"
# PYTHONPATH is already set at image build time to the analyser baked
# into the image. Deliberately not prepending $GITHUB_WORKSPACE here -
# the analysed repository must never be able to supply the code that
# analyses it. If the workspace happens to contain its own entropytrace/
# directory, that copy is never imported; only the one baked into the
# image is.

SARIF_OUTPUT="${OUTPUT%.json}.sarif"

STEP_SUMMARY_ARGS=""
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    STEP_SUMMARY_ARGS="--step-summary $GITHUB_STEP_SUMMARY"
fi

# Don't let `set -e` abort on a non-zero exit here: a FAIL/WARN verdict
# is an expected, meaningful exit code, not a script error - it must
# reach `exit $CODE` below, and the action's own outputs must still be
# written either way.
set +e
python3 -m entropytrace.cli \
    --profile "$PROFILE" \
    --mode "$MODE" \
    --output "$OUTPUT" \
    --sarif-output "$SARIF_OUTPUT" \
    $STEP_SUMMARY_ARGS
CODE=$?
set -e

if [ -n "${GITHUB_OUTPUT:-}" ] && [ -f "$OUTPUT" ]; then
    OVERALL=$(python3 -c "import json; print(json.load(open('$OUTPUT'))['policy']['overall_verdict'])")
    {
        echo "overall-verdict=$OVERALL"
        echo "findings-path=$OUTPUT"
        echo "sarif-path=$SARIF_OUTPUT"
    } >> "$GITHUB_OUTPUT"
fi

exit "$CODE"
