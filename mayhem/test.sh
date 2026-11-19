#!/usr/bin/env bash
#
# mayhem/test.sh — RUN pygame's own unittest suite (draw, surface, transform, mask, pixelarray,
# pixelcopy, image, gfxdraw, math, color, rect, freetype, bufferproxy, ...) against the pygame built
# with normal flags by mayhem/build.sh (build/test/lib), through the project-built interpreter
# launcher build/test/pgpython. The suite asserts pixel values, rects, colours and vector maths.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


RUNNER="$SRC/build/test/pgpython"
LIB="$SRC/build/test/lib"
if [ ! -x "$RUNNER" ] || [ ! -f "$LIB/pygame/__init__.py" ]; then
  echo "test.sh: $RUNNER or $LIB missing — mayhem/build.sh did not build the test tree" >&2
  emit_ctrf "pygame-unittest" 0 1 0
  exit 1
fi

log="$(mktemp)"
( cd "${TMPDIR:-/tmp}" && env SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=disk PYGAME_HIDE_SUPPORT_PROMPT=1 \
    PYTHONPATH="$LIB" PYTHONDONTWRITEBYTECODE=1 "$RUNNER" "$SRC/mayhem/run_tests.py" ) >"$log" 2>&1
rc=$?
tail -n 25 "$log"
line="$(grep -E '^PGTEST passed=[0-9]+ failed=[0-9]+ skipped=[0-9]+$' "$log" | tail -n 1)"
rm -f "$log"
if [ -z "$line" ]; then
  echo "test.sh: no PGTEST summary (runner rc=$rc) — the suite did not run" >&2
  emit_ctrf "pygame-unittest" 0 1 0
  exit 1
fi
passed="$(sed -E 's/.*passed=([0-9]+).*/\1/' <<<"$line")"
failed="$(sed -E 's/.*failed=([0-9]+).*/\1/' <<<"$line")"
skipped="$(sed -E 's/.*skipped=([0-9]+).*/\1/' <<<"$line")"
# A suite this size that runs almost nothing means the test tree is broken.
if [ "$passed" -lt 1000 ]; then
  echo "test.sh: only $passed tests passed (expected >1000)" >&2
  failed=$((failed + 1))
fi
[ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || failed=1
emit_ctrf "pygame-unittest" "$passed" "$failed" "$skipped"
