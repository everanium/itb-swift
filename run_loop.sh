#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Swift binding:
# builds the utility with SwiftPM (a no-op when it is up to date;
# libitb3.so and the C binding library are assumed built by build.sh)
# and execs it with every argument passed through.
#
# The build output is captured rather than redirected: SwiftPM writes
# progress to stderr as well as stdout, and letting either reach the
# caller would put build chatter into the utility's own output. On a
# failure the captured text is printed and the script stops.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

if ! build_log="$(swift build -c release --product loop 2>&1)"; then
    printf '%s\n' "$build_log" >&2
    exit 1
fi

exec .build/release/loop "$@"
