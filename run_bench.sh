#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the Swift binding.
# Builds libitb3.so + the C binding library + the Swift package, then
# runs the Itb3Bench executable: encryptMessage, encryptStreamPump,
# and encryptStreamOneShot throughput at 1 MiB / 16 MiB / 64 MiB as
# an MB/s table on stdout.
#
# Usage:
#   ./run_bench.sh [message|stream|stream_one_shot|all]   # default: all

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench main
# applies the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-4GiB}"
export ITB_GOGC="${ITB_GOGC:-100}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# baseline. Override any of these before calling the script to
# change the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

# Split at the shell layer so each shape carries its own ITB_PROFILE
# in a single script pass (the Itb3Bench Swift entry point handles
# "message", "stream", and "all" arguments individually).
case "${1:-all}" in
    message)
        export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
        exec .build/release/Itb3Bench message
        ;;
    stream)
        export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
        exec .build/release/Itb3Bench stream
        ;;
    stream_one_shot)
        export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
        exec .build/release/Itb3Bench stream_one_shot
        ;;
    all)
        export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
        .build/release/Itb3Bench message
        export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
        .build/release/Itb3Bench stream
        exec .build/release/Itb3Bench stream_one_shot
        ;;
    *)
        echo "usage: $0 [message|stream|stream_one_shot|all]" >&2
        exit 2
        ;;
esac
