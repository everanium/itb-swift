/*
 * main.swift — bench driver:
 * `Itb3Bench [message|stream|stream_one_shot|all]`.
 *
 * Bench-scale allocation churn leaks Go scratch heap unboundedly
 * without a soft memory cap + aggressive GC; the setters report the
 * previous values, not an error.
 */

import Foundation
import Itb3

ItbRuntime.setMemoryLimit(4 << 30) // 4 GiB soft cap
ItbRuntime.setGCPercent(100)        // balanced GC

let mode = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "all"
switch mode {
case "message":
    benchHeader()
    runMessageBench()
case "stream":
    benchHeader()
    runStreamBench()
case "stream_one_shot":
    benchHeader()
    runStreamOneShotBench()
case "all":
    benchHeader()
    runMessageBench()
    runStreamBench()
    runStreamOneShotBench()
default:
    FileHandle.standardError.write(
        Data("usage: Itb3Bench [message|stream|stream_one_shot|all]\n".utf8))
    exit(2)
}
