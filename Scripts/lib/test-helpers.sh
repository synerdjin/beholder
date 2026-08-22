#!/bin/bash
#
# Assertions shared by the shell tests.
#
# Executable targets cannot be reached by unit tests, so behaviour that only exists in a
# binary is covered by shell tests here. There are now four of them, and the counter, the
# two assertions and the epilogue had been copied into each — which is how a test file comes
# to report "PASS" from a helper subtly different from the one next door.
#
# Source it, then call `check`/`contains`, and finish with `report_results`.

failures=0

# check <name> <actual> <expected>   — exact equality.
check() {
    if [[ "$2" == "$3" ]]; then
        echo "  ok: $1"
    else
        echo "  FAIL: $1" >&2
        echo "        expected: $3" >&2
        echo "        actual:   $2" >&2
        failures=$((failures + 1))
    fi
}

# contains <name> <haystack> <needle> — substring.
#
# `grep -qF --` and not `grep -qF`: an expected string starting with a dash is otherwise read
# as options, which fails in a way that looks like the assertion itself failing.
contains() {
    if grep -qF -- "$3" <<< "$2"; then
        echo "  ok: $1"
    else
        echo "  FAIL: $1" >&2
        echo "        expected to contain: $3" >&2
        echo "        actual: $2" >&2
        failures=$((failures + 1))
    fi
}

report_results() {
    echo
    if [[ ${failures} -eq 0 ]]; then
        echo "PASS"
    else
        echo "${failures} check(s) failed" >&2
        exit 1
    fi
}
