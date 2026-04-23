#!/bin/sh
# Unit tests for image/init-templates/vendors/_lib.sh.
#
# Runs under `busybox sh` to match the initrd's actual shell (NOT bash).
# Exits 0 on all-pass, non-zero on first failure.
#
# Invoke as: busybox sh image/ci-test-vendor-lib.sh
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
LIB="$SCRIPT_DIR/init-templates/vendors/_lib.sh"
[ -f "$LIB" ] || { echo "FAIL: missing $LIB"; exit 2; }

# shellcheck disable=SC1090
. "$LIB"

TESTS=0
PASSED=0
FAILED=0
FAILURES=""

report() {
    TESTS=$((TESTS + 1))
    if [ "$1" -eq 0 ]; then
        PASSED=$((PASSED + 1))
        printf '  ok %d - %s\n' "$TESTS" "$2"
    else
        FAILED=$((FAILED + 1))
        FAILURES="${FAILURES}
  #$TESTS $2"
        printf '  FAIL %d - %s\n' "$TESTS" "$2"
        printf '      got:      %s\n' "$3"
        printf '      expected: %s\n' "$4"
    fi
}

assert_eq() {
    # $1=name $2=actual $3=expected
    if [ "$2" = "$3" ]; then
        report 0 "$1"
    else
        report 1 "$1" "$2" "$3"
    fi
}

echo "== _ee_json_to_env =="

# 1. Simple flat object.
got=$(printf '%s' '{"A":"1","B":"2"}' | _ee_json_to_env)
assert_eq "flat object" "$got" "$(printf 'A=1\nB=2')"

# 2. Whitespace tolerated.
got=$(printf '%s' '{ "A" : "1" , "B": "2" }' | _ee_json_to_env)
assert_eq "whitespace tolerated" "$got" "$(printf 'A=1\nB=2')"

# 3. Escaped quotes inside a value — the legacy GCE ee-config case.
#    EE_BOOT_WORKLOADS is traditionally a JSON-string-encoded JSON array;
#    its value contains \" which must be unescaped when piping into env.
payload='{"EE_BOOT_WORKLOADS":"[{\"app_name\":\"foo\"}]","EE_OWNER":"alice"}'
got=$(printf '%s' "$payload" | _ee_json_to_env)
expected=$(printf 'EE_BOOT_WORKLOADS=[{"app_name":"foo"}]\nEE_OWNER=alice')
assert_eq "escaped-quote values unescape" "$got" "$expected"

# 4. Empty object.
got=$(printf '%s' '{}' | _ee_json_to_env)
assert_eq "empty object produces no output" "$got" ""

# 5. Non-object body fails (returns non-zero).
if printf '%s' 'not json' | _ee_json_to_env >/dev/null 2>&1; then
    report 1 "non-object rejected" "0 (accepted)" "non-zero (rejected)"
else
    report 0 "non-object rejected"
fi

echo ""
echo "== ee_append_config =="

VENDOR_NAME=test
ENV_FILE=$(mktemp)
cleanup() { rm -f "$ENV_FILE"; }
trap cleanup EXIT

# 6. KEY=VALUE passthrough (the new contract).
: > "$ENV_FILE"
ee_append_config "$(printf 'EE_OWNER=alice\nEE_DATA_DIR=/var/x')" 2>/dev/null
got=$(cat "$ENV_FILE")
expected=$(printf 'EE_OWNER=alice\nEE_DATA_DIR=/var/x')
assert_eq "KEY=VALUE passthrough" "$got" "$expected"

# 7. KEY=VALUE with comment + blank lines filtered.
: > "$ENV_FILE"
ee_append_config "$(printf '# header comment\n\nEE_OWNER=alice\n# inline\nEE_DATA_DIR=/var/x\n')" 2>/dev/null
got=$(cat "$ENV_FILE")
expected=$(printf 'EE_OWNER=alice\nEE_DATA_DIR=/var/x')
assert_eq "comments + blanks filtered" "$got" "$expected"

# 8. JSON body routed to flattener (legacy GCE contract).
: > "$ENV_FILE"
ee_append_config '{"EE_BOOT_WORKLOADS":"[{\"app_name\":\"foo\"}]","EE_OWNER":"alice"}' 2>/dev/null
got=$(cat "$ENV_FILE")
expected=$(printf 'EE_BOOT_WORKLOADS=[{"app_name":"foo"}]\nEE_OWNER=alice')
assert_eq "JSON body auto-flattened" "$got" "$expected"

# 9. Leading spaces before `{` still detected as JSON.
: > "$ENV_FILE"
ee_append_config '   {"A":"1"}' 2>/dev/null
got=$(cat "$ENV_FILE")
assert_eq "leading spaces + JSON" "$got" "A=1"

# 10. Empty body is a no-op (not an error).
: > "$ENV_FILE"
ee_append_config "" 2>/dev/null
got=$(cat "$ENV_FILE")
assert_eq "empty body is no-op" "$got" ""

echo ""
echo "=============================================="
if [ "$FAILED" -eq 0 ]; then
    printf 'PASS: %d/%d tests\n' "$PASSED" "$TESTS"
    exit 0
else
    printf 'FAIL: %d/%d tests (%d failed)%s\n' "$PASSED" "$TESTS" "$FAILED" "$FAILURES"
    exit 1
fi
