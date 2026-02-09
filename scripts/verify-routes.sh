#!/usr/bin/env bash
# =============================================================================
# verify-routes.sh — Verify every Swagger @Router annotation has a handler
# function that is registered in a chi route call.
#
# Strategy:
#   1. Extract (method, path, funcName, file) from @Router annotations
#   2. Check each funcName appears in a r.Get/Post/Put/Delete() call
#   3. Check each Routes() method is Mount()ed in main.go
#
# Exit codes:
#   0 = all routes verified
#   1 = unregistered handlers found
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

STRICT=false
if [[ "${1:-}" == "--strict" ]]; then
    STRICT=true
fi

ERRORS=0
WARNINGS=0
MATCHED=0

HANDLER_DIR="$REPO_ROOT/internal/handlers"
MAIN_GO="$REPO_ROOT/cmd/cubeos-api/main.go"

echo "========================================"
echo " CubeOS Route Verification"
echo "========================================"
echo ""

# ============================================================================
# Step 1: Extract (@Router path, method, function_name, file) tuples
# ============================================================================
echo "Step 1: Extracting @Router annotations and handler functions..."

PAIRS=$(mktemp)

# Process each handler file individually to avoid pipefail issues
for file in "$HANDLER_DIR"/*.go; do
    [[ "$file" == *_test.go ]] && continue
    [[ ! -f "$file" ]] && continue

    # Skip files without @Router
    grep -q '@Router' "$file" 2>/dev/null || continue

    short_file=$(basename "$file")

    # Extract line numbers with @Router
    grep -n '@Router' "$file" | while IFS=: read -r lineno line; do
        # Extract path and method
        path=$(echo "$line" | sed -n 's|.*@Router[[:space:]]\+\(/[^[:space:]]*\).*|\1|p')
        method=$(echo "$line" | sed -n 's|.*\[\([a-z]\+\)\].*|\1|p')

        if [[ -z "$path" || -z "$method" ]]; then
            continue
        fi

        # Find the func declaration in the next few lines
        func_name=""
        for offset in 1 2 3 4 5; do
            target_line=$(sed -n "$((lineno + offset))p" "$file")
            if [[ "$target_line" =~ ^func ]]; then
                func_name=$(echo "$target_line" | sed -n 's/^func[[:space:]]\+\(([^)]*)[[:space:]]\+\)\?\([A-Za-z_][A-Za-z0-9_]*\)(.*$/\2/p')
                break
            fi
        done

        [[ -z "$func_name" ]] && continue

        echo "${method}|${path}|${func_name}|${short_file}"
    done || true  # prevent pipefail from grep|while
done | sort -t'|' -k4,4 -k2,2 > "$PAIRS"

TOTAL=$(wc -l < "$PAIRS")
echo "  Found $TOTAL @Router -> handler function pairs"

# ============================================================================
# Step 2: Verify each handler function is in a route registration
# ============================================================================
echo ""
echo "Step 2: Checking handler functions are registered in routes..."
echo ""

# Build combined text of all route registration lines
ROUTE_CALLS=$(mktemp)
{
    grep -rh 'r\.\(Get\|Post\|Put\|Delete\|Patch\)(' "$MAIN_GO" 2>/dev/null || true
    for f in "$HANDLER_DIR"/*.go; do
        [[ "$f" == *_test.go ]] && continue
        grep -h 'r\.\(Get\|Post\|Put\|Delete\|Patch\)(' "$f" 2>/dev/null || true
    done
} | grep -v '^[[:space:]]*//' > "$ROUTE_CALLS" || true

while IFS='|' read -r method path func_name file; do
    if grep -qE "\\.${func_name}[^A-Za-z0-9_]" "$ROUTE_CALLS" 2>/dev/null; then
        MATCHED=$((MATCHED + 1))
    else
        echo "  [MISSING] ${method^^} ${path} -> ${func_name}() in ${file}"
        ERRORS=$((ERRORS + 1))
    fi
done < "$PAIRS"

if [[ $MATCHED -gt 0 && $ERRORS -eq 0 ]]; then
    echo "  All $MATCHED handler functions are registered."
fi

# ============================================================================
# Step 3: Verify all Routes() methods are Mount()ed in main.go
# ============================================================================
echo ""
echo "Step 3: Checking handler Routes() methods are mounted..."
echo ""

UNMOUNTED=0
MOUNTED=0

for handler_file in "$HANDLER_DIR"/*.go; do
    [[ "$handler_file" == *_test.go ]] && continue

    grep -q 'func.*Routes().*chi\.Router' "$handler_file" 2>/dev/null || continue

    short=$(basename "$handler_file")

    handler_type=$(grep 'func.*Routes().*chi\.Router' "$handler_file" | \
        sed -n 's/func[[:space:]]*(h[[:space:]]*\*\([A-Za-z]*\))[[:space:]]*Routes().*/\1/p' | head -1)

    [[ -z "$handler_type" ]] && continue

    # Find the variable name: fooHandler := handlers.NewFooHandler(...)
    # Also handles: var fooHandler ... then fooHandler = handlers.NewFooHandler(...)
    var_name=$(grep "New${handler_type}" "$MAIN_GO" 2>/dev/null | \
        sed -n 's/^[[:space:]]*\([a-zA-Z]*\)[[:space:]]*:\?=.*/\1/p' | head -1)

    if [[ -n "$var_name" ]] && grep -q "${var_name}\.Routes()" "$MAIN_GO" 2>/dev/null; then
        echo "  [OK] ${short} -> ${var_name}.Routes()"
        MOUNTED=$((MOUNTED + 1))
    else
        echo "  [UNMOUNTED] ${short} -> ${handler_type}.Routes()"
        UNMOUNTED=$((UNMOUNTED + 1))
        if [[ "$STRICT" == "true" ]]; then
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
done

# ============================================================================
# Step 4: Summary
# ============================================================================
echo ""
echo "========================================"
echo " Summary"
echo "========================================"
echo "  Total @Router annotations:   $TOTAL"
echo "  Matched (func registered):   $MATCHED"
echo "  Missing (func NOT in route): $ERRORS"
echo "  Mounted Routes() methods:    $MOUNTED"
echo "  Unmounted Routes() methods:  $UNMOUNTED"
echo "========================================"

rm -f "$PAIRS" "$ROUTE_CALLS"

if [[ $ERRORS -gt 0 ]]; then
    echo ""
    echo "FAIL: $ERRORS handler functions have @Router but no route registration."
    echo "Fix: Add the route call or remove the stale @Router annotation."
    exit 1
fi

if [[ "$STRICT" == "true" && $WARNINGS -gt 0 ]]; then
    echo ""
    echo "FAIL (strict): $WARNINGS Routes() methods not Mount()ed in main.go."
    exit 1
fi

echo ""
echo "PASS: All @Router-annotated handlers are registered in routes."
exit 0
