#!/usr/bin/env bash
# =============================================================================
# verify-routes.sh — Cross-reference Swagger @Router annotations with
# actual route registrations in handler Routes() methods.
#
# Exit codes:
#   0 = all routes verified (or warnings only)
#   1 = missing routes found (errors)
#
# Usage:
#   ./scripts/verify-routes.sh [--strict]
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

echo "========================================"
echo " CubeOS Route Verification"
echo "========================================"
echo ""

# Step 1: Extract @Router annotations
echo "Step 1: Extracting @Router annotations from handlers..."

SWAGGER_ROUTES=$(mktemp)
grep -rh '@Router' "$REPO_ROOT/internal/handlers/" 2>/dev/null \
    | grep -v '_test.go' \
    | while IFS= read -r line; do
        # Extract: @Router /path [method]
        path=$(echo "$line" | grep -oP '@Router\s+\K\S+')
        method=$(echo "$line" | grep -oP '\[\K\w+')
        if [[ -n "$path" && -n "$method" ]]; then
            echo "${method^^} /api/v1${path}"
        fi
    done \
    | sort -u \
    > "$SWAGGER_ROUTES"

SWAGGER_COUNT=$(wc -l < "$SWAGGER_ROUTES")
echo "  Found $SWAGGER_COUNT @Router annotations"

# Step 2: Extract route registrations from handler Routes() methods
echo ""
echo "Step 2: Extracting registered routes from code..."

REGISTERED_ROUTES=$(mktemp)

extract_routes() {
    local file=$1
    local prefix=$2

    grep -E 'r\.(Get|Post|Put|Delete|Patch)\(' "$file" 2>/dev/null \
        | grep -v '//' \
        | while IFS= read -r line; do
            method=$(echo "$line" | grep -oP 'r\.\K(Get|Post|Put|Delete|Patch)')
            path=$(echo "$line" | grep -oP 'r\.\w+\("\K[^"]+')
            if [[ -n "$method" && -n "$path" ]]; then
                echo "${method^^} /api/v1${prefix}${path}"
            fi
        done
}

# Known mount points from main.go
declare -A HANDLER_MOUNTS=(
    ["apps.go"]="/apps"
    ["appstore.go"]="/appstore"
    ["network.go"]="/network"
    ["firewall.go"]="/firewall"
    ["fqdns.go"]="/fqdns"
    ["backups.go"]="/backups"
    ["chat.go"]="/chat"
    ["docs.go"]="/documentation"
    ["vpn.go"]="/vpn"
    ["registry.go"]="/registry"
    ["media.go"]="/media"
    ["mounts.go"]="/mounts"
    ["smb.go"]="/smb"
    ["ports.go"]="/ports"
    ["profiles.go"]="/profiles"
)

for handler_file in "${!HANDLER_MOUNTS[@]}"; do
    local_prefix="${HANDLER_MOUNTS[$handler_file]}"
    handler_path="$REPO_ROOT/internal/handlers/$handler_file"
    if [[ -f "$handler_path" ]]; then
        extract_routes "$handler_path" "$local_prefix" >> "$REGISTERED_ROUTES"
    fi
done

# Extract inline routes from main.go
extract_routes "$REPO_ROOT/cmd/cubeos-api/main.go" "" >> "$REGISTERED_ROUTES" 2>/dev/null || true

sort -u -o "$REGISTERED_ROUTES" "$REGISTERED_ROUTES"
REGISTERED_COUNT=$(wc -l < "$REGISTERED_ROUTES")
echo "  Found $REGISTERED_COUNT registered routes"

# Step 3: Cross-reference
echo ""
echo "Step 3: Cross-referencing..."
echo ""

# Normalize {param} forms for comparison
SWAGGER_NORM=$(mktemp)
REGISTERED_NORM=$(mktemp)
sed -E 's/\{[^}]+\}/{param}/g; s|/$||' "$SWAGGER_ROUTES" | sort -u > "$SWAGGER_NORM"
sed -E 's/\{[^}]+\}/{param}/g; s|/$||' "$REGISTERED_ROUTES" | sort -u > "$REGISTERED_NORM"

# Documented but not registered
MISSING=$(comm -23 "$SWAGGER_NORM" "$REGISTERED_NORM" || true)
if [[ -n "$MISSING" ]]; then
    echo "ERRORS — Documented routes NOT found in code:"
    while IFS= read -r route; do
        echo "  [MISSING] $route"
        ERRORS=$((ERRORS + 1))
    done <<< "$MISSING"
    echo ""
fi

# Registered but not documented
UNDOCUMENTED=$(comm -13 "$SWAGGER_NORM" "$REGISTERED_NORM" || true)
if [[ -n "$UNDOCUMENTED" ]]; then
    echo "WARNINGS — Registered routes without @Router annotation:"
    while IFS= read -r route; do
        echo "  [UNDOC]   $route"
        WARNINGS=$((WARNINGS + 1))
    done <<< "$UNDOCUMENTED"
    echo ""
fi

MATCHED=$(comm -12 "$SWAGGER_NORM" "$REGISTERED_NORM" | wc -l)

# Step 4: Summary
echo "========================================"
echo " Summary"
echo "========================================"
echo "  Swagger annotations:  $SWAGGER_COUNT"
echo "  Registered routes:    $REGISTERED_COUNT"
echo "  Matched:              $MATCHED"
echo "  Missing (errors):     $ERRORS"
echo "  Undocumented (warns): $WARNINGS"
echo "========================================"

rm -f "$SWAGGER_ROUTES" "$REGISTERED_ROUTES" "$SWAGGER_NORM" "$REGISTERED_NORM"

if [[ $ERRORS -gt 0 ]]; then
    echo ""
    echo "FAIL: $ERRORS documented routes are not registered in code."
    exit 1
fi

if [[ "$STRICT" == "true" && $WARNINGS -gt 0 ]]; then
    echo ""
    echo "FAIL (strict): $WARNINGS registered routes lack Swagger annotations."
    exit 1
fi

echo ""
echo "PASS: All documented routes are registered."
exit 0
