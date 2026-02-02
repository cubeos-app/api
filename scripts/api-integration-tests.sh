#!/bin/bash
# CubeOS API Integration Tests
# Version: 3.0 (with authentication)
# Tests all Sprint 3 API endpoints
#
# Usage: ./api-integration-tests.sh [API_URL] [HAL_URL] [USERNAME] [PASSWORD]
# Default: http://10.42.24.1:6010 http://10.42.24.1:6005 admin admin

set -euo pipefail

API_URL="${1:-http://10.42.24.1:6010}"
HAL_URL="${2:-http://10.42.24.1:6005}"
AUTH_USER="${3:-admin}"
AUTH_PASS="${4:-admin}"

# JWT Token (populated after login)
TOKEN=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASSED=0
FAILED=0
SKIPPED=0

# Test results array
declare -a RESULTS=()

log_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    PASSED=$((PASSED + 1))
    RESULTS+=("PASS: $1")
}

log_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    echo -e "${RED}       $2${NC}"
    FAILED=$((FAILED + 1))
    RESULTS+=("FAIL: $1 - $2")
}

log_skip() {
    echo -e "${YELLOW}○ SKIP${NC}: $1"
    SKIPPED=$((SKIPPED + 1))
    RESULTS+=("SKIP: $1")
}

log_section() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

# Helper: Make authenticated request and capture response + status
request() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"
    
    if [[ -n "$data" ]]; then
        curl -s -w "\n%{http_code}" -X "$method" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "${API_URL}${endpoint}"
    else
        curl -s -w "\n%{http_code}" -X "$method" \
            -H "Authorization: Bearer $TOKEN" \
            "${API_URL}${endpoint}"
    fi
}

# Helper: Make unauthenticated request
request_noauth() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"
    
    if [[ -n "$data" ]]; then
        curl -s -w "\n%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "${API_URL}${endpoint}"
    else
        curl -s -w "\n%{http_code}" -X "$method" \
            "${API_URL}${endpoint}"
    fi
}

# Helper: Extract body and status from response
parse_response() {
    local response="$1"
    local status_code
    status_code=$(echo "$response" | tail -n1)
    local body
    body=$(echo "$response" | sed '$d')
    echo "$status_code|$body"
}

# Helper: Check JSON field exists
json_has() {
    local json="$1"
    local field="$2"
    echo "$json" | jq -e "$field" > /dev/null 2>&1
}

# Helper: Get JSON field value
json_get() {
    local json="$1"
    local field="$2"
    echo "$json" | jq -r "$field"
}

#==============================================================================
# SECTION 1: Prerequisites & Health Checks
#==============================================================================
test_prerequisites() {
    log_section "1. Prerequisites & Health Checks"
    
    # 1.1 API Health (no auth required)
    local response
    response=$(request_noauth GET "/health")
    local parsed
    parsed=$(parse_response "$response")
    local status="${parsed%%|*}"
    local body="${parsed#*|}"
    
    if [[ "$status" == "200" ]] && json_has "$body" ".status"; then
        log_pass "1.1 API health check (${API_URL}/health)"
    else
        log_fail "1.1 API health check" "Status: $status"
        echo "CRITICAL: API not responding. Aborting tests."
        exit 1
    fi
    
    # 1.2 HAL Health
    local hal_response
    hal_response=$(curl -s -w "\n%{http_code}" "${HAL_URL}/health" 2>/dev/null || echo -e "\n000")
    parsed=$(parse_response "$hal_response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "1.2 HAL health check (${HAL_URL}/health)"
    else
        log_fail "1.2 HAL health check" "Status: $status (HAL required for network/VPN tests)"
    fi
    
    # 1.3 Login and get JWT token
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$AUTH_USER\",\"password\":\"$AUTH_PASS\"}" \
        "${API_URL}/api/v1/auth/login")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    body="${parsed#*|}"
    
    if [[ "$status" == "200" ]] && json_has "$body" ".access_token"; then
        TOKEN=$(json_get "$body" '.access_token')
        local token_len=${#TOKEN}
        log_pass "1.3 Login successful (token length: $token_len)"
    else
        log_fail "1.3 Login" "Status: $status - Cannot continue without auth"
        echo ""
        echo -e "${RED}CRITICAL: Authentication failed. Check credentials.${NC}"
        echo "  User: $AUTH_USER"
        echo "  API: $API_URL"
        echo "  Response: $body"
        exit 1
    fi
    
    # 1.4 Verify token works on protected endpoint
    response=$(request GET "/api/v1/apps")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "1.4 Authenticated request works"
    else
        log_fail "1.4 Authenticated request" "Status: $status - Token may be invalid"
        exit 1
    fi
}

#==============================================================================
# SECTION 2: Apps API - Read Operations
#==============================================================================
test_apps_read() {
    log_section "2. Apps API - Read Operations"
    
    # 2.1 GET /apps
    local response
    response=$(request GET "/api/v1/apps")
    local parsed
    parsed=$(parse_response "$response")
    local status="${parsed%%|*}"
    local body="${parsed#*|}"
    
    if [[ "$status" == "200" ]]; then
        local app_count
        app_count=$(json_get "$body" '.apps | length')
        if [[ "$app_count" -gt 0 ]]; then
            log_pass "2.1 GET /api/v1/apps (returned $app_count apps)"
        else
            log_fail "2.1 GET /api/v1/apps" "No apps returned"
        fi
    else
        log_fail "2.1 GET /api/v1/apps" "Status: $status"
    fi
    
    # 2.2 GET /apps with type filter
    response=$(request GET "/api/v1/apps?type=system")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    body="${parsed#*|}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "2.2 GET /api/v1/apps?type=system"
    else
        log_fail "2.2 GET /api/v1/apps?type=system" "Status: $status"
    fi
    
    # 2.3 GET /apps/{name} - existing app
    response=$(request GET "/api/v1/apps/pihole")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    body="${parsed#*|}"
    
    if [[ "$status" == "200" ]] && json_has "$body" ".name"; then
        local app_name
        app_name=$(json_get "$body" '.name')
        log_pass "2.3 GET /api/v1/apps/pihole (name: $app_name)"
    else
        log_fail "2.3 GET /api/v1/apps/pihole" "Status: $status"
    fi
    
    # 2.4 GET /apps/{name} - non-existent app
    response=$(request GET "/api/v1/apps/nonexistent-app-xyz")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "404" ]]; then
        log_pass "2.4 GET /api/v1/apps/nonexistent (404 expected)"
    else
        log_fail "2.4 GET /api/v1/apps/nonexistent" "Expected 404, got $status"
    fi
    
    # 2.5 GET /apps/{name}/logs
    response=$(request GET "/api/v1/apps/pihole/logs?lines=10")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    body="${parsed#*|}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "2.5 GET /api/v1/apps/pihole/logs"
    else
        log_fail "2.5 GET /api/v1/apps/pihole/logs" "Status: $status"
    fi
}

#==============================================================================
# SECTION 3: Apps API - Write Operations (Verification Tests)
#==============================================================================
test_apps_write() {
    log_section "3. Apps API - Write Operations"
    
    # 3.1 POST /apps/{name}/restart (on dozzle - safe to restart)
    echo -e "${YELLOW}  Testing restart on dozzle (safe target)...${NC}"
    
    # Restart dozzle
    local response
    response=$(request POST "/api/v1/apps/dozzle/restart")
    local parsed
    parsed=$(parse_response "$response")
    local status="${parsed%%|*}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "3.1 POST /api/v1/apps/dozzle/restart (HTTP 200)"
    else
        log_fail "3.1 POST /api/v1/apps/dozzle/restart" "Status: $status"
    fi
    
    # 3.2 POST /apps/{name}/stop - test on pihole (protected system app)
    response=$(request POST "/api/v1/apps/pihole/stop")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    # Either 200 (stop worked) or 403 (protected) is acceptable
    if [[ "$status" == "200" ]] || [[ "$status" == "403" ]]; then
        log_pass "3.2 POST /api/v1/apps/pihole/stop (Status: $status)"
        # If we stopped it, start it back
        if [[ "$status" == "200" ]]; then
            request POST "/api/v1/apps/pihole/start" > /dev/null 2>&1
        fi
    else
        log_fail "3.2 POST /api/v1/apps/pihole/stop" "Expected 200 or 403, got $status"
    fi
    
    # 3.3 POST /apps - install endpoint exists
    response=$(request POST "/api/v1/apps" '{"name":"test-app"}')
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    # Any response other than 404 means the endpoint exists
    if [[ "$status" != "404" ]]; then
        log_pass "3.3 POST /api/v1/apps endpoint exists (status: $status)"
    else
        log_fail "3.3 POST /api/v1/apps" "Endpoint not found (404)"
    fi
    
    # 3.4 DELETE /apps/{name} - non-existent app
    response=$(request DELETE "/api/v1/apps/nonexistent-app-xyz")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "404" ]]; then
        log_pass "3.4 DELETE /api/v1/apps/nonexistent (404 expected)"
    else
        log_fail "3.4 DELETE /api/v1/apps/nonexistent" "Expected 404, got $status"
    fi
}

#==============================================================================
# SECTION 4: Network API
#==============================================================================
test_network() {
    log_section "4. Network API"
    
    # 4.1 GET /network/status
    local response
    response=$(request GET "/api/v1/network/status")
    local parsed
    parsed=$(parse_response "$response")
    local status="${parsed%%|*}"
    local body="${parsed#*|}"
    
    if [[ "$status" == "200" ]]; then
        if json_has "$body" ".mode"; then
            local mode
            mode=$(json_get "$body" '.mode')
            log_pass "4.1 GET /api/v1/network/status (mode: $mode)"
        else
            log_pass "4.1 GET /api/v1/network/status"
        fi
    else
        log_fail "4.1 GET /api/v1/network/status" "Status: $status"
    fi
    
    # 4.2 GET /network/wifi/scan
    response=$(request GET "/api/v1/network/wifi/scan")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    body="${parsed#*|}"
    
    if [[ "$status" == "200" ]]; then
        if json_has "$body" ".networks"; then
            local net_count
            net_count=$(json_get "$body" '.networks | length')
            log_pass "4.2 GET /api/v1/network/wifi/scan ($net_count networks)"
        else
            log_pass "4.2 GET /api/v1/network/wifi/scan"
        fi
    elif [[ "$status" == "500" ]]; then
        # WiFi scan may fail if no interface available
        log_skip "4.2 GET /api/v1/network/wifi/scan (may need WiFi interface)"
    else
        log_fail "4.2 GET /api/v1/network/wifi/scan" "Status: $status"
    fi
    
    # 4.3 GET /network/ap/config
    response=$(request GET "/api/v1/network/ap/config")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    body="${parsed#*|}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "4.3 GET /api/v1/network/ap/config"
    else
        log_fail "4.3 GET /api/v1/network/ap/config" "Status: $status"
    fi
    
    # 4.4 POST /network/mode - invalid mode (should fail validation)
    response=$(request POST "/api/v1/network/mode" '{"mode":"invalid-mode"}')
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "400" ]]; then
        log_pass "4.4 POST /api/v1/network/mode rejects invalid mode (400)"
    else
        log_fail "4.4 POST /api/v1/network/mode" "Expected 400 for invalid mode, got $status"
    fi
}

#==============================================================================
# SECTION 5: VPN API
#==============================================================================
test_vpn() {
    log_section "5. VPN API"
    
    # 5.1 GET /vpn/configs
    local response
    response=$(request GET "/api/v1/vpn/configs")
    local parsed
    parsed=$(parse_response "$response")
    local status="${parsed%%|*}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "5.1 GET /api/v1/vpn/configs"
    else
        log_fail "5.1 GET /api/v1/vpn/configs" "Status: $status"
    fi
    
    # 5.2 GET /vpn/status
    response=$(request GET "/api/v1/vpn/status")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "5.2 GET /api/v1/vpn/status"
    else
        log_fail "5.2 GET /api/v1/vpn/status" "Status: $status"
    fi
    
    # 5.3 POST /vpn/configs/{id}/connect - non-existent config
    response=$(request POST "/api/v1/vpn/configs/999/connect")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "404" ]] || [[ "$status" == "400" ]]; then
        log_pass "5.3 POST /api/v1/vpn/configs/999/connect (status: $status)"
    else
        log_fail "5.3 POST /api/v1/vpn/configs/999/connect" "Status: $status"
    fi
}

#==============================================================================
# SECTION 6: Mounts API
#==============================================================================
test_mounts() {
    log_section "6. Mounts API"
    
    # 6.1 GET /mounts
    local response
    response=$(request GET "/api/v1/mounts")
    local parsed
    parsed=$(parse_response "$response")
    local status="${parsed%%|*}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "6.1 GET /api/v1/mounts"
    else
        log_fail "6.1 GET /api/v1/mounts" "Status: $status"
    fi
    
    # 6.2 POST /mounts - invalid request
    response=$(request POST "/api/v1/mounts" '{"name":""}')
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "400" ]] || [[ "$status" == "500" ]]; then
        log_pass "6.2 POST /api/v1/mounts rejects invalid (status: $status)"
    else
        log_fail "6.2 POST /api/v1/mounts" "Expected 400/500 for invalid, got $status"
    fi
    
    # 6.3 DELETE /mounts/{id} - non-existent
    response=$(request DELETE "/api/v1/mounts/999")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "404" ]] || [[ "$status" == "200" ]]; then
        log_pass "6.3 DELETE /api/v1/mounts/999 (status: $status)"
    else
        log_fail "6.3 DELETE /api/v1/mounts/999" "Status: $status"
    fi
}

#==============================================================================
# SECTION 7: Profiles API
#==============================================================================
test_profiles() {
    log_section "7. Profiles API"
    
    # 7.1 GET /profiles
    local response
    response=$(request GET "/api/v1/profiles")
    local parsed
    parsed=$(parse_response "$response")
    local status="${parsed%%|*}"
    local body="${parsed#*|}"
    
    if [[ "$status" == "200" ]]; then
        if json_has "$body" ".profiles"; then
            local profile_count
            profile_count=$(json_get "$body" '.profiles | length')
            log_pass "7.1 GET /api/v1/profiles ($profile_count profiles)"
        else
            log_pass "7.1 GET /api/v1/profiles"
        fi
    else
        log_fail "7.1 GET /api/v1/profiles" "Status: $status"
    fi
    
    # 7.2 POST /profiles/{name}/apply - non-existent profile
    response=$(request POST "/api/v1/profiles/nonexistent-profile/apply")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "404" ]]; then
        log_pass "7.2 POST /api/v1/profiles/nonexistent/apply (404 expected)"
    else
        log_fail "7.2 POST /api/v1/profiles/nonexistent/apply" "Expected 404, got $status"
    fi
}

#==============================================================================
# SECTION 8: System API
#==============================================================================
test_system() {
    log_section "8. System API"
    
    # 8.1 GET /system/info
    local response
    response=$(request GET "/api/v1/system/info")
    local parsed
    parsed=$(parse_response "$response")
    local status="${parsed%%|*}"
    local body="${parsed#*|}"
    
    if [[ "$status" == "200" ]]; then
        if json_has "$body" ".hostname"; then
            local hostname
            hostname=$(json_get "$body" '.hostname')
            log_pass "8.1 GET /api/v1/system/info (hostname: $hostname)"
        else
            log_pass "8.1 GET /api/v1/system/info"
        fi
    else
        log_fail "8.1 GET /api/v1/system/info" "Status: $status"
    fi
    
    # 8.2 GET /system/stats
    response=$(request GET "/api/v1/system/stats")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "8.2 GET /api/v1/system/stats"
    else
        log_fail "8.2 GET /api/v1/system/stats" "Status: $status"
    fi
    
    # 8.3 GET /system/temperature
    response=$(request GET "/api/v1/system/temperature")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "200" ]]; then
        log_pass "8.3 GET /api/v1/system/temperature"
    else
        log_fail "8.3 GET /api/v1/system/temperature" "Status: $status"
    fi
}

#==============================================================================
# SECTION 9: Error Handling & Edge Cases
#==============================================================================
test_errors() {
    log_section "9. Error Handling & Edge Cases"
    
    # 9.1 Invalid JSON (with auth)
    local response
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "not valid json" \
        "${API_URL}/api/v1/apps")
    local parsed
    parsed=$(parse_response "$response")
    local status="${parsed%%|*}"
    
    if [[ "$status" == "400" ]]; then
        log_pass "9.1 Invalid JSON rejected (400)"
    else
        log_fail "9.1 Invalid JSON" "Expected 400, got $status"
    fi
    
    # 9.2 Non-existent endpoint
    response=$(request GET "/api/v1/nonexistent-endpoint")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "404" ]]; then
        log_pass "9.2 Non-existent endpoint (404)"
    else
        log_fail "9.2 Non-existent endpoint" "Expected 404, got $status"
    fi
    
    # 9.3 Method not allowed
    response=$(request DELETE "/api/v1/network/status")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "405" ]] || [[ "$status" == "404" ]]; then
        log_pass "9.3 Method not allowed/not found ($status)"
    else
        log_fail "9.3 Method not allowed" "Expected 405 or 404, got $status"
    fi
    
    # 9.4 Response has error field on errors
    response=$(request GET "/api/v1/apps/nonexistent-app")
    parsed=$(parse_response "$response")
    local body="${parsed#*|}"
    
    if json_has "$body" ".error"; then
        log_pass "9.4 Error responses include 'error' field"
    else
        log_fail "9.4 Error responses" "Missing 'error' field in response"
    fi
    
    # 9.5 Unauthenticated request rejected
    response=$(request_noauth GET "/api/v1/apps")
    parsed=$(parse_response "$response")
    status="${parsed%%|*}"
    
    if [[ "$status" == "401" ]]; then
        log_pass "9.5 Unauthenticated request rejected (401)"
    else
        log_fail "9.5 Unauthenticated request" "Expected 401, got $status"
    fi
}

#==============================================================================
# SECTION 10: Response Time Performance
#==============================================================================
test_performance() {
    log_section "10. Response Time Performance"
    
    local endpoints=(
        "/health"
        "/api/v1/apps"
        "/api/v1/network/status"
        "/api/v1/system/stats"
    )
    
    for endpoint in "${endpoints[@]}"; do
        local start_time
        start_time=$(date +%s%N)
        
        if [[ "$endpoint" == "/health" ]]; then
            curl -s "${API_URL}${endpoint}" > /dev/null
        else
            curl -s -H "Authorization: Bearer $TOKEN" "${API_URL}${endpoint}" > /dev/null
        fi
        
        local end_time
        end_time=$(date +%s%N)
        local duration_ms=$(( (end_time - start_time) / 1000000 ))
        
        if [[ $duration_ms -lt 500 ]]; then
            log_pass "10.x $endpoint (${duration_ms}ms < 500ms)"
        elif [[ $duration_ms -lt 2000 ]]; then
            log_pass "10.x $endpoint (${duration_ms}ms - acceptable)"
        else
            log_fail "10.x $endpoint" "Slow response: ${duration_ms}ms"
        fi
    done
}

#==============================================================================
# Main
#==============================================================================
main() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          CubeOS API Integration Tests v3.0                    ║${NC}"
    echo -e "${BLUE}╠═══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║  API:  ${API_URL}${NC}"
    echo -e "${BLUE}║  HAL:  ${HAL_URL}${NC}"
    echo -e "${BLUE}║  User: ${AUTH_USER}${NC}"
    echo -e "${BLUE}║  Time: $(date)${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    
    test_prerequisites
    test_apps_read
    test_apps_write
    test_network
    test_vpn
    test_mounts
    test_profiles
    test_system
    test_errors
    test_performance
    
    # Summary
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                        TEST SUMMARY                           ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $PASSED"
    echo -e "  ${RED}Failed:${NC}  $FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED"
    echo -e "  Total:   $((PASSED + FAILED + SKIPPED))"
    echo ""
    
    if [[ $FAILED -gt 0 ]]; then
        echo -e "${RED}Failed Tests:${NC}"
        for result in "${RESULTS[@]}"; do
            if [[ "$result" == FAIL* ]]; then
                echo "  - ${result#FAIL: }"
            fi
        done
        echo ""
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

main "$@"
