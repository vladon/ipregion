#!/usr/bin/env bash

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to run tests."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=/dev/null
source "$ROOT_DIR/ipregion.sh"

failures=0

assert_eq() {
  local expected="$1"
  local actual="$2"
  local name="$3"

  if [[ "$expected" != "$actual" ]]; then
    echo "FAIL: $name (expected: '$expected', got: '$actual')"
    failures=$((failures + 1))
  else
    echo "OK: $name"
  fi
}

assert_true() {
  local name="$1"
  shift

  if ! "$@"; then
    echo "FAIL: $name"
    failures=$((failures + 1))
  else
    echo "OK: $name"
  fi
}

assert_false() {
  local name="$1"
  shift

  if "$@"; then
    echo "FAIL: $name"
    failures=$((failures + 1))
  else
    echo "OK: $name"
  fi
}

assert_empty() {
  local value="$1"
  local name="$2"

  if [[ -n "$value" ]]; then
    echo "FAIL: $name (expected empty, got: '$value')"
    failures=$((failures + 1))
  else
    echo "OK: $name"
  fi
}

assert_contains() {
  local value="$1"
  local needle="$2"
  local name="$3"

  if [[ "$value" == *"$needle"* ]]; then
    echo "OK: $name"
  else
    echo "FAIL: $name (expected '$needle' in '$value')"
    failures=$((failures + 1))
  fi
}

assert_true "is_valid_ipv4 accepts valid value" is_valid_ipv4 "1.2.3.4"
assert_false "is_valid_ipv4 rejects invalid value" is_valid_ipv4 "256.1.1.1"
assert_false "is_valid_ipv4 rejects short value" is_valid_ipv4 "1.2.3"

assert_true "is_valid_ipv6 accepts valid value" is_valid_ipv6 "2001:db8::1"
assert_false "is_valid_ipv6 rejects invalid value" is_valid_ipv6 "not-an-ip"

assert_eq "1" "$(process_json '{"a":1}' '.a')" "process_json returns value from valid JSON"
assert_empty "$(process_json "" ".a")" "process_json returns empty on empty input"
assert_empty "$(process_json "{invalid-json}" ".a")" "process_json returns empty on invalid input"

assert_true "is_valid_proxy_addr accepts host:port" is_valid_proxy_addr "127.0.0.1:1080"
assert_true "is_valid_proxy_addr accepts [ipv6]:port" is_valid_proxy_addr "[2001:db8::1]:1080"
assert_false "is_valid_proxy_addr rejects bad port" is_valid_proxy_addr "127.0.0.1:99999"

assert_eq "GOOGLE_SEARCH_CAPTCHA" "$(normalize_service_name "google-search-captcha")" "normalize_service_name normalizes separators"
assert_eq "GEMINI" "$(normalize_service_name "gemini")" "normalize_service_name normalizes gemini"

assert_eq "1016" "$(parse_gemini_user_status_code '[["wrb.fr","otAQ7b","[6,[false,null,false],true,null,null,null,false,null,null,null,null,null,false,false,1016,[]]"]]')" "parse_gemini_user_status_code reads signed-out status"
assert_eq "1060" "$(parse_gemini_user_status_code '[["wrb.fr","otAQ7b","[6,[false,null,false],false,null,null,null,false,null,null,null,null,null,false,false,1060,[]]"]]')" "parse_gemini_user_status_code reads location rejected"
assert_empty "$(parse_gemini_user_status_code '')" "parse_gemini_user_status_code handles empty input"

assert_eq "Yes" "$(gemini_availability_from_status 1000)" "gemini_availability_from_status maps available"
assert_empty "$(gemini_availability_from_status 1016)" "gemini_availability_from_status leaves unsigned web status inconclusive"
assert_eq "No" "$(gemini_availability_from_status 1060)" "gemini_availability_from_status maps location rejected"
assert_empty "$(gemini_availability_from_status 1033)" "gemini_availability_from_status leaves account issues empty"

assert_eq "No" "$(gemini_api_availability_from_response '{"error":{"message":"User location is not supported for the API use."}}')" "gemini_api_availability_from_response maps location error"
assert_eq "Yes" "$(gemini_api_availability_from_response '{"candidates":[{"content":{"parts":[{"text":"pong"}]}}]}')" "gemini_api_availability_from_response maps success"
assert_empty "$(gemini_api_availability_from_response '{"error":{"message":"API key not valid."}}')" "gemini_api_availability_from_response ignores invalid key"
assert_eq "Denied" "$(status_from_http_code 403)" "status_from_http_code maps 403"
assert_eq "Rate-limit" "$(status_from_http_code 429)" "status_from_http_code maps 429"
assert_eq "Server error" "$(status_from_http_code 503)" "status_from_http_code maps 5xx"
assert_eq "N/A" "$(status_from_http_code 404)" "status_from_http_code maps 4xx"

INCLUDED_SERVICES=("MAXMIND")
EXCLUDED_SERVICES=("GOOGLE_SEARCH_CAPTCHA")
EXCLUDED_SERVICES_CLI=("YOUTUBE")
assert_true "should_skip_service skips non-included service" should_skip_service "RIPE"
assert_false "should_skip_service keeps included service" should_skip_service "MAXMIND"
assert_true "should_skip_service skips default excluded service" should_skip_service "GOOGLE_SEARCH_CAPTCHA"
assert_true "should_skip_service skips cli excluded service" should_skip_service "YOUTUBE"

INCLUDED_SERVICES=()
EXCLUDED_SERVICES=("GOOGLE_SEARCH_CAPTCHA")
EXCLUDED_SERVICES_CLI=()

ARR_PRIMARY=()
ARR_CUSTOM=()
EXTERNAL_IPV4="1.2.3.4"
EXTERNAL_IPV6="2001:db8::1"
EXTERNAL_IPV4_SOURCE="ident.me"
EXTERNAL_IPV6_SOURCE="ifconfig.co"
EXTERNAL_IPV4_CACHE_HIT=false
EXTERNAL_IPV6_CACHE_HIT=true
EXTERNAL_IPV4_TIMESTAMP="1700000000"
EXTERNAL_IPV6_TIMESTAMP="1700000010"
REGISTERED_COUNTRY_IPV4="United States"
REGISTERED_COUNTRY_IPV6="Germany"
ASN_NUMBER="15169"
ASN_NAME="Google LLC"

add_result "primary" "MAXMIND" "US" "DE" "http_code=200;latency_ms=120;transport_ip_version=4;error_type=none" "http_code=200;latency_ms=140;transport_ip_version=6;error_type=none"
add_result "primary" "RIPE" "US" "FR" "http_code=200;latency_ms=100;transport_ip_version=4;error_type=none" "http_code=429;latency_ms=90;transport_ip_version=6;error_type=http_429"
add_result "custom" "Google" "US" "DE" "http_code=200;latency_ms=80;transport_ip_version=4;error_type=none" "http_code=200;latency_ms=95;transport_ip_version=6;error_type=none"

finalize_json

assert_eq "1.2.3.4" "$(process_json "$RESULT_JSON" ".ip.ipv4.address")" "finalize_json includes ipv4 address"
assert_eq "ident.me" "$(process_json "$RESULT_JSON" ".ip.ipv4.source")" "finalize_json includes ipv4 source"
assert_eq "true" "$(process_json "$RESULT_JSON" ".ip.ipv6.cache_hit")" "finalize_json includes cache hit flag"
assert_eq "United States" "$(process_json "$RESULT_JSON" ".ip.ipv4.registered_country")" "finalize_json includes registered country"
assert_eq "15169" "$(process_json "$RESULT_JSON" ".asn.number")" "finalize_json includes ASN number"
assert_eq "US" "$(process_json "$RESULT_JSON" ".consensus.ipv4.country")" "finalize_json computes ipv4 consensus"
assert_eq "200" "$(process_json "$RESULT_JSON" ".results.primary[0].metrics.ipv4.http_code")" "finalize_json parses metrics"
assert_eq "http_429" "$(process_json "$RESULT_JSON" ".results.primary[1].metrics.ipv6.error_type")" "finalize_json keeps error_type"

assert_eq "json" "$(detect_output_format "out.json")" "detect_output_format json"
assert_eq "csv" "$(detect_output_format "out.csv")" "detect_output_format csv"

if [[ "$failures" -gt 0 ]]; then
  echo "$failures test(s) failed."
  exit 1
fi

echo "All tests passed."
