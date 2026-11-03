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

assert_eq "stream" "$(gemini_batch_needs_stream_probe '[["wrb.fr","otAQ7b","[6,[false,null,false],true,null,null,null,false,null,null,null,null,null,false,false,1000,[]]"]]')" "gemini_batch_needs_stream_probe maps available"
assert_eq "stream" "$(gemini_batch_needs_stream_probe '[["wrb.fr","otAQ7b","[6,[false,null,false],true,null,null,null,false,null,null,null,null,null,false,false,1016,[[\"id\",\"Flash\",null,null,null,null,null,true]]]"]]')" "gemini_batch_needs_stream_probe maps unsigned with enabled model"
assert_eq "no" "$(gemini_batch_needs_stream_probe '[["wrb.fr","otAQ7b","[6,[false,null,false],true,null,null,null,false,null,null,null,null,null,false,false,1016,[]]"]]')" "gemini_batch_needs_stream_probe maps unsigned without models"
assert_eq "no" "$(gemini_batch_needs_stream_probe '[["wrb.fr","otAQ7b","[6,[false,null,false],true,null,null,null,false,null,null,null,null,null,false,false,1016,[[\"id\",\"Flash\",null,null,null,null,null,false]]]"]]')" "gemini_batch_needs_stream_probe maps unsigned without enabled model"
assert_eq "no" "$(gemini_batch_needs_stream_probe '[["wrb.fr","otAQ7b","[6,[false,null,false],false,null,null,null,false,null,null,null,null,null,false,false,1060,[]]"]]')" "gemini_batch_needs_stream_probe maps location rejected"
assert_empty "$(gemini_batch_needs_stream_probe '')" "gemini_batch_needs_stream_probe handles empty input"

assert_eq "yes" "$(gemini_stream_generate_has_reply '[["wrb.fr",null,"[null,[\"c_x\",\"r_y\"],null,null,[[\"rc_z\",[\"Hello\"],null,null,null,null,true,null,[1],\"en\"]]]"]]')" "gemini_stream_generate_has_reply detects chat reply"
assert_eq "no" "$(gemini_stream_generate_has_reply '[["wrb.fr",null,"[null,[\"c_x\",\"r_y\"],null,null,[[\"rc_z\",[],null,null,null,null,true,null,[1],\"en\"]]]"]]')" "gemini_stream_generate_has_reply rejects empty reply"
assert_eq "no" "$(gemini_stream_generate_has_reply 'Gemini is not available in your country')" "gemini_stream_generate_has_reply rejects region message"
assert_eq "no" "$(gemini_stream_generate_has_reply '')" "gemini_stream_generate_has_reply handles empty input"
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

# Regression: literal "null" jq output must not void the whole result JSON
ASN_NUMBER="null"
ASN_NAME="null"
EXTERNAL_IPV4_TIMESTAMP="null"
RESULT_JSON=""
finalize_json
assert_eq "1.2.3.4" "$(process_json "$RESULT_JSON" ".ip.ipv4.address")" "finalize_json survives null strings"
assert_eq "null" "$(process_json "$RESULT_JSON" ".asn.number")" "finalize_json maps null asn number to json null"
assert_eq "null" "$(process_json "$RESULT_JSON" ".asn.name")" "finalize_json maps null asn name to json null"
assert_eq "null" "$(process_json "$RESULT_JSON" ".ip.ipv4.timestamp")" "finalize_json maps null timestamp to json null"

assert_eq "json" "$(detect_output_format "out.json")" "detect_output_format json"
assert_eq "csv" "$(detect_output_format "out.csv")" "detect_output_format csv"

# Regression: support checks must stop at the first failure
DNS_CALLED=false
check_ip_interfaces() { return 0; }
check_ip_connectivity() { return 1; }
check_ip_dns() {
  DNS_CALLED=true
  return 0
}

check_ip_support 4 >/dev/null 2>&1 || true
assert_false "check_ip_support stops at first failed check" test "$DNS_CALLED" = "true"

# Regression: normal EXIT trap must preserve the script's exit code
DEBUG=false
SPINNER_SERVICE_FILE=""
spinner_pid=""
trap_rc=0
(
  trap cleanup_on_exit EXIT
  exit 5
) >/dev/null 2>&1 || trap_rc=$?
assert_eq "5" "$trap_rc" "EXIT trap preserves exit code"

# cleanup_on_interrupt still terminates with 130
interrupt_rc=0
(cleanup_on_interrupt) >/dev/null 2>&1 || interrupt_rc=$?
assert_eq "130" "$interrupt_rc" "interrupt handler exits 130"

# Ported upstream services: YouTube CDN node parsing
assert_eq "FRA" "$(parse_youtube_cdn_iata 'fra05s09')" "parse_youtube_cdn_iata parses google node"
assert_eq "FRA" "$(parse_youtube_cdn_iata 'video-fra04s08')" "parse_youtube_cdn_iata parses isp node"
assert_eq "SIN" "$(parse_youtube_cdn_iata 'khsinb-dvbc')" "parse_youtube_cdn_iata parses ggc node"
assert_empty "$(parse_youtube_cdn_iata 'unparsable')" "parse_youtube_cdn_iata rejects unknown node"

# Ported upstream services: ChatGPT derived_fields extraction
CHATGPT_TEST_BODY='prelude {"other":{"a":1},"derived_fields":{"country":"US","region":"us-east"}}'
CHATGPT_TEST_FRAGMENT=$(grep_wrapper -oE '"derived_fields":\{[^}]*\}' <<<"$CHATGPT_TEST_BODY" | head -n 1)
assert_eq '{"country":"US","region":"us-east"}' "${CHATGPT_TEST_FRAGMENT#"$CHATGPT_DERIVED_FIELDS_PREFIX"}" "chatgpt derived_fields fragment extracted and prefix stripped"

# Ported upstream services: registry completeness
for service_key in TWITCH CHATGPT DISNEY_PLUS DISNEY_PLUS_ACCESS YOUTUBE_CDN; do
  assert_true "custom registry defines $service_key" test -n "${CUSTOM_SERVICES[$service_key]:-}"
  assert_true "custom handler defined for $service_key" test -n "${CUSTOM_SERVICES_HANDLERS[$service_key]:-}"
done

if [[ "$failures" -gt 0 ]]; then
  echo "$failures test(s) failed."
  exit 1
fi

echo "All tests passed."
