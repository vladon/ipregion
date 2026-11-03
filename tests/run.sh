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
for service_key in TWITCH CHATGPT DISNEY_PLUS DISNEY_PLUS_ACCESS YOUTUBE_CDN CLOUDFLARE_CDN REDDIT_GUEST_ACCESS NETFLIX NETFLIX_CDN NETFLIX_TRANSPORT SPOTIFY SPOTIFY_SIGNUP INSTAGRAM INSTAGRAM_API INSTAGRAM_TRANSPORT TIKTOK_ACCESS TIKTOK_TRANSPORT WHATSAPP WHATSAPP_DC TELEGRAM_ACCESS TELEGRAM_DC DISCORD_ACCESS DISCORD_GATEWAY GOOGLE_SEARCH_CAPTCHA GOOGLE_TRANSPORT TWITTER LINKEDIN_ACCESS YOUTUBE_PREMIUM_WEB YOUTUBE_TRANSPORT APPLE APPLE_TRANSPORT FACEBOOK_ACCESS FACEBOOK_API MESSENGER_ACCESS MESSENGER_MQTT THREADS_ACCESS THREADS_API THREADS_TRANSPORT SIGNAL_ACCESS SIGNAL_SERVICE MICROSOFT MICROSOFT_TRANSPORT STEAM STEAM_TRANSPORT RUTUBE_TRANSPORT OZON_TRANSPORT DOUYIN_CN VK VK_API OK_RU GROK DEEPSEEK PERPLEXITY COPILOT MISTRAL QWEN_WEB PEACOCK_ACCESS OPENAI_API ANTHROPIC_API XAI_API DEEPSEEK_API PERPLEXITY_API MISTRAL_API REDDIT_API OK_API LINKEDIN_API X_API BLUESKY SNAPCHAT PINTEREST TRUTH_SOCIAL WEIBO BILIBILI NETEASE_MUSIC TWITCH_SITE YANDEX MAIL_RU; do
  assert_true "custom registry defines $service_key" test -n "${CUSTOM_SERVICES[$service_key]:-}"
  assert_true "custom handler defined for $service_key" test -n "${CUSTOM_SERVICES_HANDLERS[$service_key]:-}"
done
assert_true "primary registry defines IPREGISTRY" test -n "${PRIMARY_SERVICES[IPREGISTRY]:-}"
assert_contains "${PRIMARY_SERVICES[IPREGISTRY]:-}" "hostname=true" "ipregistry url template kept"
assert_true "primary registry defines GEOAPIFY_COM" test -n "${PRIMARY_SERVICES[GEOAPIFY_COM]:-}"
assert_eq "CY" "$(process_response "GEOAPIFY_COM" '{"country":{"iso_code":"CY"}}' "geoapify.com" "json")" "process_response geoapify country filter"

# macOS portability: sed_capture replaces grep -P \K (BSD grep has no -P)
assert_eq "DE" "$(printf '%s' '"a":1,"sRequestCountry":"DE","b":2' | sed_capture '"sRequestCountry":"([^"]*)')" "sed_capture extracts capture group"
assert_empty "$(printf '%s' 'no match here' | sed_capture '"sRequestCountry":"([^"]*)')" "sed_capture returns empty without match"
# macOS portability: redaction works without the sed I flag (BSD sed)
printf 'Authorization: secret1\nset-cookie: abc=def\nurl=https://x/?api_key=zzz&ok=1\n' >"${TMPDIR:-/tmp}/ipregion_redact_probe.log"
redacted_probe=$(redact_debug_log "${TMPDIR:-/tmp}/ipregion_redact_probe.log")
assert_contains "$(cat "$redacted_probe")" "[REDACTED]" "redact masks Authorization case-insensitively without sed I flag"
assert_contains "$(cat "$redacted_probe")" "set-cookie: [REDACTED]" "redact masks lowercase set-cookie"
assert_contains "$(cat "$redacted_probe")" "api_key=[REDACTED]" "redact masks query parameter"
assert_contains "$(cat "$redacted_probe")" "&ok=1" "redact keeps neighbouring query parameters"
rm -f "${TMPDIR:-/tmp}/ipregion_redact_probe.log" "$redacted_probe"

# Ported upstream services: Reddit guest access status handling (curl_wrapper stubbed)
reddit_stub_wrapper() {
  if [[ -n "${REDDIT_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$REDDIT_STUB_RESPONSE"
  fi
}
curl_wrapper() { reddit_stub_wrapper "$@"; }
JSON_OUTPUT=true
REDDIT_STUB_RESPONSE="Denied"
assert_eq "No" "$(lookup_reddit_guest_access 4)" "reddit guest access maps Denied to No"
REDDIT_STUB_RESPONSE="normal page body"
assert_eq "Yes" "$(lookup_reddit_guest_access 4)" "reddit guest access maps page to Yes"
REDDIT_STUB_RESPONSE=""
assert_empty "$(lookup_reddit_guest_access 4)" "reddit guest access maps empty response to N/A"
REDDIT_STUB_RESPONSE="Rate-limit"
assert_eq "Rate-limit" "$(lookup_reddit_guest_access 4)" "reddit guest access passes other status strings through"
unset -f curl_wrapper reddit_stub_wrapper
unset REDDIT_STUB_RESPONSE

# Reinstated services: Spotify signup status matrix (curl_wrapper stubbed)
spotify_stub_wrapper() {
  if [[ -n "${SPOTIFY_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$SPOTIFY_STUB_RESPONSE"
  fi
}
curl_wrapper() { spotify_stub_wrapper "$@"; }
JSON_OUTPUT=true
SPOTIFY_STUB_RESPONSE='{"status":120,"is_country_launched":false,"country":"SE"}'
assert_eq "No" "$(lookup_spotify_signup 4)" "spotify signup maps status 120 to No"
SPOTIFY_STUB_RESPONSE='{"status":320,"is_country_launched":true,"country":"SE"}'
assert_eq "No" "$(lookup_spotify_signup 4)" "spotify signup maps status 320 to No"
SPOTIFY_STUB_RESPONSE='{"status":200,"is_country_launched":true,"country":"SE"}'
assert_eq "Yes" "$(lookup_spotify_signup 4)" "spotify signup maps launched country to Yes"
SPOTIFY_STUB_RESPONSE='{"status":200,"is_country_launched":false,"country":"SE"}'
assert_eq "No" "$(lookup_spotify_signup 4)" "spotify signup maps unlaunched country to No"
SPOTIFY_STUB_RESPONSE=""
assert_empty "$(lookup_spotify_signup 4)" "spotify signup maps empty response to N/A"
SPOTIFY_STUB_RESPONSE="Denied"
assert_eq "Denied" "$(lookup_spotify_signup 4)" "spotify signup passes status strings through"
unset -f curl_wrapper spotify_stub_wrapper
unset SPOTIFY_STUB_RESPONSE
JSON_OUTPUT=false

# Instagram availability check (curl_wrapper stubbed, meta file fixture)
instagram_stub_wrapper() {
  if [[ -n "${INSTAGRAM_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$INSTAGRAM_STUB_RESPONSE"
  fi
}
curl_wrapper() { instagram_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
INSTAGRAM_STUB_RESPONSE=""
assert_eq "No" "$(lookup_instagram 4)" "instagram maps transport failure to No"
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
INSTAGRAM_STUB_RESPONSE=""
assert_empty "$(lookup_instagram 4)" "instagram maps empty response without curl error to N/A"
INSTAGRAM_STUB_RESPONSE='<html><meta property="og:title" content="Instagram" /></html>'
assert_eq "Yes" "$(lookup_instagram 4)" "instagram maps page marker to Yes"
INSTAGRAM_STUB_RESPONSE='<html>captive portal</html>'
assert_eq "No" "$(lookup_instagram 4)" "instagram maps unmarked body to No"
INSTAGRAM_STUB_RESPONSE="Denied"
assert_eq "Denied" "$(lookup_instagram 4)" "instagram passes status strings through"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper instagram_stub_wrapper
unset INSTAGRAM_STUB_RESPONSE
JSON_OUTPUT=false

# TikTok access check shares lookup_site_access with Instagram
tiktok_stub_wrapper() {
  if [[ -n "${TIKTOK_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$TIKTOK_STUB_RESPONSE"
  fi
}
curl_wrapper() { tiktok_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
TIKTOK_STUB_RESPONSE=""
assert_eq "No" "$(lookup_tiktok_access 4)" "tiktok access maps transport failure to No"
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
TIKTOK_STUB_RESPONSE='<html><title>TikTok - Make Your Day</title></html>'
assert_eq "Yes" "$(lookup_tiktok_access 4)" "tiktok access maps page marker to Yes"
TIKTOK_STUB_RESPONSE='<html>captive portal</html>'
assert_eq "No" "$(lookup_tiktok_access 4)" "tiktok access maps unmarked body to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper tiktok_stub_wrapper
unset TIKTOK_STUB_RESPONSE
JSON_OUTPUT=false

# WhatsApp check shares lookup_site_access with Instagram and TikTok
whatsapp_stub_wrapper() {
  if [[ -n "${WHATSAPP_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$WHATSAPP_STUB_RESPONSE"
  fi
}
curl_wrapper() { whatsapp_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
WHATSAPP_STUB_RESPONSE=""
assert_eq "No" "$(lookup_whatsapp 4)" "whatsapp maps transport failure to No"
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
WHATSAPP_STUB_RESPONSE='<html><title>WhatsApp Web</title></html>'
assert_eq "Yes" "$(lookup_whatsapp 4)" "whatsapp maps page marker to Yes"
WHATSAPP_STUB_RESPONSE='<html>captive portal</html>'
assert_eq "No" "$(lookup_whatsapp 4)" "whatsapp maps unmarked body to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper whatsapp_stub_wrapper
unset WHATSAPP_STUB_RESPONSE
JSON_OUTPUT=false

# Telegram access check shares lookup_site_access with the other messengers
telegram_stub_wrapper() {
  if [[ -n "${TELEGRAM_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$TELEGRAM_STUB_RESPONSE"
  fi
}
curl_wrapper() { telegram_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
TELEGRAM_STUB_RESPONSE=""
assert_eq "No" "$(lookup_telegram_access 4)" "telegram access maps transport failure to No"
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
TELEGRAM_STUB_RESPONSE='<html><title>Telegram Web</title></html>'
assert_eq "Yes" "$(lookup_telegram_access 4)" "telegram access maps page marker to Yes"
TELEGRAM_STUB_RESPONSE='<html>captive portal</html>'
assert_eq "No" "$(lookup_telegram_access 4)" "telegram access maps unmarked body to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper telegram_stub_wrapper
unset TELEGRAM_STUB_RESPONSE
JSON_OUTPUT=false

# Discord access check shares lookup_site_access with the other messengers
discord_stub_wrapper() {
  if [[ -n "${DISCORD_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$DISCORD_STUB_RESPONSE"
  fi
}
curl_wrapper() { discord_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
DISCORD_STUB_RESPONSE=""
assert_eq "No" "$(lookup_discord_access 4)" "discord access maps transport failure to No"
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
DISCORD_STUB_RESPONSE='<html><title>Discord | Your Place to Talk and Hang Out</title></html>'
assert_eq "Yes" "$(lookup_discord_access 4)" "discord access maps page marker to Yes"
DISCORD_STUB_RESPONSE='<html>captive portal</html>'
assert_eq "No" "$(lookup_discord_access 4)" "discord access maps unmarked body to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper discord_stub_wrapper
unset DISCORD_STUB_RESPONSE
JSON_OUTPUT=false

# Twitter (X) access check shares lookup_site_access with the other messengers
twitter_stub_wrapper() {
  if [[ -n "${TWITTER_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$TWITTER_STUB_RESPONSE"
  fi
}
curl_wrapper() { twitter_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
TWITTER_STUB_RESPONSE=""
assert_eq "No" "$(lookup_twitter 4)" "twitter maps transport failure to No"
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
TWITTER_STUB_RESPONSE='<html><link rel="canonical" href="https://x.com/" /><title>X</title></html>'
assert_eq "Yes" "$(lookup_twitter 4)" "twitter maps page marker to Yes"
TWITTER_STUB_RESPONSE='<html>captive portal</html>'
assert_eq "No" "$(lookup_twitter 4)" "twitter maps unmarked body to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper twitter_stub_wrapper
unset TWITTER_STUB_RESPONSE
JSON_OUTPUT=false

# LinkedIn access check shares lookup_site_access with the other messengers
linkedin_stub_wrapper() {
  if [[ -n "${LINKEDIN_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$LINKEDIN_STUB_RESPONSE"
  fi
}
curl_wrapper() { linkedin_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
LINKEDIN_STUB_RESPONSE=""
assert_eq "No" "$(lookup_linkedin_access 4)" "linkedin access maps transport failure to No"
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
LINKEDIN_STUB_RESPONSE='<html><title>LinkedIn: Log In or Sign Up</title></html>'
assert_eq "Yes" "$(lookup_linkedin_access 4)" "linkedin access maps page marker to Yes"
LINKEDIN_STUB_RESPONSE='<html>captive portal</html>'
assert_eq "No" "$(lookup_linkedin_access 4)" "linkedin access maps unmarked body to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper linkedin_stub_wrapper
unset LINKEDIN_STUB_RESPONSE
JSON_OUTPUT=false

# YouTube Premium web-page check (curl_wrapper stubbed)
premium_web_stub_wrapper() {
  if [[ -n "${PREMIUM_WEB_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$PREMIUM_WEB_STUB_RESPONSE"
  fi
}
curl_wrapper() { premium_web_stub_wrapper "$@"; }
JSON_OUTPUT=true
PREMIUM_WEB_STUB_RESPONSE="Subscribe to YouTube Premium"
assert_eq "Yes" "$(lookup_youtube_premium_web 4)" "premium web maps marketing page to Yes"
PREMIUM_WEB_STUB_RESPONSE="YouTube Premium is not available in your country"
assert_eq "No" "$(lookup_youtube_premium_web 4)" "premium web maps unavailability banner to No"
PREMIUM_WEB_STUB_RESPONSE=""
assert_empty "$(lookup_youtube_premium_web 4)" "premium web maps empty response to N/A"
PREMIUM_WEB_STUB_RESPONSE="Denied"
assert_eq "Denied" "$(lookup_youtube_premium_web 4)" "premium web passes status strings through"
unset -f curl_wrapper premium_web_stub_wrapper
unset PREMIUM_WEB_STUB_RESPONSE
JSON_OUTPUT=false

# Social batch (Facebook/Messenger/Threads/Signal) share lookup_site_access
social_stub_wrapper() {
  local -n stub_var="$1"
  printf "%s" "${stub_var:-}"
}
curl_wrapper() { social_stub_wrapper "${SOCIAL_STUB_NAME}"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
SOCIAL_STUB_NAME="EMPTY_SOCIAL_STUB"
assert_eq "No" "$(lookup_facebook_access 4)" "facebook maps transport failure to No"
assert_eq "No" "$(lookup_messenger_access 4)" "messenger maps transport failure to No"
assert_eq "No" "$(lookup_threads_access 4)" "threads maps transport failure to No"
assert_eq "No" "$(lookup_signal_access 4)" "signal maps transport failure to No"
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
SOCIAL_STUB_NAME="PAGE_SOCIAL_STUB"
PAGE_SOCIAL_STUB='<html><title>platform page</title></html>'
assert_eq "No" "$(lookup_facebook_access 4)" "facebook maps unmarked body to No"
SOCIAL_STUB_NAME="MESSENGER_PAGE_STUB"
MESSENGER_PAGE_STUB='<html>messenger login</html>'
assert_eq "Yes" "$(lookup_messenger_access 4)" "messenger maps page marker to Yes"
SOCIAL_STUB_NAME="THREADS_PAGE_STUB"
THREADS_PAGE_STUB='<html>threads by instagram</html>'
assert_eq "Yes" "$(lookup_threads_access 4)" "threads maps page marker to Yes"
SOCIAL_STUB_NAME="SIGNAL_PAGE_STUB"
SIGNAL_PAGE_STUB='<html>Signal private messenger</html>'
assert_eq "Yes" "$(lookup_signal_access 4)" "signal maps page marker to Yes"
SOCIAL_STUB_NAME="FACEBOOK_PAGE_STUB"
FACEBOOK_PAGE_STUB='<html>facebook login</html>'
assert_eq "Yes" "$(lookup_facebook_access 4)" "facebook maps page marker to Yes"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper social_stub_wrapper
unset SOCIAL_STUB_NAME PAGE_SOCIAL_STUB MESSENGER_PAGE_STUB THREADS_PAGE_STUB SIGNAL_PAGE_STUB FACEBOOK_PAGE_STUB
JSON_OUTPUT=false

# Site availability batch (Bluesky…Mail.ru) shares lookup_site_access
site_stub_wrapper() {
  local -n stub_var="$1"
  printf "%s" "${stub_var:-}"
}
curl_wrapper() { site_stub_wrapper "${SITE_STUB_NAME}"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
SITE_STUB_NAME="UNMARKED_SITE_STUB"
UNMARKED_SITE_STUB='<html><title>portal</title></html>'
assert_eq "No" "$(lookup_bluesky 4)" "bluesky maps unmarked body to No"
assert_eq "No" "$(lookup_snapchat 4)" "snapchat maps unmarked body to No"
assert_eq "No" "$(lookup_pinterest 4)" "pinterest maps unmarked body to No"
assert_eq "No" "$(lookup_truth_social 4)" "truth social maps unmarked body to No"
assert_eq "No" "$(lookup_weibo 4)" "weibo maps unmarked body to No"
assert_eq "No" "$(lookup_bilibili 4)" "bilibili maps unmarked body to No"
assert_eq "No" "$(lookup_netease_music 4)" "netease music maps unmarked body to No"
assert_eq "No" "$(lookup_twitch_site 4)" "twitch site maps unmarked body to No"
assert_eq "No" "$(lookup_yandex 4)" "yandex maps unmarked body to No"
assert_eq "No" "$(lookup_mail_ru 4)" "mail ru maps unmarked body to No"
SITE_STUB_NAME="BLUESKY_PAGE_STUB"
BLUESKY_PAGE_STUB='<html>bluesky app</html>'
assert_eq "Yes" "$(lookup_bluesky 4)" "bluesky maps page marker to Yes"
SITE_STUB_NAME="SNAPCHAT_PAGE_STUB"
SNAPCHAT_PAGE_STUB='<html>snapchat app</html>'
assert_eq "Yes" "$(lookup_snapchat 4)" "snapchat maps page marker to Yes"
SITE_STUB_NAME="PINTEREST_PAGE_STUB"
PINTEREST_PAGE_STUB='<html>pinterest pins</html>'
assert_eq "Yes" "$(lookup_pinterest 4)" "pinterest maps page marker to Yes"
SITE_STUB_NAME="TRUTH_SOCIAL_PAGE_STUB"
TRUTH_SOCIAL_PAGE_STUB='<html>truthsocial feed</html>'
assert_eq "Yes" "$(lookup_truth_social 4)" "truth social maps page marker to Yes"
SITE_STUB_NAME="WEIBO_PAGE_STUB"
WEIBO_PAGE_STUB='<html>weibo feed</html>'
assert_eq "Yes" "$(lookup_weibo 4)" "weibo maps page marker to Yes"
SITE_STUB_NAME="BILIBILI_PAGE_STUB"
BILIBILI_PAGE_STUB='<html>bilibili tv</html>'
assert_eq "Yes" "$(lookup_bilibili 4)" "bilibili maps page marker to Yes"
SITE_STUB_NAME="NETEASE_MUSIC_PAGE_STUB"
NETEASE_MUSIC_PAGE_STUB='<html>netease music 163</html>'
assert_eq "Yes" "$(lookup_netease_music 4)" "netease music maps page marker to Yes"
SITE_STUB_NAME="TWITCH_SITE_PAGE_STUB"
TWITCH_SITE_PAGE_STUB='<html>twitch tv</html>'
assert_eq "Yes" "$(lookup_twitch_site 4)" "twitch site maps page marker to Yes"
SITE_STUB_NAME="YANDEX_PAGE_STUB"
YANDEX_PAGE_STUB='<html>yandex search</html>'
assert_eq "Yes" "$(lookup_yandex 4)" "yandex maps page marker to Yes"
SITE_STUB_NAME="MAIL_RU_PAGE_STUB"
MAIL_RU_PAGE_STUB='<html>mail.ru mail</html>'
assert_eq "Yes" "$(lookup_mail_ru 4)" "mail ru maps page marker to Yes"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper site_stub_wrapper
unset SITE_STUB_NAME UNMARKED_SITE_STUB BLUESKY_PAGE_STUB SNAPCHAT_PAGE_STUB PINTEREST_PAGE_STUB TRUTH_SOCIAL_PAGE_STUB WEIBO_PAGE_STUB BILIBILI_PAGE_STUB NETEASE_MUSIC_PAGE_STUB TWITCH_SITE_PAGE_STUB YANDEX_PAGE_STUB MAIL_RU_PAGE_STUB
JSON_OUTPUT=false

# Douyin region gate (curl_wrapper stubbed)
douyin_stub_wrapper() {
  if [[ -n "${DOUYIN_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$DOUYIN_STUB_RESPONSE"
  fi
}
curl_wrapper() { douyin_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
DOUYIN_STUB_RESPONSE='<html><title>抖音 - 记录美好生活</title></html>'
assert_eq "Yes" "$(lookup_douyin_cn 4)" "douyin maps CN SSR content to Yes"
DOUYIN_STUB_RESPONSE='<html><body></body><script>var glb;(_$jsvmprt=function(){})</script></html>'
assert_eq "No" "$(lookup_douyin_cn 4)" "douyin maps foreign bot-shell to No"
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
DOUYIN_STUB_RESPONSE=""
assert_eq "No" "$(lookup_douyin_cn 4)" "douyin maps transport failure to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper douyin_stub_wrapper
unset DOUYIN_STUB_RESPONSE
JSON_OUTPUT=false

# AI access checks share lookup_site_access
ai_stub_wrapper() {
  local -n stub_var="$1"
  printf "%s" "${stub_var:-}"
}
curl_wrapper() { ai_stub_wrapper "${AI_STUB_NAME}"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
AI_STUB_NAME="AI_EMPTY_STUB"
assert_eq "No" "$(lookup_grok 4)" "grok maps transport failure to No"
assert_eq "No" "$(lookup_deepseek 4)" "deepseek maps transport failure to No"
assert_eq "No" "$(lookup_perplexity 4)" "perplexity maps transport failure to No"
assert_eq "No" "$(lookup_copilot 4)" "copilot maps transport failure to No"
assert_eq "No" "$(lookup_mistral 4)" "mistral maps transport failure to No"
assert_eq "No" "$(lookup_qwen_web 4)" "qwen web maps transport failure to No"
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
AI_STUB_NAME="GROK_PAGE_STUB"
GROK_PAGE_STUB='<html>grok assistant</html>'
assert_eq "Yes" "$(lookup_grok 4)" "grok maps page marker to Yes"
AI_STUB_NAME="DEEPSEEK_PAGE_STUB"
DEEPSEEK_PAGE_STUB='<html>deepseek chat</html>'
assert_eq "Yes" "$(lookup_deepseek 4)" "deepseek maps page marker to Yes"
AI_STUB_NAME="PERPLEXITY_PAGE_STUB"
PERPLEXITY_PAGE_STUB='<html>perplexity search</html>'
assert_eq "Yes" "$(lookup_perplexity 4)" "perplexity maps page marker to Yes"
AI_STUB_NAME="COPILOT_PAGE_STUB"
COPILOT_PAGE_STUB='<html>copilot window</html>'
assert_eq "Yes" "$(lookup_copilot 4)" "copilot maps page marker to Yes"
AI_STUB_NAME="MISTRAL_PAGE_STUB"
MISTRAL_PAGE_STUB='<html>mistral le chat</html>'
assert_eq "Yes" "$(lookup_mistral 4)" "mistral maps page marker to Yes"
AI_STUB_NAME="QWEN_PAGE_STUB"
QWEN_PAGE_STUB='<html>qwen chat</html>'
assert_eq "Yes" "$(lookup_qwen_web 4)" "qwen web maps page marker to Yes"
AI_STUB_NAME="AI_UNMARKED_STUB"
AI_UNMARKED_STUB='<html>captive portal</html>'
assert_eq "No" "$(lookup_grok 4)" "ai checks map unmarked body to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper ai_stub_wrapper
unset AI_STUB_NAME GROK_PAGE_STUB DEEPSEEK_PAGE_STUB PERPLEXITY_PAGE_STUB COPILOT_PAGE_STUB MISTRAL_PAGE_STUB QWEN_PAGE_STUB AI_UNMARKED_STUB
JSON_OUTPUT=false

# Peacock region gate (curl_wrapper stubbed)
peacock_stub_wrapper() {
  if [[ -n "${PEACOCK_STUB_RESPONSE:-}" ]]; then
    printf "%s" "$PEACOCK_STUB_RESPONSE"
  fi
}
curl_wrapper() { peacock_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=200;latency_ms=100;error_type=none\n" >"$CURL_META_FILE"
PEACOCK_STUB_RESPONSE='<html><title>Unavailable In Your Region</title></html>'
assert_eq "No" "$(lookup_peacock_access 4)" "peacock maps region gate to No"
PEACOCK_STUB_RESPONSE='<html>stream peacock originals</html>'
assert_eq "Yes" "$(lookup_peacock_access 4)" "peacock maps brand page to Yes"
PEACOCK_STUB_RESPONSE='<html>captive portal</html>'
assert_eq "No" "$(lookup_peacock_access 4)" "peacock maps unmarked body to No"
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
PEACOCK_STUB_RESPONSE=""
assert_eq "No" "$(lookup_peacock_access 4)" "peacock maps transport failure to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper peacock_stub_wrapper
unset PEACOCK_STUB_RESPONSE
JSON_OUTPUT=false

# Telegram DC probe: tcp_probe against a closed local port (deterministic)
assert_false "tcp_probe reports closed port" tcp_probe 127.0.0.1 9

# Telegram DC handler verdicts (tcp_probe stubbed)
dc_probe_stub() {
  if [[ "${DC_PROBE_MODE:-}" == "up" ]]; then
    return 0
  fi
  return 1
}
tcp_probe() { dc_probe_stub "$@"; }
host_resolves() { [[ "${DNS_STUB_MODE:-ok}" == "ok" ]]; }
JSON_OUTPUT=true
DC_PROBE_MODE="up"
assert_eq "Yes" "$(lookup_telegram_dc 4)" "telegram dc maps reachable dc to Yes"
DC_PROBE_MODE="down"
assert_eq "No" "$(lookup_telegram_dc 4)" "telegram dc maps unreachable dc to No"
assert_eq "No" "$(lookup_whatsapp_dc 4)" "whatsapp dc maps unreachable dc to No"
assert_eq "No" "$(lookup_discord_gateway 4)" "discord gateway maps unreachable dc to No"
assert_eq "No" "$(lookup_instagram_api 4)" "instagram api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_threads_api 4)" "threads api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_signal_service 4)" "signal service maps unreachable endpoint to No"
assert_eq "No" "$(lookup_vk_api 4)" "vk api maps unreachable endpoint to No"
DC_PROBE_MODE="up"
assert_eq "Yes" "$(lookup_whatsapp_dc 4)" "whatsapp dc maps reachable dc to Yes"
assert_eq "Yes" "$(lookup_discord_gateway 4)" "discord gateway maps reachable dc to Yes"
assert_eq "Yes" "$(lookup_instagram_api 4)" "instagram api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_threads_api 4)" "threads api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_signal_service 4)" "signal service maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_vk_api 4)" "vk api maps reachable endpoint to Yes"
DC_PROBE_MODE="up"
assert_eq "Yes" "$(lookup_facebook_api 4)" "facebook api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_messenger_mqtt 4)" "messenger mqtt maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_tiktok_transport 4)" "tiktok transport maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_google_transport 4)" "google transport maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_youtube_transport 4)" "youtube transport maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_instagram_transport 4)" "instagram transport maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_threads_transport 4)" "threads transport maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_steam_transport 4)" "steam transport maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_netflix_transport 4)" "netflix transport maps reachable endpoint to Yes"
DC_PROBE_MODE="up"
assert_eq "Yes" "$(lookup_apple_transport 4)" "apple transport maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_microsoft_transport 4)" "microsoft transport maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_rutube_transport 4)" "rutube transport maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_ozon_transport 4)" "ozon transport maps reachable endpoint to Yes"
DC_PROBE_MODE="down"
assert_eq "No" "$(lookup_apple_transport 4)" "apple transport maps unreachable endpoint to No"
assert_eq "No" "$(lookup_microsoft_transport 4)" "microsoft transport maps unreachable endpoint to No"
assert_eq "No" "$(lookup_rutube_transport 4)" "rutube transport maps unreachable endpoint to No"
assert_eq "No" "$(lookup_ozon_transport 4)" "ozon transport maps unreachable endpoint to No"
DC_PROBE_MODE="down"
assert_eq "No" "$(lookup_facebook_api 4)" "facebook api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_messenger_mqtt 4)" "messenger mqtt maps unreachable endpoint to No"
assert_eq "No" "$(lookup_tiktok_transport 4)" "tiktok transport maps unreachable endpoint to No"
assert_eq "No" "$(lookup_google_transport 4)" "google transport maps unreachable endpoint to No"
assert_eq "No" "$(lookup_youtube_transport 4)" "youtube transport maps unreachable endpoint to No"
assert_eq "No" "$(lookup_instagram_transport 4)" "instagram transport maps unreachable endpoint to No"
assert_eq "No" "$(lookup_threads_transport 4)" "threads transport maps unreachable endpoint to No"
assert_eq "No" "$(lookup_steam_transport 4)" "steam transport maps unreachable endpoint to No"
assert_eq "No" "$(lookup_netflix_transport 4)" "netflix transport maps unreachable endpoint to No"
DNS_STUB_MODE="blocked"
DC_PROBE_MODE="up"
assert_eq "DNS block" "$(lookup_telegram_dc 4)" "telegram dc maps failed resolution to DNS block"
assert_eq "DNS block" "$(lookup_netflix_transport 4)" "netflix transport maps failed resolution to DNS block"
DNS_STUB_MODE="ok"
DC_PROBE_MODE="up"
assert_eq "Yes" "$(lookup_openai_api 4)" "openai api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_anthropic_api 4)" "anthropic api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_xai_api 4)" "xai api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_deepseek_api 4)" "deepseek api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_perplexity_api 4)" "perplexity api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_mistral_api 4)" "mistral api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_reddit_api 4)" "reddit api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_ok_api 4)" "ok api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_linkedin_api 4)" "linkedin api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_x_api 4)" "x api maps reachable endpoint to Yes"
DC_PROBE_MODE="down"
assert_eq "No" "$(lookup_openai_api 4)" "openai api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_anthropic_api 4)" "anthropic api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_xai_api 4)" "xai api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_deepseek_api 4)" "deepseek api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_perplexity_api 4)" "perplexity api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_mistral_api 4)" "mistral api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_reddit_api 4)" "reddit api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_ok_api 4)" "ok api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_linkedin_api 4)" "linkedin api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_x_api 4)" "x api maps unreachable endpoint to No"
unset -f tcp_probe dc_probe_stub host_resolves
unset DC_PROBE_MODE DNS_STUB_MODE
JSON_OUTPUT=false

if [[ "$failures" -gt 0 ]]; then
  echo "$failures test(s) failed."
  exit 1
fi

echo "All tests passed."
