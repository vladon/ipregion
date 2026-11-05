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
add_result "cdn" "YouTube CDN" "US" "" "" ""
add_result "devinfra" "Docker Hub" "US" "" "" ""

finalize_json

assert_eq "1.2.3.4" "$(process_json "$RESULT_JSON" ".ip.ipv4.address")" "finalize_json includes ipv4 address"
assert_eq "ident.me" "$(process_json "$RESULT_JSON" ".ip.ipv4.source")" "finalize_json includes ipv4 source"
assert_eq "true" "$(process_json "$RESULT_JSON" ".ip.ipv6.cache_hit")" "finalize_json includes cache hit flag"
assert_eq "United States" "$(process_json "$RESULT_JSON" ".ip.ipv4.registered_country")" "finalize_json includes registered country"
assert_eq "15169" "$(process_json "$RESULT_JSON" ".asn.number")" "finalize_json includes ASN number"
assert_eq "US" "$(process_json "$RESULT_JSON" ".consensus.ipv4.country")" "finalize_json computes ipv4 consensus"
assert_eq "200" "$(process_json "$RESULT_JSON" ".results.primary[0].metrics.ipv4.http_code")" "finalize_json parses metrics"
assert_eq "http_429" "$(process_json "$RESULT_JSON" ".results.primary[1].metrics.ipv6.error_type")" "finalize_json keeps error_type"
assert_eq "YouTube CDN" "$(process_json "$RESULT_JSON" ".results.cdn[0].service")" "finalize_json includes cdn results"
assert_eq "Docker Hub" "$(process_json "$RESULT_JSON" ".results.devinfra[0].service")" "finalize_json includes devinfra results"

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
for service_key in TWITCH CHATGPT DISNEY_PLUS DISNEY_PLUS_ACCESS REDDIT_GUEST_ACCESS NETFLIX NETFLIX_TRANSPORT SPOTIFY SPOTIFY_SIGNUP INSTAGRAM INSTAGRAM_API INSTAGRAM_TRANSPORT TIKTOK_ACCESS TIKTOK_TRANSPORT WHATSAPP WHATSAPP_DC TELEGRAM_ACCESS TELEGRAM_DC DISCORD_ACCESS DISCORD_GATEWAY GOOGLE_SEARCH_CAPTCHA GOOGLE_TRANSPORT TWITTER LINKEDIN_ACCESS YOUTUBE_PREMIUM_WEB YOUTUBE_TRANSPORT APPLE APPLE_TRANSPORT FACEBOOK_ACCESS FACEBOOK_API MESSENGER_ACCESS MESSENGER_MQTT THREADS_ACCESS THREADS_API THREADS_TRANSPORT SIGNAL_ACCESS SIGNAL_SERVICE MICROSOFT MICROSOFT_TRANSPORT STEAM STEAM_TRANSPORT RUTUBE_TRANSPORT OZON_TRANSPORT DOUYIN_CN VK VK_API OK_RU GROK DEEPSEEK PERPLEXITY COPILOT MISTRAL QWEN_WEB GEMINI_NOTEBOOK PEACOCK_ACCESS OPENAI_API ANTHROPIC_API XAI_API DEEPSEEK_API PERPLEXITY_API MISTRAL_API REDDIT_API OK_API LINKEDIN_API X_API BLUESKY SNAPCHAT PINTEREST TRUTH_SOCIAL WEIBO BILIBILI NETEASE_MUSIC TWITCH_SITE YANDEX MAIL_RU STEAM_API DISCORD_API TWITTER_LEGACY_API YOUTUBE_API BING DUCKDUCKGO BRAVE_SEARCH TWITCH_API TWITCH_CHAT FACEBOOK_CDN GROQ_API OPENROUTER COHERE_API ELEVENLABS_API TEAMS OUTLOOK AZURE_PORTAL VIBER SLACK ZOOM LINE DOH_GOOGLE DOH_CLOUDFLARE GMAIL GOOGLE_DRIVE PLAY_STORE APP_STORE AWS GCP_CONSOLE ORACLE_CLOUD ONEDRIVE WECHAT BAIDU ALIPAY PROTON DROPBOX MEGA EPIC_GAMES BATTLE_NET MINECRAFT_SESSION ROBLOX ROBLOX_API RIOT XBOX STRIPE_API PAYPAL WISE GEMINI_API AI_STUDIO GOOGLE_MEET GOOGLE_PHOTOS GOOGLE_CALENDAR YOUTUBE_MUSIC APPLE_MUSIC SOUNDCLOUD DEEZER DISCORD_CDN WECHAT_API KAKAOTALK THREEMA NOTION FIGMA MIRO CANVA TRELLO MEDIUM WIKIPEDIA STACK_OVERFLOW HABR DEEPL CHARACTER_AI POE GOOGLE_TRANSLATE HETZNER DIGITALOCEAN VULTR MATRIX NTFY TELEGRAM_BOT_API; do
  assert_true "custom registry defines $service_key" test -n "${CUSTOM_SERVICES[$service_key]:-}"
  assert_true "custom handler defined for $service_key" test -n "${CUSTOM_SERVICES_HANDLERS[$service_key]:-}"
done
for service_key in GITHUB GITHUB_API GITHUB_CODELOAD GITHUB_RAW GITLAB GITLAB_API NPM_REGISTRY PYPI DOCKER_HUB DOCKER_HUB_API GO_MODULES CRATES_IO MAVEN_CENTRAL HUGGING_FACE; do
  assert_true "devinfra registry defines $service_key" test -n "${DEVINFRA_SERVICES[$service_key]:-}"
  assert_true "devinfra handler defined for $service_key" test -n "${CUSTOM_SERVICES_HANDLERS[$service_key]:-}"
done
assert_true "devinfra group lists devinfra services" test "${SERVICE_GROUPS[devinfra]}" == "${DEVINFRA_SERVICES_ORDER[*]}"
assert_true "include-service validation accepts cdn service" validate_known_service YOUTUBE_CDN
assert_true "include-service validation accepts devinfra service" validate_known_service DOCKER_HUB
assert_false "include-service validation rejects unknown service" validate_known_service TOTALLY_UNKNOWN
for service_key in YOUTUBE_CDN CLOUDFLARE_CDN NETFLIX_CDN; do
  assert_true "cdn registry defines $service_key" test -n "${CDN_SERVICES[$service_key]:-}"
  assert_true "cdn handler defined for $service_key" test -n "${CUSTOM_SERVICES_HANDLERS[$service_key]:-}"
done
assert_true "cdn group lists cdn services" test "${SERVICE_GROUPS[cdn]}" == "${CDN_SERVICES_ORDER[*]}"
assert_true "primary registry defines IPREGISTRY" test -n "${PRIMARY_SERVICES[IPREGISTRY]:-}"
assert_contains "${PRIMARY_SERVICES[IPREGISTRY]:-}" "hostname=true" "ipregistry url template kept"
assert_true "primary registry defines GEOAPIFY_COM" test -n "${PRIMARY_SERVICES[GEOAPIFY_COM]:-}"
assert_eq "CY" "$(process_response "GEOAPIFY_COM" '{"country":{"iso_code":"CY"}}' "geoapify.com" "json")" "process_response geoapify country filter"
assert_eq "US" "$(process_response "DETECTOR404" '{"data":{"country":{"ccode":"us"}}}' "geoip.detector404.ru" "json")" "process_response detector404 uppercases country code"

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
SITE_STUB_NAME="GITHUB_PAGE_STUB"
GITHUB_PAGE_STUB='<html>Octocat developer platform</html>'
assert_eq "No" "$(lookup_github 4)" "github maps unmarked body to No"
GITHUB_PAGE_STUB='<html>github Octocat</html>'
assert_eq "Yes" "$(lookup_github 4)" "github maps page marker to Yes"
SITE_STUB_NAME="UNMARKED_SEARCH_STUB"
UNMARKED_SEARCH_STUB='<html>search portal</html>'
assert_eq "No" "$(lookup_bing 4)" "bing maps unmarked body to No"
SITE_STUB_NAME="BING_PAGE_STUB"
BING_PAGE_STUB='<html>bing search</html>'
assert_eq "Yes" "$(lookup_bing 4)" "bing maps page marker to Yes"
SITE_STUB_NAME="DUCKDUCKGO_PAGE_STUB"
DUCKDUCKGO_PAGE_STUB='<html>duckduckgo private search</html>'
assert_eq "Yes" "$(lookup_duckduckgo 4)" "duckduckgo maps page marker to Yes"
SITE_STUB_NAME="BRAVE_PAGE_STUB"
BRAVE_PAGE_STUB='<html>brave search engine</html>'
assert_eq "Yes" "$(lookup_brave_search 4)" "brave search maps page marker to Yes"
SITE_STUB_NAME="UNMARKED_SEARCH_STUB"
assert_eq "No" "$(lookup_duckduckgo 4)" "duckduckgo maps unmarked body to No"
assert_eq "No" "$(lookup_brave_search 4)" "brave search maps unmarked body to No"
SITE_STUB_NAME="WECHAT_PAGE_STUB"
WECHAT_PAGE_STUB='<html>weixin wechat login</html>'
assert_eq "Yes" "$(lookup_wechat 4)" "wechat maps page marker to Yes"
SITE_STUB_NAME="BAIDU_PAGE_STUB"
BAIDU_PAGE_STUB='<html>baidu search cn</html>'
assert_eq "Yes" "$(lookup_baidu 4)" "baidu maps page marker to Yes"
SITE_STUB_NAME="ALIPAY_PAGE_STUB"
ALIPAY_PAGE_STUB='<html>alipay china</html>'
assert_eq "Yes" "$(lookup_alipay 4)" "alipay maps page marker to Yes"
SITE_STUB_NAME="UNMARKED_CN_STUB"
UNMARKED_CN_STUB='<html>cn portal</html>'
assert_eq "No" "$(lookup_wechat 4)" "wechat maps unmarked body to No"
assert_eq "No" "$(lookup_baidu 4)" "baidu maps unmarked body to No"
assert_eq "No" "$(lookup_alipay 4)" "alipay maps unmarked body to No"
SITE_STUB_NAME="NOTION_PAGE_STUB"
NOTION_PAGE_STUB='<html>notion workspace</html>'
assert_eq "Yes" "$(lookup_notion 4)" "notion maps page marker to Yes"
SITE_STUB_NAME="FIGMA_PAGE_STUB"
FIGMA_PAGE_STUB='<html>figma design tool</html>'
assert_eq "Yes" "$(lookup_figma 4)" "figma maps page marker to Yes"
SITE_STUB_NAME="MIRO_PAGE_STUB"
MIRO_PAGE_STUB='<html>miro whiteboard</html>'
assert_eq "Yes" "$(lookup_miro 4)" "miro maps page marker to Yes"
SITE_STUB_NAME="CANVA_PAGE_STUB"
CANVA_PAGE_STUB='<html>canva design</html>'
assert_eq "Yes" "$(lookup_canva 4)" "canva maps page marker to Yes"
SITE_STUB_NAME="TRELLO_PAGE_STUB"
TRELLO_PAGE_STUB='<html>trello boards</html>'
assert_eq "Yes" "$(lookup_trello 4)" "trello maps page marker to Yes"
SITE_STUB_NAME="MEDIUM_PAGE_STUB"
MEDIUM_PAGE_STUB='<html>medium stories</html>'
assert_eq "Yes" "$(lookup_medium 4)" "medium maps page marker to Yes"
SITE_STUB_NAME="WIKIPEDIA_PAGE_STUB"
WIKIPEDIA_PAGE_STUB='<html>wikipedia encyclopedia</html>'
assert_eq "Yes" "$(lookup_wikipedia 4)" "wikipedia maps page marker to Yes"
SITE_STUB_NAME="STACK_OVERFLOW_PAGE_STUB"
STACK_OVERFLOW_PAGE_STUB='<html>stackoverflow questions</html>'
assert_eq "Yes" "$(lookup_stack_overflow 4)" "stack overflow maps page marker to Yes"
SITE_STUB_NAME="HABR_PAGE_STUB"
HABR_PAGE_STUB='<html>habr articles</html>'
assert_eq "Yes" "$(lookup_habr 4)" "habr maps page marker to Yes"
SITE_STUB_NAME="CHARACTER_AI_PAGE_STUB"
CHARACTER_AI_PAGE_STUB='<html>character ai chat</html>'
assert_eq "Yes" "$(lookup_character_ai 4)" "character ai maps page marker to Yes"
SITE_STUB_NAME="POE_PAGE_STUB"
POE_PAGE_STUB='<html>poe ai chat</html>'
assert_eq "Yes" "$(lookup_poe 4)" "poe maps page marker to Yes"
SITE_STUB_NAME="GOOGLE_TRANSLATE_PAGE_STUB"
GOOGLE_TRANSLATE_PAGE_STUB='<html>google translate service</html>'
assert_eq "Yes" "$(lookup_google_translate 4)" "google translate maps page marker to Yes"
SITE_STUB_NAME="UNMARKED_KQ_STUB"
UNMARKED_KQ_STUB='<html>portal</html>'
assert_eq "No" "$(lookup_notion 4)" "notion maps unmarked body to No"
assert_eq "No" "$(lookup_figma 4)" "figma maps unmarked body to No"
assert_eq "No" "$(lookup_miro 4)" "miro maps unmarked body to No"
assert_eq "No" "$(lookup_canva 4)" "canva maps unmarked body to No"
assert_eq "No" "$(lookup_trello 4)" "trello maps unmarked body to No"
assert_eq "No" "$(lookup_medium 4)" "medium maps unmarked body to No"
assert_eq "No" "$(lookup_wikipedia 4)" "wikipedia maps unmarked body to No"
assert_eq "No" "$(lookup_stack_overflow 4)" "stack overflow maps unmarked body to No"
assert_eq "No" "$(lookup_habr 4)" "habr maps unmarked body to No"
assert_eq "No" "$(lookup_character_ai 4)" "character ai maps unmarked body to No"
assert_eq "No" "$(lookup_poe 4)" "poe maps unmarked body to No"
assert_eq "No" "$(lookup_google_translate 4)" "google translate maps unmarked body to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper site_stub_wrapper
unset SITE_STUB_NAME UNMARKED_SITE_STUB BLUESKY_PAGE_STUB SNAPCHAT_PAGE_STUB PINTEREST_PAGE_STUB TRUTH_SOCIAL_PAGE_STUB WEIBO_PAGE_STUB BILIBILI_PAGE_STUB NETEASE_MUSIC_PAGE_STUB TWITCH_SITE_PAGE_STUB YANDEX_PAGE_STUB MAIL_RU_PAGE_STUB GITHUB_PAGE_STUB BING_PAGE_STUB DUCKDUCKGO_PAGE_STUB BRAVE_PAGE_STUB UNMARKED_SEARCH_STUB WECHAT_PAGE_STUB BAIDU_PAGE_STUB ALIPAY_PAGE_STUB UNMARKED_CN_STUB NOTION_PAGE_STUB FIGMA_PAGE_STUB MIRO_PAGE_STUB CANVA_PAGE_STUB TRELLO_PAGE_STUB MEDIUM_PAGE_STUB WIKIPEDIA_PAGE_STUB STACK_OVERFLOW_PAGE_STUB HABR_PAGE_STUB CHARACTER_AI_PAGE_STUB POE_PAGE_STUB GOOGLE_TRANSLATE_PAGE_STUB UNMARKED_KQ_STUB
JSON_OUTPUT=false

# Gemini Notebook / NotebookLM region gate (curl_wrapper stubbed; gate
# and app signs live in effective/redirect URLs recorded in
# CURL_META_FILE). One stub step per probe attempt:
#   http_code|body|effective_url|redirect_url   (code 0 = transport error)
# The step index persists in a file: the stub runs inside the handler's
# command substitution, where plain variable increments are discarded.
notebooklm_stub_wrapper() {
  local idx=0
  if [[ -n "${NOTEBOOKLM_STUB_COUNTS:-}" ]]; then
    idx=$(($(cat "$NOTEBOOKLM_STUB_COUNTS" 2>/dev/null || echo 0) + 1))
    printf '%s' "$idx" >"$NOTEBOOKLM_STUB_COUNTS"
  fi
  local step="${NOTEBOOKLM_STUB_STEPS[$((idx - 1))]:-}"
  local code body eff red
  IFS='|' read -r code body eff red <<<"$step"
  if [[ -n "$CURL_META_FILE" ]]; then
    printf "http_code=%s;latency_ms=100;error_type=none;effective_url=%s;redirect_url=%s\n" \
      "$code" "$eff" "$red" >"$CURL_META_FILE"
  fi
  [[ "$code" == "0" ]] && return
  printf "%s" "$body"
}
curl_wrapper() { notebooklm_stub_wrapper "$@"; }
run_notebooklm_scenario() {
  : >"${NOTEBOOKLM_STUB_COUNTS:-/dev/null}"
  lookup_gemini_notebook 4
}
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
NOTEBOOKLM_STUB_COUNTS=$(mktemp)
: >"$NOTEBOOKLM_STUB_COUNTS"

# Three successful application responses across both app domains
NOTEBOOKLM_STUB_STEPS=(
  "200|<html>notebooklm app</html>|https://notebooklm.google.com/|"
  "200|<html>Gemini Notebook app shell</html>|https://notebook.google.com/|https://notebooklm.google.com/"
  "200|<html>gemini notebook app shell</html>|https://notebook.google.com/?authuser=0|https://notebook.google.com/"
)
assert_eq "Yes" "$(run_notebooklm_scenario)" "gemini notebook: three app responses on both domains is Yes"

# The gate confirms No even when the remaining attempts are clean
NOTEBOOKLM_STUB_STEPS=(
  "200|<html>notebooklm app</html>|https://notebooklm.google.com/|"
  "200|<html>unsupported landing</html>|https://notebooklm.google?location=unsupported|"
  "200|<html>notebooklm app</html>|https://notebooklm.google.com/|"
)
assert_eq "No" "$(run_notebooklm_scenario)" "gemini notebook: gate in one attempt is No"

# Gate marker in an intermediate redirect Location
NOTEBOOKLM_STUB_STEPS=(
  "200|<html>notebooklm app</html>|https://notebook.google.com/|https://notebooklm.google?location=unsupported"
)
assert_eq "No" "$(run_notebooklm_scenario)" "gemini notebook: intermediate gate redirect is No"

# Percent-encoded gate parameter
NOTEBOOKLM_STUB_STEPS=(
  "200|<html>unsupported landing</html>|https://notebooklm.google?location%3Dunsupported|"
)
assert_eq "No" "$(run_notebooklm_scenario)" "gemini notebook: percent-encoded gate is No"

# A single success among transport failures is not Yes
NOTEBOOKLM_STUB_STEPS=(
  "200|<html>notebooklm app</html>|https://notebooklm.google.com/|"
  "0|||"
  "0|||"
)
assert_empty "$(run_notebooklm_scenario)" "gemini notebook: one success among transport errors is N/A"

# Redirect to Google sign-in is not the application
NOTEBOOKLM_STUB_STEPS=(
  "200|<html>sign in</html>|https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fnotebooklm.google.com%2F|"
  "200|<html>sign in</html>|https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fnotebooklm.google.com%2F|"
  "200|<html>sign in</html>|https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fnotebooklm.google.com%2F|"
)
assert_empty "$(run_notebooklm_scenario)" "gemini notebook: sign-in redirect is N/A"

# The marketing page without a region parameter is not the application
NOTEBOOKLM_STUB_STEPS=(
  "200|<html>Gemini Notebook marketing</html>|https://notebook.google/|"
  "200|<html>Gemini Notebook marketing</html>|https://notebook.google/|"
  "200|<html>Gemini Notebook marketing</html>|https://notebook.google/|"
)
assert_empty "$(run_notebooklm_scenario)" "gemini notebook: marketing page is N/A"

# CAPTCHA pages are not the application
NOTEBOOKLM_STUB_STEPS=(
  "200|<html>recaptcha captcha challenge</html>|https://notebooklm.google.com/|"
  "200|<html>recaptcha captcha challenge</html>|https://notebooklm.google.com/|"
  "200|<html>recaptcha captcha challenge</html>|https://notebooklm.google.com/|"
)
assert_empty "$(run_notebooklm_scenario)" "gemini notebook: captcha page is N/A"

# Empty application responses are undetermined
NOTEBOOKLM_STUB_STEPS=(
  "200||https://notebooklm.google.com/|"
  "200||https://notebooklm.google.com/|"
  "200||https://notebooklm.google.com/|"
)
assert_empty "$(run_notebooklm_scenario)" "gemini notebook: empty app responses are N/A"

# HTTP 429 and 5xx are undetermined
NOTEBOOKLM_STUB_STEPS=(
  "429|Rate-limit|https://notebooklm.google.com/|"
  "429|Rate-limit|https://notebooklm.google.com/|"
  "429|Rate-limit|https://notebooklm.google.com/|"
)
assert_empty "$(run_notebooklm_scenario)" "gemini notebook: 429 is N/A"
NOTEBOOKLM_STUB_STEPS=(
  "500|Server error|https://notebooklm.google.com/|"
  "500|Server error|https://notebooklm.google.com/|"
  "500|Server error|https://notebooklm.google.com/|"
)
assert_empty "$(run_notebooklm_scenario)" "gemini notebook: 5xx is N/A"

# Transport errors and timeouts are undetermined
NOTEBOOKLM_STUB_STEPS=(
  "0|||"
  "0|||"
  "0|||"
)
assert_empty "$(run_notebooklm_scenario)" "gemini notebook: transport errors and timeouts are N/A"

rm -f "$CURL_META_FILE" "$NOTEBOOKLM_STUB_COUNTS"
CURL_META_FILE=""
unset -f curl_wrapper notebooklm_stub_wrapper run_notebooklm_scenario
unset NOTEBOOKLM_STUB_STEPS NOTEBOOKLM_STUB_INDEX NOTEBOOKLM_STUB_COUNTS
JSON_OUTPUT=false

# DeepL region gate (curl_wrapper stubbed; RU gets HTTP 451 with a
# server-rendered "Unavailable in your region" page)
deepl_stub_wrapper() {
  local url="$2"
  printf "%s" "${DEEPL_STUB_RESPONSE:-}"
}
curl_wrapper() { deepl_stub_wrapper "$@"; }
JSON_OUTPUT=true
CURL_META_FILE=$(mktemp)
printf "http_code=451;latency_ms=100;error_type=http_451\n" >"$CURL_META_FILE"
DEEPL_STUB_RESPONSE="Region blocked"
assert_eq "Region blocked" "$(lookup_deepl 4)" "deepl passes 451 region blocked status through"
DEEPL_STUB_RESPONSE='<html>Unavailable in your region</html>'
assert_eq "No" "$(lookup_deepl 4)" "deepl maps region gate page to No"
DEEPL_STUB_RESPONSE='<html>deepl translator</html>'
assert_eq "Yes" "$(lookup_deepl 4)" "deepl maps brand page to Yes"
DEEPL_STUB_RESPONSE='<html>portal</html>'
assert_eq "No" "$(lookup_deepl 4)" "deepl maps unmarked body to No"
printf "http_code=;latency_ms=;error_type=curl_error\n" >"$CURL_META_FILE"
DEEPL_STUB_RESPONSE=""
assert_eq "No" "$(lookup_deepl 4)" "deepl maps transport failure to No"
rm -f "$CURL_META_FILE"
CURL_META_FILE=""
unset -f curl_wrapper deepl_stub_wrapper
unset DEEPL_STUB_RESPONSE
JSON_OUTPUT=false

assert_eq "Region blocked" "$(status_from_http_code 451)" "status_from_http_code maps 451"

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
assert_eq "Yes" "$(lookup_twitter_legacy_api 4)" "twitter legacy api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_github_api 4)" "github api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_gitlab 4)" "gitlab maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_gitlab_api 4)" "gitlab api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_steam_api 4)" "steam api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_discord_api 4)" "discord api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_youtube_api 4)" "youtube api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_github_raw 4)" "github raw maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_npm_registry 4)" "npm registry maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_pypi 4)" "pypi maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_docker_hub 4)" "docker hub maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_hugging_face 4)" "hugging face maps reachable endpoint to Yes"
DC_PROBE_MODE="up"
assert_eq "Yes" "$(lookup_twitch_api 4)" "twitch api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_twitch_chat 4)" "twitch chat maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_facebook_cdn 4)" "facebook cdn maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_groq_api 4)" "groq api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_openrouter 4)" "openrouter maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_cohere_api 4)" "cohere api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_elevenlabs_api 4)" "elevenlabs api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_teams 4)" "teams maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_outlook 4)" "outlook maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_azure_portal 4)" "azure portal maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_viber 4)" "viber maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_slack 4)" "slack maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_zoom 4)" "zoom maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_doh_google 4)" "doh google maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_doh_cloudflare 4)" "doh cloudflare maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_line 4)" "line maps reachable endpoint to Yes"
DC_PROBE_MODE="up"
assert_eq "Yes" "$(lookup_gmail 4)" "gmail maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_proton 4)" "proton maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_google_drive 4)" "google drive maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_dropbox 4)" "dropbox maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_onedrive 4)" "onedrive maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_mega 4)" "mega maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_epic_games 4)" "epic games maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_battle_net 4)" "battle net maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_roblox 4)" "roblox maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_riot 4)" "riot maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_xbox 4)" "xbox maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_app_store 4)" "app store maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_play_store 4)" "play store maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_aws 4)" "aws maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_gcp_console 4)" "gcp console maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_oracle_cloud 4)" "oracle cloud maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_stripe_api 4)" "stripe api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_paypal 4)" "paypal maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_wise 4)" "wise maps reachable endpoint to Yes"
DC_PROBE_MODE="up"
assert_eq "Yes" "$(lookup_gemini_api 4)" "gemini api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_ai_studio 4)" "ai studio maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_google_meet 4)" "google meet maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_google_photos 4)" "google photos maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_google_calendar 4)" "google calendar maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_youtube_music 4)" "youtube music maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_apple_music 4)" "apple music maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_soundcloud 4)" "soundcloud maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_deezer 4)" "deezer maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_discord_cdn 4)" "discord cdn maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_minecraft_session 4)" "minecraft session maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_roblox_api 4)" "roblox api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_wechat_api 4)" "wechat api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_kakaotalk 4)" "kakaotalk maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_threema 4)" "threema maps reachable endpoint to Yes"
DC_PROBE_MODE="up"
assert_eq "Yes" "$(lookup_docker_hub_api 4)" "docker hub api maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_go_modules 4)" "go modules maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_crates_io 4)" "crates io maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_maven_central 4)" "maven central maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_hetzner 4)" "hetzner maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_digitalocean 4)" "digitalocean maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_vultr 4)" "vultr maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_matrix 4)" "matrix maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_ntfy 4)" "ntfy maps reachable endpoint to Yes"
assert_eq "Yes" "$(lookup_telegram_bot_api 4)" "telegram bot api maps reachable endpoint to Yes"
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
assert_eq "No" "$(lookup_twitter_legacy_api 4)" "twitter legacy api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_github_api 4)" "github api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_gitlab 4)" "gitlab maps unreachable endpoint to No"
assert_eq "No" "$(lookup_gitlab_api 4)" "gitlab api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_steam_api 4)" "steam api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_discord_api 4)" "discord api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_youtube_api 4)" "youtube api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_github_raw 4)" "github raw maps unreachable endpoint to No"
assert_eq "No" "$(lookup_npm_registry 4)" "npm registry maps unreachable endpoint to No"
assert_eq "No" "$(lookup_pypi 4)" "pypi maps unreachable endpoint to No"
assert_eq "No" "$(lookup_docker_hub 4)" "docker hub maps unreachable endpoint to No"
assert_eq "No" "$(lookup_hugging_face 4)" "hugging face maps unreachable endpoint to No"
DC_PROBE_MODE="down"
assert_eq "No" "$(lookup_twitch_api 4)" "twitch api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_twitch_chat 4)" "twitch chat maps unreachable endpoint to No"
assert_eq "No" "$(lookup_facebook_cdn 4)" "facebook cdn maps unreachable endpoint to No"
assert_eq "No" "$(lookup_groq_api 4)" "groq api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_openrouter 4)" "openrouter maps unreachable endpoint to No"
assert_eq "No" "$(lookup_cohere_api 4)" "cohere api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_elevenlabs_api 4)" "elevenlabs api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_teams 4)" "teams maps unreachable endpoint to No"
assert_eq "No" "$(lookup_outlook 4)" "outlook maps unreachable endpoint to No"
assert_eq "No" "$(lookup_azure_portal 4)" "azure portal maps unreachable endpoint to No"
assert_eq "No" "$(lookup_viber 4)" "viber maps unreachable endpoint to No"
assert_eq "No" "$(lookup_slack 4)" "slack maps unreachable endpoint to No"
assert_eq "No" "$(lookup_zoom 4)" "zoom maps unreachable endpoint to No"
assert_eq "No" "$(lookup_line 4)" "line maps unreachable endpoint to No"
DC_PROBE_MODE="down"
assert_eq "No" "$(lookup_doh_google 4)" "doh google maps unreachable endpoint to No"
assert_eq "No" "$(lookup_doh_cloudflare 4)" "doh cloudflare maps unreachable endpoint to No"
DC_PROBE_MODE="down"
assert_eq "No" "$(lookup_gmail 4)" "gmail maps unreachable endpoint to No"
assert_eq "No" "$(lookup_proton 4)" "proton maps unreachable endpoint to No"
assert_eq "No" "$(lookup_google_drive 4)" "google drive maps unreachable endpoint to No"
assert_eq "No" "$(lookup_dropbox 4)" "dropbox maps unreachable endpoint to No"
assert_eq "No" "$(lookup_onedrive 4)" "onedrive maps unreachable endpoint to No"
assert_eq "No" "$(lookup_mega 4)" "mega maps unreachable endpoint to No"
assert_eq "No" "$(lookup_epic_games 4)" "epic games maps unreachable endpoint to No"
assert_eq "No" "$(lookup_battle_net 4)" "battle net maps unreachable endpoint to No"
assert_eq "No" "$(lookup_roblox 4)" "roblox maps unreachable endpoint to No"
assert_eq "No" "$(lookup_riot 4)" "riot maps unreachable endpoint to No"
assert_eq "No" "$(lookup_xbox 4)" "xbox maps unreachable endpoint to No"
assert_eq "No" "$(lookup_app_store 4)" "app store maps unreachable endpoint to No"
assert_eq "No" "$(lookup_play_store 4)" "play store maps unreachable endpoint to No"
assert_eq "No" "$(lookup_aws 4)" "aws maps unreachable endpoint to No"
assert_eq "No" "$(lookup_gcp_console 4)" "gcp console maps unreachable endpoint to No"
assert_eq "No" "$(lookup_oracle_cloud 4)" "oracle cloud maps unreachable endpoint to No"
assert_eq "No" "$(lookup_stripe_api 4)" "stripe api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_paypal 4)" "paypal maps unreachable endpoint to No"
assert_eq "No" "$(lookup_wise 4)" "wise maps unreachable endpoint to No"
DC_PROBE_MODE="down"
assert_eq "No" "$(lookup_gemini_api 4)" "gemini api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_ai_studio 4)" "ai studio maps unreachable endpoint to No"
assert_eq "No" "$(lookup_google_meet 4)" "google meet maps unreachable endpoint to No"
assert_eq "No" "$(lookup_google_photos 4)" "google photos maps unreachable endpoint to No"
assert_eq "No" "$(lookup_google_calendar 4)" "google calendar maps unreachable endpoint to No"
assert_eq "No" "$(lookup_youtube_music 4)" "youtube music maps unreachable endpoint to No"
assert_eq "No" "$(lookup_apple_music 4)" "apple music maps unreachable endpoint to No"
assert_eq "No" "$(lookup_soundcloud 4)" "soundcloud maps unreachable endpoint to No"
assert_eq "No" "$(lookup_deezer 4)" "deezer maps unreachable endpoint to No"
assert_eq "No" "$(lookup_discord_cdn 4)" "discord cdn maps unreachable endpoint to No"
assert_eq "No" "$(lookup_minecraft_session 4)" "minecraft session maps unreachable endpoint to No"
assert_eq "No" "$(lookup_roblox_api 4)" "roblox api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_wechat_api 4)" "wechat api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_kakaotalk 4)" "kakaotalk maps unreachable endpoint to No"
assert_eq "No" "$(lookup_threema 4)" "threema maps unreachable endpoint to No"
DC_PROBE_MODE="down"
assert_eq "No" "$(lookup_docker_hub_api 4)" "docker hub api maps unreachable endpoint to No"
assert_eq "No" "$(lookup_go_modules 4)" "go modules maps unreachable endpoint to No"
assert_eq "No" "$(lookup_crates_io 4)" "crates io maps unreachable endpoint to No"
assert_eq "No" "$(lookup_maven_central 4)" "maven central maps unreachable endpoint to No"
assert_eq "No" "$(lookup_hetzner 4)" "hetzner maps unreachable endpoint to No"
assert_eq "No" "$(lookup_digitalocean 4)" "digitalocean maps unreachable endpoint to No"
assert_eq "No" "$(lookup_vultr 4)" "vultr maps unreachable endpoint to No"
assert_eq "No" "$(lookup_matrix 4)" "matrix maps unreachable endpoint to No"
assert_eq "No" "$(lookup_ntfy 4)" "ntfy maps unreachable endpoint to No"
assert_eq "No" "$(lookup_telegram_bot_api 4)" "telegram bot api maps unreachable endpoint to No"
unset -f tcp_probe dc_probe_stub host_resolves
unset DC_PROBE_MODE DNS_STUB_MODE
JSON_OUTPUT=false

# Spinner counter and instant result lines
assert_eq "3" "$(count_group_checks cdn)" "count_group_checks counts cdn group"
assert_eq "14" "$(count_group_checks devinfra)" "count_group_checks counts devinfra group"
CHECKS_DONE_FILE=$(mktemp)
spinner_running=true
JSON_OUTPUT=true
out=$({ add_result "cdn" "Counter Test" "Yes" "" "" ""; } 2>&1)
clean_out=$(printf '%s' "$out" | sed "s/$(printf '\033')\\[[0-9;]*m//g")
assert_contains "$clean_out" "✔" "instant result line prints pass symbol"
assert_contains "$clean_out" "Counter Test: Yes" "instant result line prints service and verdict"
assert_contains "$out" $'\r\033[K' "instant result line wipes the spinner frame first"
assert_eq "1" "$(grep -c . "$CHECKS_DONE_FILE")" "counter file increments per check"
assert_contains "1;32" "$(tail -n 1 "$CHECKS_DONE_FILE")" "counter marker carries the verdict color"
out=$({ add_result "cdn" "Counter Test 2" "No" "Denied" "" ""; } 2>&1)
clean_out=$(printf '%s' "$out" | sed "s/$(printf '\033')\\[[0-9;]*m//g")
assert_contains "$clean_out" "✘" "instant result line prints fail symbol"
assert_contains "$clean_out" "Counter Test 2: No/Denied" "second instant result line prints"
assert_eq "2" "$(grep -c . "$CHECKS_DONE_FILE")" "counter file increments twice"
assert_contains "1;31" "$(tail -n 1 "$CHECKS_DONE_FILE")" "counter marker switches to the fail color"
spinner_running=false
JSON_OUTPUT=false
out=$({ add_result "cdn" "Counter Quiet" "Yes" "" "" ""; } 2>&1)
assert_empty "$out" "no instant line when spinner inactive"
rm -f "$CHECKS_DONE_FILE"
CHECKS_DONE_FILE=""
unset out clean_out

# Stale temp file sweep: killed runs leave ipregion_* files behind; the
# sweep removes files older than 24h and keeps fresh ones
STALE_TMP="${TMPDIR:-/tmp}/ipregion_stale_unit_test"
FRESH_TMP="${TMPDIR:-/tmp}/ipregion_fresh_unit_test"
echo junk >"$STALE_TMP"
touch -t 202001010000 "$STALE_TMP"
echo junk >"$FRESH_TMP"
cleanup_stale_temp_files
assert_false "stale temp file swept" test -f "$STALE_TMP"
assert_true "fresh temp file kept" test -f "$FRESH_TMP"
rm -f "$STALE_TMP" "$FRESH_TMP"

# The spinner rendering subshell self-terminates when its service file
# is removed (orphaned-subshell protection)
spinner_start
sleep 0.3
rm -f "$SPINNER_SERVICE_FILE"
# The sentinel is checked once per frame rotation (0.4s) - poll instead
# of sleeping a fixed interval
silenced_kill() { kill -0 "$1" 2>/dev/null; }
for _ in $(seq 1 20); do
  silenced_kill "$spinner_pid" || break
  sleep 0.1
done
assert_false "spinner subshell self-terminates after cleanup" silenced_kill "$spinner_pid"
spinner_stop
rm -f "$SPINNER_SERVICE_FILE"
SPINNER_SERVICE_FILE=""

# Monitoring kit: verdict line collection, diffing, compare, telegram
collect_verdict_lines '{"results":{"primary":[{"service":"Alpha","ipv4":"Yes","ipv6":"Yes"}],"custom":[{"service":"Beta","ipv4":"No","ipv6":"Denied"}],"cdn":[],"devinfra":[{"service":"Gamma","ipv4":"N/A","ipv6":"Yes"}]}}' >/tmp/mk_lines.txt
grep -q "^Alpha=Yes/Yes$" /tmp/mk_lines.txt && grep -q "^Beta=No/Denied$" /tmp/mk_lines.txt && grep -q "^Gamma=N\/A/Yes$" /tmp/mk_lines.txt && echo "OK: verdict lines collected" || {
  echo "FAIL: verdict lines collected"
  failures=$((failures + 1))
}

mk_changes=$(compute_verdict_changes "Alpha=Yes/Yes
Beta=No/Denied" "Alpha=Yes/Yes
Beta=Yes/Yes
Gamma=Yes/-")
assert_contains "$mk_changes" "Beta: No/Denied → Yes/Yes" "watch diff reports changed verdicts"
assert_contains "$mk_changes" "+ Gamma: Yes/-" "watch diff reports new checks"

mk_changes=$(compute_verdict_changes "Alpha=Yes/Yes
Beta=Yes/Yes" "Alpha=Yes/Yes")
assert_contains "$mk_changes" "- Beta: Yes/Yes" "watch diff reports removed checks"
mk_changes=$(compute_verdict_changes "Alpha=Yes/Yes" "Alpha=Yes/Yes")
assert_empty "$mk_changes" "watch diff is empty without changes"

# --compare over two result JSON files
old_json='{"results":{"primary":[],"custom":[{"service":"GitHub","ipv4":"Yes","ipv6":"Yes"}],"cdn":[],"devinfra":[]}}'
new_json='{"results":{"primary":[],"custom":[{"service":"GitHub","ipv4":"No","ipv6":"Yes"}],"cdn":[],"devinfra":[]}}'
echo "$old_json" >"${TMPDIR:-/tmp}/ipregion_cmp_old.json"
echo "$new_json" >"${TMPDIR:-/tmp}/ipregion_cmp_new.json"
mk_changes=$(run_compare "${TMPDIR:-/tmp}/ipregion_cmp_old.json" "${TMPDIR:-/tmp}/ipregion_cmp_new.json")
assert_contains "$mk_changes" "~ GitHub: Yes/Yes → No/Yes" "run_compare reports verdict change"
rm -f "${TMPDIR:-/tmp}/ipregion_cmp_old.json" "${TMPDIR:-/tmp}/ipregion_cmp_new.json"

# Telegram notify sends the change text to the bot API
tg_capture_file=$(mktemp)
tg_stub_wrapper() {
  printf '%s' "$*" >"$tg_capture_file"
}
curl_wrapper() { tg_stub_wrapper "$@"; }
IPREGION_TG_BOT_TOKEN="123:ABC"
IPREGION_TG_CHAT_ID="42"
telegram_send_message "ipregion changes"
unset IPREGION_TG_BOT_TOKEN IPREGION_TG_CHAT_ID
assert_contains "$(cat "$tg_capture_file")" "api.telegram.org/bot123:ABC/sendMessage" "telegram notify hits bot API"
assert_contains "$(cat "$tg_capture_file")" "chat_id=42" "telegram notify carries chat id"
assert_contains "$(cat "$tg_capture_file")" "text=ipregion changes" "telegram notify carries text"
# No credentials - silently no-op
out=$({ telegram_send_message "x"; } 2>&1)
assert_empty "$out" "telegram notify no-ops without credentials"
rm -f "$tg_capture_file"
unset -f curl_wrapper tg_stub_wrapper

# Spinner counter test needs the marker channel back after monitoring block
CHECKS_DONE_FILE=""

# --only-changes requires --watch
oc_err=$(bash "$ROOT_DIR/ipregion.sh" --only-changes 2>&1 || true)
assert_contains "$oc_err" "requires --watch" "only-changes without watch errors"

# --list prints the full check registry, one tab-separated line per check
list_output=$(bash "$ROOT_DIR/ipregion.sh" --list)
expected_list_lines=$((${#PRIMARY_SERVICES_ORDER[@]} + ${#CUSTOM_SERVICES_ORDER[@]} + ${#CDN_SERVICES_ORDER[@]} + ${#DEVINFRA_SERVICES_ORDER[@]}))
assert_eq "$expected_list_lines" "$(printf '%s\n' "$list_output" | grep -c .)" "list prints every registry entry"
printf '%s\n' "$list_output" | grep -q $'^custom\tGEMINI_NOTEBOOK\tGemini Notebook$' && echo "OK: list carries group/key/display" || {
  echo "FAIL: list carries group/key/display"
  failures=$((failures + 1))
}

if [[ "$failures" -gt 0 ]]; then
  echo "$failures test(s) failed."
  exit 1
fi

echo "All tests passed."
