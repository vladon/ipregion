#!/usr/bin/env bash

# Golden tests: render the availability family against stubbed network
# responses and diff the output against tests/golden/expected.
# Regenerate expected files with: GOLDEN_UPDATE=1 bash tests/golden.sh
#
# Note: no set -euo pipefail here on purpose - the sourced script does not
# run under strict mode in production and several of its paths reference
# variables that are only conditionally set.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_DIR="$ROOT_DIR/tests/golden/expected"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to run golden tests."
  exit 1
fi

if ! command -v column >/dev/null 2>&1; then
  echo "Skipping golden tests: 'column' is not available."
  exit 0
fi

# shellcheck source=/dev/null
source "$ROOT_DIR/ipregion.sh"

# Deterministic network stubs ----------------------------------------------

# print_results pipes rows through the external column(1); BSD and util-linux
# column pad differently (and handle ANSI differently), which would make the
# golden depend on the local column build. Route it to cat for the duration of
# the run so the snapshot covers the script's own output up to the pipe.
SHIM_DIR=$(mktemp -d)
printf '#!/usr/bin/env sh\nexec cat\n' >"$SHIM_DIR/column"
chmod +x "$SHIM_DIR/column"
PATH="$SHIM_DIR:$PATH"
trap 'rm -rf "$SHIM_DIR"' EXIT

stub_body() {
  case "$1" in
  *instagram.com*)
    printf '%s' '<!doctype html><html><head><meta property="og:title" content="Instagram" /></head><body>instagram login</body></html>'
    ;;
  *tiktok.com*)
    printf '%s' '<!doctype html><html><head><title>Home / X</title></head><body>generic portal page</body></html>'
    ;;
  *whatsapp.com*)
    printf '%s' '<!doctype html><html><head><title>WhatsApp Web</title></head><body>whatsapp web app</body></html>'
    ;;
  *telegram.org*)
    printf '%s' '<!doctype html><html><head><title>Telegram Web</title></head><body>telegram web client</body></html>'
    ;;
  *discord.com*)
    printf '%s' '<!doctype html><html><head><title>Discord | Your Place to Talk and Hang Out</title></head><body>discord app</body></html>'
    ;;
  *x.com*)
    printf '%s' '<!doctype html><html><head><link rel="canonical" href="https://x.com/" /><title>X</title></head><body>x timeline</body></html>'
    ;;
  *linkedin.com*)
    printf '%s' 'Denied'
    ;;
  *facebook.com*)
    printf '%s' '<!doctype html><html><head><title>Facebook</title></head><body>facebook login</body></html>'
    ;;
  *messenger.com*)
    printf '%s' '<!doctype html><html><head><title>Messenger</title></head><body>messenger login</body></html>'
    ;;
  *threads.com*)
    printf '%s' '<!doctype html><html><head><title>Threads</title></head><body>threads feed</body></html>'
    ;;
  *signal.org*)
    printf '%s' '<!doctype html><html><head><title>Signal Private Messenger</title></head><body>signal app</body></html>'
    ;;
  *douyin.com*)
    printf '%s' '<!doctype html><html><head><meta charset="UTF-8" /></head><body></body><script>var glb;_$jsvmprt</script></html>'
    ;;
  *vk.com*)
    printf '%s' '<!doctype html><html><head><title>VK | landing</title></head><body>vk.com login</body></html>'
    ;;
  *ok.ru*)
    printf '%s' '<!doctype html><html><head><title>OK</title></head><body>ok.ru login</body></html>'
    ;;
  *grok.com*)
    printf '%s' '<!doctype html><html><head><title>grok assistant</title></head><body>grok app</body></html>'
    ;;
  *chat.deepseek.com*)
    printf '%s' '<!doctype html><html><head><title>DeepSeek</title></head><body>deepseek chat</body></html>'
    ;;
  *perplexity.ai*)
    printf '%s' '<!doctype html><html><head><title>Perplexity</title></head><body>perplexity search</body></html>'
    ;;
  *copilot.microsoft.com*)
    printf '%s' '<!doctype html><html><head><title>Microsoft Copilot</title></head><body>copilot chat</body></html>'
    ;;
  *mistral.ai*)
    printf '%s' '<!doctype html><html><head><title>Mistral Le Chat</title></head><body>mistral chat</body></html>'
    ;;
  *chat.qwen.ai*)
    printf '%s' '<!doctype html><html><head><title>Qwen</title></head><body>qwen chat</body></html>'
    ;;
  *peacocktv.com*)
    printf '%s' '<!doctype html><html><head><title>Unavailable In Your Region</title></head><body>peacock gate</body></html>'
    ;;
  *bsky.app*)
    printf '%s' '<!doctype html><html><head><title>Bluesky</title></head><body>bluesky app</body></html>'
    ;;
  *snapchat.com*)
    printf '%s' '<!doctype html><html><head><title>Snapchat</title></head><body>snapchat app</body></html>'
    ;;
  *pinterest.com*)
    printf '%s' '<!doctype html><html><head><title>Pinterest</title></head><body>pinterest pins</body></html>'
    ;;
  *truthsocial.com*)
    printf '%s' '<!doctype html><html><head><title>Truth Social</title></head><body>truthsocial feed</body></html>'
    ;;
  *weibo.com*)
    printf '%s' '<!doctype html><html><head><title>Weibo</title></head><body>weibo feed</body></html>'
    ;;
  *bilibili.com*)
    printf '%s' '<!doctype html><html><head><title>Bilibili</title></head><body>bilibili tv</body></html>'
    ;;
  *music.163.com*)
    printf '%s' '<!doctype html><html><head><title>NetEase Music</title></head><body>netease music 163</body></html>'
    ;;
  *twitch.tv*)
    printf '%s' '<!doctype html><html><head><title>Twitch</title></head><body>twitch tv</body></html>'
    ;;
  *yandex.ru*)
    printf '%s' '<!doctype html><html><head><title>Yandex</title></head><body>yandex search</body></html>'
    ;;
  *mail.ru*)
    printf '%s' '<!doctype html><html><head><title>Mail.ru</title></head><body>mail.ru mail</body></html>'
    ;;
  *github.com*)
    printf '%s' '<!doctype html><html><head><title>GitHub: Where the world builds software</title></head><body>github Octocat developer platform</body></html>'
    ;;
  # Primary GeoIP fixtures (all US, iplocation.com CY to exercise its custom handler)
  *geoip.maxmind.com*)
    printf '%s' '{"country":{"iso_code":"US"},"traits":{"autonomous_system_number":64496}}'
    ;;
  *rdap.db.ripe.net*)
    printf '%s' '{"country":"US"}'
    ;;
  *ipinfo.io*)
    printf '%s' '{"data":{"country":"US"}}'
    ;;
  *api.ipregistry.co*)
    printf '%s' '{"location":{"country":{"code":"US"}}}'
    ;;
  *ipapi.co*)
    printf '%s' '{"country":"US"}'
    ;;
  *speed.cloudflare.com*)
    printf '%s' '{"country":"US"}'
    ;;
  *api.country.is*)
    printf '%s' '{"country":"US"}'
    ;;
  *get.geojs.io*)
    printf '%s' '[{"country":"US"}]'
    ;;
  *api.geoapify.com*)
    printf '%s' '{"country":{"iso_code":"US"}}'
    ;;
  *api.ipapi.is*)
    printf '%s' '{"location":{"country_code":"US"}}'
    ;;
  *api.ipbase.com*)
    printf '%s' '{"data":{"location":{"country":{"alpha2":"US"}}}}'
    ;;
  *api.ipquery.io*)
    printf '%s' '{"location":{"country_code":"US"}}'
    ;;
  *ipwho.is*)
    printf '%s' '{"country_code":"US"}'
    ;;
  *ip-api.com*)
    printf '%s' '{"countryCode":"US"}'
    ;;
  *geoip.detector404.ru*)
    printf '%s' '{"data":{"country":{"ccode":"US"}}}'
    ;;
  *api.ip2location.io*)
    printf '%s' '{"country_code":"US"}'
    ;;
  *ifconfig.co*)
    printf '%s' 'US'
    ;;
  *iplocation.com*)
    printf '%s' '{"country_code":"CY"}'
    ;;
  *)
    printf '%s' ''
    ;;
  esac
}

curl_wrapper() {
  local url="$2"
  local response http_code error_type

  response=$(stub_body "$url")
  if [[ -n "$response" ]]; then
    http_code=200
    error_type=none
  else
    http_code=""
    error_type=curl_error
  fi

  if [[ -n "$CURL_META_FILE" ]]; then
    printf 'http_code=%s;latency_ms=100;error_type=%s\n' "$http_code" "$error_type" >"$CURL_META_FILE"
  fi

  printf '%s' "$response"
}

# Only the Telegram datacenter answers in this fixture set; WhatsApp edges and
# the Discord gateway drop the connection.
tcp_probe() {
  [[ "$1" == "149.154.167.51" ]]
}

# Golden verdicts must not depend on the real DNS resolver.
host_resolves() {
  true
}

# Fixed state ----------------------------------------------------------------

INCLUDED_SERVICES=(
  "INSTAGRAM"
  "INSTAGRAM_API"
  "INSTAGRAM_TRANSPORT"
  "TIKTOK_ACCESS"
  "TIKTOK_TRANSPORT"
  "WHATSAPP"
  "WHATSAPP_DC"
  "TELEGRAM_ACCESS"
  "TELEGRAM_DC"
  "DISCORD_ACCESS"
  "DISCORD_GATEWAY"
  "TWITTER"
  "LINKEDIN_ACCESS"
  "FACEBOOK_ACCESS"
  "FACEBOOK_API"
  "MESSENGER_ACCESS"
  "MESSENGER_MQTT"
  "THREADS_ACCESS"
  "THREADS_API"
  "THREADS_TRANSPORT"
  "SIGNAL_ACCESS"
  "SIGNAL_SERVICE"
  "STEAM_TRANSPORT"
  "NETFLIX_TRANSPORT"
  "APPLE_TRANSPORT"
  "MICROSOFT_TRANSPORT"
  "DOUYIN_CN"
  "VK"
  "VK_API"
  "OK_RU"
  "RUTUBE_TRANSPORT"
  "OZON_TRANSPORT"
  "GROK"
  "DEEPSEEK"
  "PERPLEXITY"
  "COPILOT"
  "MISTRAL"
  "QWEN_WEB"
  "PEACOCK_ACCESS"
  "GOOGLE_TRANSPORT"
  "YOUTUBE_TRANSPORT"
  "YOUTUBE_API"
  "OPENAI_API"
  "ANTHROPIC_API"
  "XAI_API"
  "DEEPSEEK_API"
  "PERPLEXITY_API"
  "MISTRAL_API"
  "REDDIT_API"
  "OK_API"
  "LINKEDIN_API"
  "X_API"
  "TWITTER_LEGACY_API"
  "BLUESKY"
  "SNAPCHAT"
  "PINTEREST"
  "TRUTH_SOCIAL"
  "WEIBO"
  "BILIBILI"
  "NETEASE_MUSIC"
  "TWITCH_SITE"
  "YANDEX"
  "MAIL_RU"
  "GITHUB"
  "GITHUB_API"
  "GITHUB_RAW"
  "GITLAB"
  "GITLAB_API"
  "NPM_REGISTRY"
  "PYPI"
  "DOCKER_HUB"
  "HUGGING_FACE"
  "STEAM_API"
  "DISCORD_API"
  # Primary GeoIP group (also rendered by the golden run)
  "MAXMIND"
  "RIPE"
  "IPINFO_IO"
  "CLOUDFLARE"
  "IPAPI_CO"
  "IFCONFIG_CO"
  "IP2LOCATION_IO"
  "IPLOCATION_COM"
  "COUNTRY_IS"
  "GEOJS_IO"
  "IPAPI_IS"
  "IPBASE_COM"
  "IPQUERY_IO"
  "IPWHOIS_IO"
  "IPWHO_IS"
  "IPAPI_COM"
  "DETECTOR404"
  "IPREGISTRY"
  "GEOAPIFY_COM"
)
EXCLUDED_SERVICES=()
EXCLUDED_SERVICES_CLI=()
EXTERNAL_IPV4="203.0.113.10"
EXTERNAL_IPV6="2001:db8::10"
EXTERNAL_IPV4_SOURCE="golden"
EXTERNAL_IPV6_SOURCE="golden"
EXTERNAL_IPV4_CACHE_HIT=false
EXTERNAL_IPV6_CACHE_HIT=false
EXTERNAL_IPV4_TIMESTAMP="1700000000"
EXTERNAL_IPV6_TIMESTAMP="1700000010"
REGISTERED_COUNTRY_IPV4="US"
REGISTERED_COUNTRY_IPV6="DE"
ASN_NUMBER="64496"
ASN_NAME="Golden Example AS"
DEBUG=false
PROGRESS_LOG=false
SHOW_METRICS=false
VERBOSE=false

# Run ------------------------------------------------------------------------

run_service_group "custom"
run_service_group "primary"
finalize_json

table_file=$(mktemp)
json_file=$(mktemp)
trap 'rm -f "$table_file" "$json_file"' EXIT

JSON_OUTPUT=false
print_results >"$table_file"

JSON_OUTPUT=true
jq -S . <<<"$RESULT_JSON" >"$json_file"

# Compare --------------------------------------------------------------------

compare_golden() {
  local name="$1"
  local actual="$2"
  local expected="$EXPECTED_DIR/$name"
  local diff_file

  diff_file=$(mktemp)

  if [[ "${GOLDEN_UPDATE:-}" == "1" ]]; then
    mkdir -p "$EXPECTED_DIR"
    cp "$actual" "$expected"
    echo "Updated golden: $name"
    rm -f "$diff_file"
    return 0
  fi

  if [[ ! -f "$expected" ]]; then
    echo "FAIL: golden $name is missing (regenerate with GOLDEN_UPDATE=1)"
    rm -f "$diff_file"
    return 1
  fi

  if ! diff -u "$expected" "$actual" >"$diff_file"; then
    echo "FAIL: golden mismatch: $name"
    cat "$diff_file"
    rm -f "$diff_file"
    return 1
  fi

  echo "OK: golden $name matches"
  rm -f "$diff_file"
}

golden_failures=0
compare_golden table.txt "$table_file" || golden_failures=$((golden_failures + 1))
compare_golden result.json "$json_file" || golden_failures=$((golden_failures + 1))

if [[ "$golden_failures" -gt 0 ]]; then
  echo "$golden_failures golden file(s) mismatched."
  exit 1
fi

echo "All golden tests passed."
