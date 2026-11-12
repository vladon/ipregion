#!/usr/bin/env bash

SCRIPT_NAME="ipregion.sh"
SCRIPT_URL="https://github.com/vladon/ipregion"
# Version metadata - injected during build/deploy
# Format: VERSION_TYPE|VERSION_VALUE|BUILD_DATE|COMMIT_HASH
# Examples:
#   tag|v2.1.0|2025-01-15T10:30:00Z|1a2b3c4d
#   commit|1a2b3c4d|2025-01-15T10:30:00Z|
SCRIPT_VERSION_METADATA="unknown|unknown|unknown|"
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
YOUTUBE_LANG="ru"

# Upstream (vernette/ipregion) service credentials
DISNEY_PLUS_API_KEY="ZGlzbmV5JmFuZHJvaWQmMS4wLjA.bkeb0m230uUhv8qrAXuNu39tbE_mD5EEhM_NAcohjyA"
DISNEY_PLUS_JSON_BODY='{"query":"\n     mutation registerDevice($registerDevice: RegisterDeviceInput!) {\n       registerDevice(registerDevice: $registerDevice) {\n         __typename\n       }\n     }\n     ","variables":{"registerDevice":{"applicationRuntime":"android","attributes":{"operatingSystem":"Android","operatingSystemVersion":"13"},"deviceFamily":"android","deviceLanguage":"en","deviceProfile":"phone","devicePlatformId":"android"}},"operationName":"registerDevice"}'
TWITCH_CLIENT_ID="kimne78kx3ncx6brgo4mv6wki5h1ko"
CHATGPT_STATSIG_API_KEY="client-zUdXdSTygXJdzoE0sWTkP8GKTVsUMF2IRM7ShVO2JAG"
CHATGPT_DERIVED_FIELDS_PREFIX='"derived_fields":'
NETFLIX_API_KEY="YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm"
SPOTIFY_API_KEY="142b583129b2df829de3656f9eb484e6"
SPOTIFY_CLIENT_ID="9a8d2f0ce77a4e248bb71fefcb557637"

# Telegram production MTProto data centers (official app endpoints)
TELEGRAM_DC_PROBE_TARGETS=("149.154.167.51:443" "91.108.56.130:443")
# WhatsApp media/gateway edges and the Discord websocket gateway
WHATSAPP_PROBE_TARGETS=("g.whatsapp.net:443")
DISCORD_PROBE_TARGETS=("gateway.discord.gg:443")
# Instagram/Threads Meta API edges (verified reachable via hostname probes);
# VK API as IP literals - bash /dev/tcp proved unreliable with its multi-A
# hostname. Signal's hostname DNS-poisons to nothing on restricted networks,
# which the probe honestly reports as No.
INSTAGRAM_API_PROBE_TARGETS=("i.instagram.com:443")
THREADS_PROBE_TARGETS=("graph.threads.net:443")
SIGNAL_PROBE_TARGETS=("textsecure-service.whispersystems.org:443")
VK_PROBE_TARGETS=("87.240.137.208:443" "87.240.190.70:443")
# Facebook Graph API and the Messenger MQTT transport edge
FACEBOOK_PROBE_TARGETS=("graph.facebook.com:443")
MESSENGER_PROBE_TARGETS=("edge-mqtt.facebook.com:443")
# TikTok and Google main service hosts (verified stable across repeated
# probes from both networks)
TIKTOK_PROBE_TARGETS=("www.tiktok.com:443")
GOOGLE_PROBE_TARGETS=("www.google.com:443")
# Site-host transports pairing with the site access checks
YOUTUBE_PROBE_TARGETS=("www.youtube.com:443")
INSTAGRAM_PROBE_TARGETS=("www.instagram.com:443")
THREADS_PROBE_TARGETS=("www.threads.com:443")
STEAM_PROBE_TARGETS=("store.steampowered.com:443")
NETFLIX_PROBE_TARGETS=("www.netflix.com:443")
APPLE_PROBE_TARGETS=("www.apple.com:443")
MICROSOFT_PROBE_TARGETS=("www.microsoft.com:443")
# Russian platforms (verified stable from a RU network)
RUTUBE_PROBE_TARGETS=("rutube.ru:443")
OZON_PROBE_TARGETS=("ozon.ru:443")
# AI and platform API transports (verified stable ×2 from a RU network)
OPENAI_API_PROBE_TARGETS=("api.openai.com:443")
ANTHROPIC_API_PROBE_TARGETS=("api.anthropic.com:443")
XAI_API_PROBE_TARGETS=("api.x.ai:443")
DEEPSEEK_API_PROBE_TARGETS=("api.deepseek.com:443")
PERPLEXITY_API_PROBE_TARGETS=("api.perplexity.ai:443")
MISTRAL_API_PROBE_TARGETS=("api.mistral.ai:443")
REDDIT_API_PROBE_TARGETS=("oauth.reddit.com:443")
OK_API_PROBE_TARGETS=("api.ok.ru:443")
LINKEDIN_API_PROBE_TARGETS=("api.linkedin.com:443")
X_API_PROBE_TARGETS=("api.x.com:443")
# Pre-rebrand Twitter API host, still answering: distinguishes networks
# where api.x.com is cut but the legacy endpoint connects (ru01 OK ×3)
TWITTER_LEGACY_API_PROBE_TARGETS=("api.twitter.com:443")
# GitHub API: raw-ISP TCP resets from some RU networks even though the
# github.com site page stays reachable (verified ru01 OK ×2, mac reset ×2)
GITHUB_API_PROBE_TARGETS=("api.github.com:443")
# GitLab site and API transports (verified stable ×3 from both networks)
GITLAB_PROBE_TARGETS=("gitlab.com:443")
GITLAB_API_PROBE_TARGETS=("api.gitlab.com:443")
# Steam Web API and the legacy Discord API host (verified ru01 OK ×2;
# the mac raw path was flapping during verification, DNS resolving fine)
STEAM_API_PROBE_TARGETS=("api.steampowered.com:443")
DISCORD_API_PROBE_TARGETS=("discordapp.com:443")
# YouTube InnerTube API backend, the backend the youtubei/v1 calls hit
# (verified stable ×2 from both networks)
YOUTUBE_API_PROBE_TARGETS=("youtubei.googleapis.com:443")
# Dev-workflow registries and artifact hosts (verified ru01 OK ×3;
# Docker Hub had RF pull restrictions in 2024, raw.githubusercontent.com
# is frequently cut separately from github.com)
NPM_REGISTRY_PROBE_TARGETS=("registry.npmjs.org:443")
PYPI_PROBE_TARGETS=("pypi.org:443")
DOCKER_HUB_PROBE_TARGETS=("registry-1.docker.io:443")
GITHUB_RAW_PROBE_TARGETS=("raw.githubusercontent.com:443")
GITHUB_CODELOAD_PROBE_TARGETS=("codeload.github.com:443")
HUGGING_FACE_PROBE_TARGETS=("huggingface.co:443")
# Twitch API + chat IRC edge, Meta static CDN, AI inference providers,
# enterprise Microsoft endpoints and communication platforms (verified
# ru01 OK ×2 in the coverage sweep; search pages carry brand markers)
TWITCH_API_PROBE_TARGETS=("api.twitch.tv:443")
TWITCH_CHAT_PROBE_TARGETS=("irc-ws.chat.twitch.tv:443")
FACEBOOK_CDN_PROBE_TARGETS=("static.xx.fbcdn.net:443")
GROQ_API_PROBE_TARGETS=("api.groq.com:443")
OPENROUTER_PROBE_TARGETS=("openrouter.ai:443")
COHERE_API_PROBE_TARGETS=("api.cohere.com:443")
ELEVENLABS_API_PROBE_TARGETS=("api.elevenlabs.io:443")
TEAMS_PROBE_TARGETS=("teams.microsoft.com:443")
OUTLOOK_PROBE_TARGETS=("outlook.office365.com:443")
AZURE_PORTAL_PROBE_TARGETS=("portal.azure.com:443")
VIBER_PROBE_TARGETS=("viber.com:443")
SLACK_PROBE_TARGETS=("slack.com:443")
ZOOM_PROBE_TARGETS=("zoom.us:443")
LINE_PROBE_TARGETS=("line.me:443")
# Encrypted-DNS resolvers, often cut separately from general traffic
DOH_GOOGLE_PROBE_TARGETS=("dns.google:443")
DOH_CLOUDFLARE_PROBE_TARGETS=("cloudflare-dns.com:443")
DOT_GOOGLE_PROBE_TARGETS=("dns.google:853")
DOT_CLOUDFLARE_PROBE_TARGETS=("one.one.one.one:853")
# Mail and file-storage transports
GMAIL_PROBE_TARGETS=("mail.google.com:443")
PROTON_PROBE_TARGETS=("proton.me:443")
GOOGLE_DRIVE_PROBE_TARGETS=("drive.google.com:443")
DROPBOX_PROBE_TARGETS=("dropbox.com:443")
ONEDRIVE_PROBE_TARGETS=("onedrive.live.com:443")
MEGA_PROBE_TARGETS=("mega.nz:443")
# Gaming platforms (Steam lives in the custom registry site family)
EPIC_GAMES_PROBE_TARGETS=("store.epicgames.com:443")
BATTLE_NET_PROBE_TARGETS=("battle.net:443")
ROBLOX_PROBE_TARGETS=("roblox.com:443")
RIOT_PROBE_TARGETS=("riotgames.com:443")
XBOX_PROBE_TARGETS=("xbox.com:443")
# App stores and cloud consoles
APP_STORE_PROBE_TARGETS=("apps.apple.com:443")
PLAY_STORE_PROBE_TARGETS=("play.google.com:443")
AWS_PROBE_TARGETS=("aws.amazon.com:443")
GCP_CONSOLE_PROBE_TARGETS=("console.cloud.google.com:443")
ORACLE_CLOUD_PROBE_TARGETS=("cloud.oracle.com:443")
# Payment gateways
STRIPE_API_PROBE_TARGETS=("api.stripe.com:443")
PAYPAL_PROBE_TARGETS=("paypal.com:443")
WISE_PROBE_TARGETS=("wise.com:443")
# Google per-service transports: Google gates individual services
# independently of the network path (Gemini Notebook proved it)
GEMINI_API_PROBE_TARGETS=("generativelanguage.googleapis.com:443")
AI_STUDIO_PROBE_TARGETS=("aistudio.google.com:443")
GOOGLE_MEET_PROBE_TARGETS=("meet.google.com:443")
GOOGLE_PHOTOS_PROBE_TARGETS=("photos.google.com:443")
GOOGLE_CALENDAR_PROBE_TARGETS=("calendar.google.com:443")
# Music streaming transports
YOUTUBE_MUSIC_PROBE_TARGETS=("music.youtube.com:443")
APPLE_MUSIC_PROBE_TARGETS=("music.apple.com:443")
SOUNDCLOUD_PROBE_TARGETS=("soundcloud.com:443")
DEEZER_PROBE_TARGETS=("deezer.com:443")
# Content CDN and game-session endpoints, cut separately from sites
DISCORD_CDN_PROBE_TARGETS=("cdn.discordapp.com:443")
MINECRAFT_SESSION_PROBE_TARGETS=("sessionserver.mojang.com:443")
ROBLOX_API_PROBE_TARGETS=("apis.roblox.com:443")
# Messenger additions
WECHAT_API_PROBE_TARGETS=("weixin.qq.com:443")
KAKAOTALK_PROBE_TARGETS=("kakao.com:443")
THREEMA_PROBE_TARGETS=("threema.ch:443")
# Dev-ops registries and hosting/cloud provider transports
DOCKER_HUB_API_PROBE_TARGETS=("hub.docker.com:443")
GO_MODULES_PROBE_TARGETS=("proxy.golang.org:443")
CRATES_IO_PROBE_TARGETS=("crates.io:443")
MAVEN_CENTRAL_PROBE_TARGETS=("repo.maven.apache.org:443")
HETZNER_PROBE_TARGETS=("hetzner.com:443")
DIGITALOCEAN_PROBE_TARGETS=("api.digitalocean.com:443")
VULTR_PROBE_TARGETS=("api.vultr.com:443")
# Decentralized chat, push notifications, bot infrastructure
MATRIX_PROBE_TARGETS=("matrix.org:443")
NTFY_PROBE_TARGETS=("ntfy.sh:443")
TELEGRAM_BOT_API_PROBE_TARGETS=("api.telegram.org:443")
# Static hosting platforms: this infrastructure is often blocked wholesale
WORKERS_DEV_PROBE_TARGETS=("workers.dev:443")
GITHUB_PAGES_PROBE_TARGETS=("github.io:443")
GITLAB_PAGES_PROBE_TARGETS=("gitlab.io:443")
VERCEL_APP_PROBE_TARGETS=("vercel.app:443")
NETLIFY_APP_PROBE_TARGETS=("netlify.app:443")
PAGES_DEV_PROBE_TARGETS=("pages.dev:443")
HEROKU_APP_PROBE_TARGETS=("herokuapp.com:443")
SPINNER_SERVICE_FILE=""
DEBUG_LOG_FILE=""

VERBOSE=false
JSON_OUTPUT=false
GROUPS_TO_SHOW="default"
# Curated default profile (bare `ipregion.sh` run): GeoIP group plus the
# messenger transports and the fast DNS health trio. --full / -g all runs
# everything.
DEFAULT_PROFILE=false
DEFAULT_PROFILE_SERVICES=(
  TELEGRAM_ACCESS
  TELEGRAM_DC
  WHATSAPP
  WHATSAPP_DC
  SIGNAL_ACCESS
  SIGNAL_SERVICE
  DNS_INTEGRITY
  DNS_INTERCEPT
  DNS_LATENCY
)
CURL_TIMEOUT=5
CURL_RETRIES=1

# Kernel route tables (Linux only; absence is not an error)
PROC_NET_DIR="${IPREGION_PROC_NET_DIR:-/proc/net}"
IPV4_ROUTE_TABLE="$PROC_NET_DIR/route"
IPV6_ROUTE_TABLE="$PROC_NET_DIR/ipv6_route"
IPV4_DEFAULT_ROUTE="00000000"
IPV6_DEFAULT_ROUTE="00000000000000000000000000000000"
IPV6_DEFAULT_PREFIX_LENGTH="00"
ROUTE_FLAG_UP=1
ROUTE_FLAG_GATEWAY=2

IPV4_ONLY=false
IPV6_ONLY=false
PROXY_ADDR=""
INTERFACE_NAME=""
MAIN_INTERFACE=""
DEBUG=false
IPV4_SUPPORTED=0
IPV6_SUPPORTED=0
EXTERNAL_IPV4=""
EXTERNAL_IPV6=""
EXTERNAL_IPV4_SOURCE=""
EXTERNAL_IPV6_SOURCE=""
EXTERNAL_IPV4_CACHE_HIT=false
EXTERNAL_IPV6_CACHE_HIT=false
EXTERNAL_IPV4_TIMESTAMP=""
EXTERNAL_IPV6_TIMESTAMP=""
PARALLEL_JOBS=0
PARALLEL_PIDS=()
PROGRESS_LOG=false
LAST_PROGRESS_MSG=""
SHOW_METRICS=false
SHOW_EMOJI=false
SHOW_ATTENTION=true
OUTPUT_FILE=""

# Cache configuration
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/ipregion"
CACHE_FILE="$CACHE_DIR/ip_cache.json"
CACHE_TTL=3600
CACHE_ENABLED=true
IP_FETCH_MAX_RETRIES=3
IP_FETCH_RETRY_DELAY=1
CACHE_CLEARED=false
CACHE_SHOWN=false

RESULT_JSON=""
ARR_PRIMARY=()
ARR_CUSTOM=()
ARR_CDN=()
ARR_DNS=()
ARR_DEVINFRA=()
CHECKS_TOTAL=0
CHECKS_DONE_FILE=""
CHECKS_TOTAL_FILE=""
CHECKS_GROUP_FILE=""
RUN_START_SECONDS=$SECONDS
WATCH_INTERVAL=0
ONLY_CHANGES=false
DNS_SUMMARY=false
COMPARE_OLD=""
COMPARE_NEW=""
FAIL_ON_BLOCK_KEYS=()
LIST_ONLY=false
REGISTERED_COUNTRY_IPV4=""
REGISTERED_COUNTRY_IPV6=""
ASN_NUMBER=""
ASN_NAME=""
MAXMIND_PROFILE_IPV4=""
MAXMIND_PROFILE_IPV6=""
CURL_META_FILE=""
CACHE_LAST_SOURCE=""
CACHE_LAST_TIMESTAMP=""
UPLOADED_URL_PATTERN='^https?://[^[:space:]]+$'

# Colors render only on a terminal; NO_COLOR (https://no-color.org) disables
# them too. Stdout (report) and stderr (logs, spinner) are gated separately.
# The code variables stay usable as raw values (e.g. spinner counters).
USE_COLOR_STDOUT=false
USE_COLOR_STDERR=false
if [[ -z "${NO_COLOR:-}" ]]; then
  [[ -t 1 ]] && USE_COLOR_STDOUT=true
  [[ -t 2 ]] && USE_COLOR_STDERR=true
fi

COLOR_HEADER="1;36"
COLOR_SERVICE="1;32"
COLOR_HEART="1;31"
COLOR_URL="1;90"
COLOR_ASN="1;33"
COLOR_TABLE_HEADER="1;97"
COLOR_TABLE_VALUE="1"
COLOR_NULL="0;90"
COLOR_ERROR="1;31"
COLOR_WARN="1;33"
COLOR_INFO="1;36"
COLOR_RESET="0"

# ANSI/width helpers for the card renderer; the emoji class lists every icon
# the UI can print (flags are counted separately in label_country)
readonly ANSI_SEQUENCE=$'\033\[+([0-9;])m'
readonly WIDE_EMOJI_PATTERN='[🚨📱🌍📡🛠🧭✅]'

LOG_INFO="INFO"
LOG_WARN="WARNING"
LOG_ERROR="ERROR"
LOG_DEBUG="DEBUG"

STATUS_NA="N/A"
STATUS_DENIED="Denied"
STATUS_RATE_LIMIT="Rate-limit"
STATUS_SERVER_ERROR="Server error"
STATUS_REGION_BLOCKED="Region blocked"

# Report statuses (rendered in cards; reason strings stay in Attention)
STATUS_YES="Yes"
STATUS_NO="No"
SYMBOL_YES="✓"
SYMBOL_NO="✗"
SYMBOL_IPBLOCK="⊘"
SYMBOL_UNKNOWN="?"

# Card engine geometry
readonly CARD_GAP=1
readonly CARD_SIDES_WIDTH=2
readonly CARD_CONTENT_INDENT=1
readonly CARD_TRAILING_GAP=1
readonly CARD_TITLE_OFFSET=1
readonly CARD_HORIZONTAL="─"
readonly CARD_TOP_LEFT="╭"
readonly CARD_TOP_RIGHT="╮"
readonly CARD_BOTTOM_LEFT="╰"
readonly CARD_BOTTOM_RIGHT="╯"
readonly CARD_SIDE="│"
readonly VALUE_COLUMN_WIDTH=10
readonly HEADER_MARK="┃"
readonly CHECKS_BAR_MARGIN=26
readonly CHECKS_BAR_CHAR="━"
readonly CHECKS_BAR_REST_CHAR="─"
readonly VERDICT_NOTE="seen by most services"
readonly LEGEND_LINE="✓ works · ✗ no/blocked · ⊘ IP blocked · ? no answer · bright country = verdict"

declare -A GROUP_EMOJI=(
  [primary]="🌍"
  [custom]="📱"
  [cdn]="📡"
  [devinfra]="🛠"
  [dns]="🧭"
)

declare -A DEPENDENCIES=(
  [jq]="jq"
  [curl]="curl"
  [nslookup]="bind-utils"
)

declare -A PACKAGE_MAPPING=(
  ["apt:nslookup"]="dnsutils"
  ["pacman:nslookup"]="bind"
  ["dnf:nslookup"]="bind-utils"
  ["yum:nslookup"]="bind-utils"
  ["brew:nslookup"]="bind"
)

declare -A PRIMARY_SERVICES=(
  [MAXMIND]="maxmind.com|geoip.maxmind.com|/geoip/v2.1/city/me"
  [RIPE]="rdap.db.ripe.net|rdap.db.ripe.net|/ip/{ip}"
  [IPINFO_IO]="ipinfo.io|ipinfo.io|/widget/demo/{ip}"
  [IPAPI_CO]="ipapi.co|ipapi.co|/{ip}/json"
  [CLOUDFLARE]="cloudflare.com|speed.cloudflare.com|/meta"
  [IFCONFIG_CO]="ifconfig.co|ifconfig.co|/country-iso?ip={ip}|plain"
  [IP2LOCATION_IO]="ip2location.io|api.ip2location.io|/?ip={ip}"
  [IPLOCATION_COM]="iplocation.com|iplocation.com"
  [COUNTRY_IS]="country.is|api.country.is|/{ip}"
  [GEOJS_IO]="geojs.io|get.geojs.io|/v1/ip/country.json?ip={ip}"
  [IPAPI_IS]="ipapi.is|api.ipapi.is|/?q={ip}"
  [IPBASE_COM]="ipbase.com|api.ipbase.com|/v2/info?ip={ip}"
  [IPQUERY_IO]="ipquery.io|api.ipquery.io|/{ip}"
  [IPWHOIS_IO]="ipwhois.io|ipwho.is|/{ip}"
  [IPWHO_IS]="ipwho.is|ipwho.is|/{ip}"
  [IPAPI_COM]="ip-api.com|ip-api.com|/json/{ip}?fields=countryCode"
  [IPREGISTRY]="ipregistry.co|api.ipregistry.co|/{ip}?hostname=true&key=sb69ksjcajfs4c"
  [GEOAPIFY_COM]="geoapify.com|api.geoapify.com|/v1/ipinfo?&ip={ip}&apiKey=b8568cb9afc64fad861a69edbddb2658"
  [DETECTOR404]="Detector404|geoip.detector404.ru|/api/v1/ip/{ip}"
)

PRIMARY_SERVICES_ORDER=(
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

declare -A PRIMARY_SERVICES_CUSTOM_HANDLERS=(
  [IPLOCATION_COM]="lookup_iplocation_com"
)

declare -A SERVICE_HEADERS=(
  [MAXMIND]="Referer: https://www.maxmind.com"
  [IPAPI_COM]="Origin: https://ip-api.com"
  [CLOUDFLARE]="Referer: https://speed.cloudflare.com"
  [IPREGISTRY]="Origin: https://ipregistry.co"
)

declare -A CUSTOM_SERVICES=(
  [GOOGLE]="Google"
  [YOUTUBE]="YouTube"
  [YOUTUBE_PREMIUM]="YouTube Premium"
  [YOUTUBE_PREMIUM_WEB]="YouTube Premium (Web)"
  [YOUTUBE_API]="YouTube API"
  [YOUTUBE_TRANSPORT]="YouTube Transport"
  [YOUTUBE_MUSIC]="YouTube Music"
  [GOOGLE_SEARCH_CAPTCHA]="Google Search Captcha"
  [GOOGLE_TRANSPORT]="Google Transport"
  [REDIRECT_CHAIN]="Redirect Chain"
  [HTTP2_SUPPORT]="HTTP/2"
  [BING]="Bing"
  [DUCKDUCKGO]="DuckDuckGo"
  [BRAVE_SEARCH]="Brave Search"
  [DOH_GOOGLE]="DoH Google"
  [DOH_CLOUDFLARE]="DoH Cloudflare"
  [GMAIL]="Gmail"
  [GOOGLE_DRIVE]="Google Drive"
  [GOOGLE_MEET]="Google Meet"
  [GOOGLE_PHOTOS]="Google Photos"
  [GOOGLE_CALENDAR]="Google Calendar"
  [PLAY_STORE]="Play Store"
  [AWS]="AWS"
  [GCP_CONSOLE]="GCP Console"
  [ORACLE_CLOUD]="Oracle Cloud"
  [HETZNER]="Hetzner"
  [DIGITALOCEAN]="DigitalOcean"
  [VULTR]="Vultr"
  [GEMINI]="Google Gemini"
  [GEMINI_NOTEBOOK]="Gemini Notebook"
  [GEMINI_API]="Gemini API"
  [AI_STUDIO]="AI Studio"
  [APPLE]="Apple"
  [APPLE_TRANSPORT]="Apple Transport"
  [APP_STORE]="App Store"
  [APPLE_MUSIC]="Apple Music"
  [STEAM]="Steam"
  [STEAM_API]="Steam API"
  [STEAM_TRANSPORT]="Steam Transport"
  [TIKTOK]="Tiktok"
  [OOKLA_SPEEDTEST]="Ookla Speedtest"
  [JETBRAINS]="JetBrains"
  [PLAYSTATION]="PlayStation"
  [MICROSOFT]="Microsoft"
  [MICROSOFT_TRANSPORT]="Microsoft Transport"
  [TEAMS]="Microsoft Teams"
  [OUTLOOK]="Outlook"
  [AZURE_PORTAL]="Azure Portal"
  [ONEDRIVE]="OneDrive"
  [TWITCH]="Twitch"
  [CHATGPT]="ChatGPT"
  [OPENAI_API]="OpenAI API"
  [DISNEY_PLUS]="Disney+"
  [DISNEY_PLUS_ACCESS]="Disney+ Access"
  [HULU]="Hulu"
  [PARAMOUNT_PLUS]="Paramount+"
  [APPLE_TV_PLUS]="Apple TV+"
  [PLUTO_TV]="Pluto TV"
  [DISCOVERY_PLUS]="discovery+"
  [TUBI]="Tubi"
  [MUBI]="MUBI"
  [VIKI]="Rakuten Viki"
  [IQIYI]="iQIYI"
  [PLEX]="Plex"
  [KICK]="Kick"
  [REDDIT_GUEST_ACCESS]="Reddit Guest Access"
  [REDDIT_API]="Reddit API"
  [CLAUDE]="Claude"
  [ANTHROPIC_API]="Anthropic API"
  [REDDIT]="Reddit"
  [QWEN_CN]="Qwen CN API"
  [KIMI_CN]="Kimi CN API"
  [GLM_CN]="GLM CN API"
  [MINIMAX_CN]="MiniMax CN API"
  [YOUTUBE_NO_ADS]="YouTube No Ads"
  [NETFLIX]="Netflix"
  [NETFLIX_TRANSPORT]="Netflix Transport"
  [SPOTIFY]="Spotify"
  [SPOTIFY_SIGNUP]="Spotify Signup"
  [INSTAGRAM]="Instagram"
  [INSTAGRAM_API]="Instagram API"
  [INSTAGRAM_TRANSPORT]="Instagram Transport"
  [TIKTOK_ACCESS]="TikTok Access"
  [TIKTOK_TRANSPORT]="TikTok Transport"
  [WHATSAPP]="WhatsApp"
  [WHATSAPP_DC]="WhatsApp DC"
  [TELEGRAM_ACCESS]="Telegram Access"
  [TELEGRAM_DC]="Telegram DC"
  [DISCORD_ACCESS]="Discord Access"
  [DISCORD_API]="Discord API"
  [DISCORD_GATEWAY]="Discord Gateway"
  [DISCORD_CDN]="Discord CDN"
  [TWITTER]="Twitter (X)"
  [X_API]="X API"
  [TWITTER_LEGACY_API]="Twitter Legacy API"
  [LINKEDIN_ACCESS]="LinkedIn Access"
  [LINKEDIN_API]="LinkedIn API"
  [FACEBOOK_ACCESS]="Facebook Access"
  [FACEBOOK_API]="Facebook API"
  [FACEBOOK_CDN]="Facebook CDN"
  [MESSENGER_ACCESS]="Messenger Access"
  [MESSENGER_MQTT]="Messenger MQTT"
  [VIBER]="Viber"
  [SLACK]="Slack"
  [ZOOM]="Zoom"
  [LINE]="Line"
  [KAKAOTALK]="KakaoTalk"
  [THREEMA]="Threema"
  [MATRIX]="Matrix"
  [NTFY]="ntfy"
  [TELEGRAM_BOT_API]="Telegram Bot API"
  [WORKERS_DEV]="Workers.dev"
  [GITHUB_PAGES]="GitHub Pages"
  [GITLAB_PAGES]="GitLab Pages"
  [VERCEL_APP]="Vercel"
  [NETLIFY_APP]="Netlify"
  [PAGES_DEV]="Cloudflare Pages"
  [HEROKU_APP]="Heroku"
  [THREADS_ACCESS]="Threads Access"
  [THREADS_API]="Threads API"
  [THREADS_TRANSPORT]="Threads Transport"
  [SIGNAL_ACCESS]="Signal Access"
  [SIGNAL_SERVICE]="Signal Service"
  [DOUYIN_CN]="Douyin (CN)"
  [WECHAT]="WeChat"
  [WECHAT_API]="WeChat API"
  [BAIDU]="Baidu"
  [ALIPAY]="Alipay"
  [VK]="VK"
  [VK_API]="VK API"
  [OK_RU]="OK"
  [OK_API]="OK API"
  [RUTUBE_TRANSPORT]="RUTUBE Transport"
  [OZON_TRANSPORT]="Ozon Transport"
  [GROK]="Grok"
  [XAI_API]="xAI API"
  [DEEPSEEK]="DeepSeek"
  [DEEPSEEK_API]="DeepSeek API"
  [PERPLEXITY]="Perplexity"
  [PERPLEXITY_API]="Perplexity API"
  [COPILOT]="Copilot"
  [MISTRAL]="Mistral"
  [MISTRAL_API]="Mistral API"
  [GROQ_API]="Groq API"
  [OPENROUTER]="OpenRouter"
  [COHERE_API]="Cohere API"
  [ELEVENLABS_API]="ElevenLabs API"
  [QWEN_WEB]="Qwen Web"
  [DEEPL]="DeepL"
  [CHARACTER_AI]="Character.AI"
  [POE]="Poe"
  [GOOGLE_TRANSLATE]="Google Translate"
  [PEACOCK_ACCESS]="Peacock Access"
  [BLUESKY]="Bluesky"
  [SNAPCHAT]="Snapchat"
  [PINTEREST]="Pinterest"
  [TRUTH_SOCIAL]="Truth Social"
  [WEIBO]="Weibo"
  [BILIBILI]="Bilibili"
  [NETEASE_MUSIC]="NetEase Music"
  [TWITCH_SITE]="Twitch Site"
  [TWITCH_API]="Twitch API"
  [TWITCH_CHAT]="Twitch Chat"
  [YANDEX]="Yandex"
  [MAIL_RU]="Mail.ru"
  [PROTON]="Proton"
  [DROPBOX]="Dropbox"
  [MEGA]="MEGA"
  [EPIC_GAMES]="Epic Games"
  [BATTLE_NET]="Battle.net"
  [MINECRAFT_SESSION]="Minecraft Session"
  [ROBLOX]="Roblox"
  [ROBLOX_API]="Roblox API"
  [RIOT]="Riot Games"
  [XBOX]="Xbox"
  [STRIPE_API]="Stripe API"
  [PAYPAL]="PayPal"
  [WISE]="Wise"
  [NOTION]="Notion"
  [FIGMA]="Figma"
  [MIRO]="Miro"
  [CANVA]="Canva"
  [TRELLO]="Trello"
  [MEDIUM]="Medium"
  [WIKIPEDIA]="Wikipedia"
  [STACK_OVERFLOW]="Stack Overflow"
  [HABR]="Habr"
  [SOUNDCLOUD]="SoundCloud"
  [DEEZER]="Deezer"
)

CUSTOM_SERVICES_ORDER=(
  "GOOGLE"
  "YOUTUBE"
  "YOUTUBE_PREMIUM"
  "YOUTUBE_PREMIUM_WEB"
  "YOUTUBE_API"
  "YOUTUBE_TRANSPORT"
  "YOUTUBE_MUSIC"
  "GOOGLE_SEARCH_CAPTCHA"
  "GOOGLE_TRANSPORT"
  "REDIRECT_CHAIN"
  "HTTP2_SUPPORT"
  "BING"
  "DUCKDUCKGO"
  "BRAVE_SEARCH"
  "DOH_GOOGLE"
  "DOH_CLOUDFLARE"
  "GMAIL"
  "GOOGLE_DRIVE"
  "GOOGLE_MEET"
  "GOOGLE_PHOTOS"
  "GOOGLE_CALENDAR"
  "PLAY_STORE"
  "AWS"
  "GCP_CONSOLE"
  "ORACLE_CLOUD"
  "HETZNER"
  "DIGITALOCEAN"
  "VULTR"
  "GEMINI"
  "GEMINI_NOTEBOOK"
  "GEMINI_API"
  "AI_STUDIO"
  "APPLE"
  "APPLE_TRANSPORT"
  "APP_STORE"
  "APPLE_MUSIC"
  "STEAM"
  "STEAM_API"
  "STEAM_TRANSPORT"
  "TIKTOK"
  "OOKLA_SPEEDTEST"
  "JETBRAINS"
  "PLAYSTATION"
  "MICROSOFT"
  "MICROSOFT_TRANSPORT"
  "TEAMS"
  "OUTLOOK"
  "AZURE_PORTAL"
  "ONEDRIVE"
  "TWITCH"
  "CHATGPT"
  "OPENAI_API"
  "DISNEY_PLUS"
  "DISNEY_PLUS_ACCESS"
  "HULU"
  "PARAMOUNT_PLUS"
  "APPLE_TV_PLUS"
  "PLUTO_TV"
  "DISCOVERY_PLUS"
  "TUBI"
  "MUBI"
  "VIKI"
  "IQIYI"
  "PLEX"
  "KICK"
  "REDDIT_GUEST_ACCESS"
  "REDDIT_API"
  "CLAUDE"
  "ANTHROPIC_API"
  "REDDIT"
  "QWEN_CN"
  "KIMI_CN"
  "GLM_CN"
  "MINIMAX_CN"
  "YOUTUBE_NO_ADS"
  "NETFLIX"
  "NETFLIX_TRANSPORT"
  "SPOTIFY"
  "SPOTIFY_SIGNUP"
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
  "DISCORD_API"
  "DISCORD_GATEWAY"
  "DISCORD_CDN"
  "TWITTER"
  "X_API"
  "TWITTER_LEGACY_API"
  "LINKEDIN_ACCESS"
  "LINKEDIN_API"
  "FACEBOOK_ACCESS"
  "FACEBOOK_API"
  "FACEBOOK_CDN"
  "MESSENGER_ACCESS"
  "MESSENGER_MQTT"
  "VIBER"
  "SLACK"
  "ZOOM"
  "LINE"
  "KAKAOTALK"
  "THREEMA"
  "MATRIX"
  "NTFY"
  "TELEGRAM_BOT_API"
  "WORKERS_DEV"
  "GITHUB_PAGES"
  "GITLAB_PAGES"
  "VERCEL_APP"
  "NETLIFY_APP"
  "PAGES_DEV"
  "HEROKU_APP"
  "THREADS_ACCESS"
  "THREADS_API"
  "THREADS_TRANSPORT"
  "SIGNAL_ACCESS"
  "SIGNAL_SERVICE"
  "DOUYIN_CN"
  "WECHAT"
  "WECHAT_API"
  "BAIDU"
  "ALIPAY"
  "VK"
  "VK_API"
  "OK_RU"
  "OK_API"
  "RUTUBE_TRANSPORT"
  "OZON_TRANSPORT"
  "GROK"
  "XAI_API"
  "DEEPSEEK"
  "DEEPSEEK_API"
  "PERPLEXITY"
  "PERPLEXITY_API"
  "COPILOT"
  "MISTRAL"
  "MISTRAL_API"
  "GROQ_API"
  "OPENROUTER"
  "COHERE_API"
  "ELEVENLABS_API"
  "QWEN_WEB"
  "DEEPL"
  "CHARACTER_AI"
  "POE"
  "GOOGLE_TRANSLATE"
  "PEACOCK_ACCESS"
  "BLUESKY"
  "SNAPCHAT"
  "PINTEREST"
  "TRUTH_SOCIAL"
  "WEIBO"
  "BILIBILI"
  "NETEASE_MUSIC"
  "TWITCH_SITE"
  "TWITCH_API"
  "TWITCH_CHAT"
  "YANDEX"
  "MAIL_RU"
  "PROTON"
  "DROPBOX"
  "MEGA"
  "EPIC_GAMES"
  "BATTLE_NET"
  "MINECRAFT_SESSION"
  "ROBLOX"
  "ROBLOX_API"
  "RIOT"
  "XBOX"
  "STRIPE_API"
  "PAYPAL"
  "WISE"
  "NOTION"
  "FIGMA"
  "MIRO"
  "CANVA"
  "TRELLO"
  "MEDIUM"
  "WIKIPEDIA"
  "STACK_OVERFLOW"
  "HABR"
  "SOUNDCLOUD"
  "DEEZER"
)

# CDN node lookups form their own -g cdn group; handlers stay in
# CUSTOM_SERVICES_HANDLERS because they are discovered through the same
# process_custom_service path.
declare -A CDN_SERVICES=(
  [YOUTUBE_CDN]="YouTube CDN"
  [CLOUDFLARE_CDN]="Cloudflare CDN"
  [NETFLIX_CDN]="Netflix CDN"
)

CDN_SERVICES_ORDER=(
  "YOUTUBE_CDN"
  "CLOUDFLARE_CDN"
  "NETFLIX_CDN"
)

# DNS diagnostics form their own -g dns group; handlers stay in
# CUSTOM_SERVICES_HANDLERS because they are discovered through the same
# process_custom_service path.
declare -A DNS_DIAG_SERVICES=(
  [DNS_INTEGRITY]="DNS Integrity"
  [DNS_INTERCEPT]="DNS Intercept"
  [DNS_PTR]="PTR Match"
  [DNSSEC_VALIDATION]="DNSSEC Validation"
  [DOT_GOOGLE]="DoT Google"
  [DOT_CLOUDFLARE]="DoT Cloudflare"
  [PUBLIC_ANSWERS]="Public Answers"
  [DNS_TTL]="TTL Honesty"
  [RESOLVER_CONSENSUS]="Resolver Consensus"
  [DNS_LATENCY]="DNS Latency"
  [DNS_JITTER]="DNS Jitter"
  [RESOLVER_LATENCY]="Resolver Latency"
  [RESOLVER_JITTER]="Resolver Jitter"
  [DOH_PROXY]="DoH via Proxy"
  [REBIND_PROTECTION]="Rebind Protection"
)

DNS_DIAG_SERVICES_ORDER=(
  "DNS_INTEGRITY"
  "DNS_INTERCEPT"
  "DNS_PTR"
  "DNSSEC_VALIDATION"
  "DOT_GOOGLE"
  "DOT_CLOUDFLARE"
  "PUBLIC_ANSWERS"
  "DNS_TTL"
  "RESOLVER_CONSENSUS"
  "DNS_LATENCY"
  "DNS_JITTER"
  "RESOLVER_LATENCY"
  "RESOLVER_JITTER"
  "DOH_PROXY"
  "REBIND_PROTECTION"
)

# Developer-infrastructure services form their own -g devinfra group;
# handlers stay in CUSTOM_SERVICES_HANDLERS because they are discovered
# through the same process_custom_service path.
declare -A DEVINFRA_SERVICES=(
  [GITHUB]="GitHub"
  [GITHUB_API]="GitHub API"
  [GITHUB_CODELOAD]="GitHub Codeload"
  [GITHUB_RAW]="GitHub Raw"
  [GITLAB]="GitLab"
  [GITLAB_API]="GitLab API"
  [NPM_REGISTRY]="npm Registry"
  [PYPI]="PyPI"
  [DOCKER_HUB]="Docker Hub"
  [DOCKER_HUB_API]="Docker Hub API"
  [GO_MODULES]="Go Modules"
  [CRATES_IO]="Crates.io"
  [MAVEN_CENTRAL]="Maven Central"
  [HUGGING_FACE]="Hugging Face"
  [CERT_EXPIRY]="Cert Expiry"
  [PROXY_EGRESS]="Proxy Egress"
)

DEVINFRA_SERVICES_ORDER=(
  "GITHUB"
  "GITHUB_API"
  "GITHUB_CODELOAD"
  "GITHUB_RAW"
  "GITLAB"
  "GITLAB_API"
  "NPM_REGISTRY"
  "PYPI"
  "DOCKER_HUB"
  "DOCKER_HUB_API"
  "GO_MODULES"
  "CRATES_IO"
  "MAVEN_CENTRAL"
  "HUGGING_FACE"
  "CERT_EXPIRY"
  "PROXY_EGRESS"
)

declare -A CUSTOM_SERVICES_HANDLERS=(
  [GOOGLE]="lookup_google"
  [YOUTUBE]="lookup_youtube"
  [YOUTUBE_PREMIUM]="lookup_youtube_premium"
  [YOUTUBE_PREMIUM_WEB]="lookup_youtube_premium_web"
  [YOUTUBE_API]="lookup_youtube_api"
  [YOUTUBE_TRANSPORT]="lookup_youtube_transport"
  [YOUTUBE_MUSIC]="lookup_youtube_music"
  [GOOGLE_SEARCH_CAPTCHA]="lookup_google_search_captcha"
  [GOOGLE_TRANSPORT]="lookup_google_transport"
  [REDIRECT_CHAIN]="lookup_redirect_chain"
  [HTTP2_SUPPORT]="lookup_http2_support"
  [BING]="lookup_bing"
  [DUCKDUCKGO]="lookup_duckduckgo"
  [BRAVE_SEARCH]="lookup_brave_search"
  [DOH_GOOGLE]="lookup_doh_google"
  [DOH_CLOUDFLARE]="lookup_doh_cloudflare"
  [DOT_GOOGLE]="lookup_dot_google"
  [DOT_CLOUDFLARE]="lookup_dot_cloudflare"
  [DNS_INTEGRITY]="lookup_dns_integrity"
  [DNS_INTERCEPT]="lookup_dns_intercept"
  [DNS_PTR]="lookup_dns_ptr"
  [DNSSEC_VALIDATION]="lookup_dnssec_validation"
  [PUBLIC_ANSWERS]="lookup_public_answers"
  [DNS_TTL]="lookup_dns_ttl"
  [RESOLVER_CONSENSUS]="lookup_resolver_consensus"
  [DNS_LATENCY]="lookup_dns_latency"
  [DNS_JITTER]="lookup_dns_jitter"
  [RESOLVER_LATENCY]="lookup_resolver_latency"
  [RESOLVER_JITTER]="lookup_resolver_jitter"
  [DOH_PROXY]="lookup_doh_via_proxy"
  [REBIND_PROTECTION]="lookup_rebind_protection"
  [GMAIL]="lookup_gmail"
  [GOOGLE_DRIVE]="lookup_google_drive"
  [GOOGLE_MEET]="lookup_google_meet"
  [GOOGLE_PHOTOS]="lookup_google_photos"
  [GOOGLE_CALENDAR]="lookup_google_calendar"
  [PLAY_STORE]="lookup_play_store"
  [AWS]="lookup_aws"
  [GCP_CONSOLE]="lookup_gcp_console"
  [ORACLE_CLOUD]="lookup_oracle_cloud"
  [HETZNER]="lookup_hetzner"
  [DIGITALOCEAN]="lookup_digitalocean"
  [VULTR]="lookup_vultr"
  [GEMINI]="lookup_gemini"
  [GEMINI_NOTEBOOK]="lookup_gemini_notebook"
  [GEMINI_API]="lookup_gemini_api"
  [AI_STUDIO]="lookup_ai_studio"
  [APPLE]="lookup_apple"
  [APPLE_TRANSPORT]="lookup_apple_transport"
  [APP_STORE]="lookup_app_store"
  [APPLE_MUSIC]="lookup_apple_music"
  [STEAM]="lookup_steam"
  [STEAM_API]="lookup_steam_api"
  [STEAM_TRANSPORT]="lookup_steam_transport"
  [TIKTOK]="lookup_tiktok"
  [OOKLA_SPEEDTEST]="lookup_ookla_speedtest"
  [JETBRAINS]="lookup_jetbrains"
  [PLAYSTATION]="lookup_playstation"
  [MICROSOFT]="lookup_microsoft"
  [MICROSOFT_TRANSPORT]="lookup_microsoft_transport"
  [TEAMS]="lookup_teams"
  [OUTLOOK]="lookup_outlook"
  [AZURE_PORTAL]="lookup_azure_portal"
  [ONEDRIVE]="lookup_onedrive"
  [TWITCH]="lookup_twitch"
  [CHATGPT]="lookup_chatgpt"
  [OPENAI_API]="lookup_openai_api"
  [DISNEY_PLUS]="lookup_disney_plus"
  [DISNEY_PLUS_ACCESS]="lookup_disney_plus_access"
  [HULU]="lookup_hulu"
  [PARAMOUNT_PLUS]="lookup_paramount_plus"
  [APPLE_TV_PLUS]="lookup_apple_tv_plus"
  [PLUTO_TV]="lookup_pluto_tv"
  [DISCOVERY_PLUS]="lookup_discovery_plus"
  [TUBI]="lookup_tubi"
  [MUBI]="lookup_mubi"
  [VIKI]="lookup_viki"
  [IQIYI]="lookup_iqiyi"
  [PLEX]="lookup_plex"
  [KICK]="lookup_kick"
  [YOUTUBE_CDN]="lookup_youtube_cdn"
  [CLOUDFLARE_CDN]="lookup_cloudflare_cdn"
  [REDDIT_GUEST_ACCESS]="lookup_reddit_guest_access"
  [REDDIT_API]="lookup_reddit_api"
  [CLAUDE]="lookup_claude"
  [ANTHROPIC_API]="lookup_anthropic_api"
  [REDDIT]="lookup_reddit"
  [QWEN_CN]="lookup_qwen_cn"
  [KIMI_CN]="lookup_kimi_cn"
  [GLM_CN]="lookup_glm_cn"
  [MINIMAX_CN]="lookup_minimax_cn"
  [YOUTUBE_NO_ADS]="lookup_youtube_no_ads"
  [NETFLIX]="lookup_netflix"
  [NETFLIX_CDN]="lookup_netflix_cdn"
  [NETFLIX_TRANSPORT]="lookup_netflix_transport"
  [SPOTIFY]="lookup_spotify"
  [SPOTIFY_SIGNUP]="lookup_spotify_signup"
  [INSTAGRAM]="lookup_instagram"
  [INSTAGRAM_API]="lookup_instagram_api"
  [INSTAGRAM_TRANSPORT]="lookup_instagram_transport"
  [TIKTOK_ACCESS]="lookup_tiktok_access"
  [TIKTOK_TRANSPORT]="lookup_tiktok_transport"
  [WHATSAPP]="lookup_whatsapp"
  [WHATSAPP_DC]="lookup_whatsapp_dc"
  [TELEGRAM_ACCESS]="lookup_telegram_access"
  [TELEGRAM_DC]="lookup_telegram_dc"
  [DISCORD_ACCESS]="lookup_discord_access"
  [DISCORD_API]="lookup_discord_api"
  [DISCORD_GATEWAY]="lookup_discord_gateway"
  [DISCORD_CDN]="lookup_discord_cdn"
  [TWITTER]="lookup_twitter"
  [X_API]="lookup_x_api"
  [TWITTER_LEGACY_API]="lookup_twitter_legacy_api"
  [LINKEDIN_ACCESS]="lookup_linkedin_access"
  [LINKEDIN_API]="lookup_linkedin_api"
  [FACEBOOK_ACCESS]="lookup_facebook_access"
  [FACEBOOK_API]="lookup_facebook_api"
  [FACEBOOK_CDN]="lookup_facebook_cdn"
  [MESSENGER_ACCESS]="lookup_messenger_access"
  [MESSENGER_MQTT]="lookup_messenger_mqtt"
  [VIBER]="lookup_viber"
  [SLACK]="lookup_slack"
  [ZOOM]="lookup_zoom"
  [LINE]="lookup_line"
  [KAKAOTALK]="lookup_kakaotalk"
  [THREEMA]="lookup_threema"
  [MATRIX]="lookup_matrix"
  [NTFY]="lookup_ntfy"
  [TELEGRAM_BOT_API]="lookup_telegram_bot_api"
  [WORKERS_DEV]="lookup_workers_dev"
  [GITHUB_PAGES]="lookup_github_pages"
  [GITLAB_PAGES]="lookup_gitlab_pages"
  [VERCEL_APP]="lookup_vercel_app"
  [NETLIFY_APP]="lookup_netlify_app"
  [PAGES_DEV]="lookup_pages_dev"
  [HEROKU_APP]="lookup_heroku_app"
  [THREADS_ACCESS]="lookup_threads_access"
  [THREADS_API]="lookup_threads_api"
  [THREADS_TRANSPORT]="lookup_threads_transport"
  [SIGNAL_ACCESS]="lookup_signal_access"
  [SIGNAL_SERVICE]="lookup_signal_service"
  [DOUYIN_CN]="lookup_douyin_cn"
  [WECHAT]="lookup_wechat"
  [WECHAT_API]="lookup_wechat_api"
  [BAIDU]="lookup_baidu"
  [ALIPAY]="lookup_alipay"
  [VK]="lookup_vk"
  [VK_API]="lookup_vk_api"
  [OK_RU]="lookup_ok_ru"
  [OK_API]="lookup_ok_api"
  [RUTUBE_TRANSPORT]="lookup_rutube_transport"
  [OZON_TRANSPORT]="lookup_ozon_transport"
  [GROK]="lookup_grok"
  [XAI_API]="lookup_xai_api"
  [DEEPSEEK]="lookup_deepseek"
  [DEEPSEEK_API]="lookup_deepseek_api"
  [PERPLEXITY]="lookup_perplexity"
  [PERPLEXITY_API]="lookup_perplexity_api"
  [COPILOT]="lookup_copilot"
  [MISTRAL]="lookup_mistral"
  [MISTRAL_API]="lookup_mistral_api"
  [GROQ_API]="lookup_groq_api"
  [OPENROUTER]="lookup_openrouter"
  [COHERE_API]="lookup_cohere_api"
  [ELEVENLABS_API]="lookup_elevenlabs_api"
  [QWEN_WEB]="lookup_qwen_web"
  [DEEPL]="lookup_deepl"
  [CHARACTER_AI]="lookup_character_ai"
  [POE]="lookup_poe"
  [GOOGLE_TRANSLATE]="lookup_google_translate"
  [PEACOCK_ACCESS]="lookup_peacock_access"
  [BLUESKY]="lookup_bluesky"
  [SNAPCHAT]="lookup_snapchat"
  [PINTEREST]="lookup_pinterest"
  [TRUTH_SOCIAL]="lookup_truth_social"
  [WEIBO]="lookup_weibo"
  [BILIBILI]="lookup_bilibili"
  [NETEASE_MUSIC]="lookup_netease_music"
  [TWITCH_SITE]="lookup_twitch_site"
  [TWITCH_API]="lookup_twitch_api"
  [TWITCH_CHAT]="lookup_twitch_chat"
  [YANDEX]="lookup_yandex"
  [MAIL_RU]="lookup_mail_ru"
  [PROTON]="lookup_proton"
  [DROPBOX]="lookup_dropbox"
  [MEGA]="lookup_mega"
  [EPIC_GAMES]="lookup_epic_games"
  [BATTLE_NET]="lookup_battle_net"
  [MINECRAFT_SESSION]="lookup_minecraft_session"
  [ROBLOX]="lookup_roblox"
  [ROBLOX_API]="lookup_roblox_api"
  [RIOT]="lookup_riot"
  [XBOX]="lookup_xbox"
  [STRIPE_API]="lookup_stripe_api"
  [PAYPAL]="lookup_paypal"
  [WISE]="lookup_wise"
  [GITHUB]="lookup_github"
  [GITHUB_API]="lookup_github_api"
  [GITHUB_RAW]="lookup_github_raw"
  [GITHUB_CODELOAD]="lookup_github_codeload"
  [GITLAB]="lookup_gitlab"
  [GITLAB_API]="lookup_gitlab_api"
  [NPM_REGISTRY]="lookup_npm_registry"
  [PYPI]="lookup_pypi"
  [DOCKER_HUB]="lookup_docker_hub"
  [DOCKER_HUB_API]="lookup_docker_hub_api"
  [GO_MODULES]="lookup_go_modules"
  [CRATES_IO]="lookup_crates_io"
  [MAVEN_CENTRAL]="lookup_maven_central"
  [HUGGING_FACE]="lookup_hugging_face"
  [CERT_EXPIRY]="lookup_cert_expiry"
  [PROXY_EGRESS]="lookup_proxy_egress"
  [NOTION]="lookup_notion"
  [FIGMA]="lookup_figma"
  [MIRO]="lookup_miro"
  [CANVA]="lookup_canva"
  [TRELLO]="lookup_trello"
  [MEDIUM]="lookup_medium"
  [WIKIPEDIA]="lookup_wikipedia"
  [STACK_OVERFLOW]="lookup_stack_overflow"
  [HABR]="lookup_habr"
  [SOUNDCLOUD]="lookup_soundcloud"
  [DEEZER]="lookup_deezer"
)

declare -A SERVICE_GROUPS=(
  [primary]="${PRIMARY_SERVICES_ORDER[*]}"
  [custom]="${CUSTOM_SERVICES_ORDER[*]}"
  [cdn]="${CDN_SERVICES_ORDER[*]}"
  [dns]="${DNS_DIAG_SERVICES_ORDER[*]}"
  [devinfra]="${DEVINFRA_SERVICES_ORDER[*]}"
  [default]="${PRIMARY_SERVICES_ORDER[*]} TELEGRAM_ACCESS TELEGRAM_DC WHATSAPP WHATSAPP_DC SIGNAL_ACCESS SIGNAL_SERVICE DNS_INTEGRITY DNS_INTERCEPT DNS_LATENCY"
)

EXCLUDED_SERVICES=(
  # "IPINFO_IO"
  # "IPAPI_CO"
  "GOOGLE_SEARCH_CAPTCHA"
)
INCLUDED_SERVICES=()
EXCLUDED_SERVICES_CLI=()

IDENTITY_SERVICES=(
  # Primary services
  "ident.me"
  "ifconfig.me"
  "api64.ipify.org"
  "ip.im"
  "ifconfig.co"
  # Secondary services (fallback pool)
  "icanhazip.com"
  "checkip.amazonaws.com"
  "ipinfo.io/ip"
  "api.ipify.org"
  "myip.dnsomatic.com"
  "ipecho.net/plain"
  "whatismyipaddress.com/plain"
)

IPV6_OVER_IPV4_SERVICES=(
  "IPINFO_IO"
  "IPAPI_IS"
  "IPLOCATION_COM"
  "IPWHO_IS"
  "IPAPI_COM"
)

# Which stream the next color()/bold() output goes to: stdout renderers and
# stderr log paths set this around their calls so gating follows the stream.
COLOR_TARGET=stdout

color() {
  local color_name="$1"
  local text="$2"
  local code

  case "$color_name" in
  HEADER) code="$COLOR_HEADER" ;;
  SERVICE) code="$COLOR_SERVICE" ;;
  HEART) code="$COLOR_HEART" ;;
  URL) code="$COLOR_URL" ;;
  ASN) code="$COLOR_ASN" ;;
  TABLE_HEADER) code="$COLOR_TABLE_HEADER" ;;
  TABLE_VALUE) code="$COLOR_TABLE_VALUE" ;;
  NULL) code="$COLOR_NULL" ;;
  ERROR) code="$COLOR_ERROR" ;;
  WARN) code="$COLOR_WARN" ;;
  INFO) code="$COLOR_INFO" ;;
  *) code="$color_name" ;;
  esac

  case "$COLOR_TARGET" in
  stderr)
    [[ "$USE_COLOR_STDERR" == true ]] || {
      printf '%s' "$text"
      return
    }
    ;;
  *)
    [[ "$USE_COLOR_STDOUT" == true ]] || {
      printf '%s' "$text"
      return
    }
    ;;
  esac

  printf "\033[%sm%s\033[0m" "$code" "$text"
}

bold() {
  color "1" "$1"
}

get_timestamp() {
  local format="$1"
  date +"$format"
}

log() {
  local log_level="$1"
  local message="${*:2}"
  local timestamp
  local prev_target="$COLOR_TARGET"
  COLOR_TARGET=stderr

  if [[ "$VERBOSE" == true ]]; then
    local color_code

    timestamp=$(get_timestamp "%d.%m.%Y %H:%M:%S")

    case "$log_level" in
    "$LOG_ERROR") color_code=ERROR ;;
    "$LOG_WARN") color_code=WARN ;;
    "$LOG_INFO") color_code=INFO ;;
    "$LOG_DEBUG") color_code=NULL ;;
    *) color_code=RESET ;;
    esac

    printf "[%s] [%s]: %s\n" "$timestamp" "$(color $color_code "$log_level")" "$message" >&2
  fi

  COLOR_TARGET="$prev_target"
}

error_exit() {
  local message="$1"
  local exit_code="${2:-1}"
  local prev_target="$COLOR_TARGET"
  COLOR_TARGET=stderr
  printf "%s %s\n" "$(color ERROR '[ERROR]')" "$(color TABLE_HEADER "$message")" >&2
  COLOR_TARGET="$prev_target"
  display_help
  exit "$exit_code"
}

display_help() {
  cat <<EOF

Usage: $SCRIPT_NAME [OPTIONS]

IPRegion — determines your IP geolocation using various GeoIP services and popular websites

Options:
  -h, --help           Show this help message and exit
  -v, --verbose        Enable verbose logging
  -d, --debug          Enable debug trace; log may contain sensitive data (uploads use redacted copy)
  -j, --json           Output results in JSON format
  -g, --group GROUP    Run only one group: primary, custom, cdn, devinfra, dns, default, or all (default: default)
  --full               Run every check in all five groups
  -t, --timeout SEC    Set curl request timeout in seconds (default: $CURL_TIMEOUT)
  -P, --parallel N     Run up to N services in parallel (default: auto)
  --watch N            Monitoring mode: re-run checks every N seconds and report verdict changes
  --only-changes       With --watch: skip tables and header, print only verdict changes
  --dns-summary        With --watch: print a one-line DNS-family verdict summary every cycle
  --compare OLD NEW    Compare two result JSON files and print verdict changes
  --list               Print the full check registry (group, key, display) and exit
  --progress-log       Print progress lines instead of spinner
  -4, --ipv4           Test only IPv4
  -6, --ipv6           Test only IPv6
  -p, --proxy ADDR     Use SOCKS5 proxy (format: host:port)
  -i, --interface IF   Use specified network interface (e.g. eth1)
  --no-cache           Disable IP address caching
  --cache-ttl SEC      Set cache TTL in seconds (default: $CACHE_TTL)
  --clear-cache        Clear the IP cache
  --show-cache         Show cached IP addresses
  --include-service S  Include check (repeatable, case-insensitive)
  --exclude-service S  Exclude check (repeatable, case-insensitive)
  --fail-on-block S    Exit 1 if check S is not Yes (repeatable)
  --metrics            Show per-service HTTP/latency metrics in table output
  --emoji              Show country flags and group icons
  --no-attention       Hide the Attention card
  --youtube-lang LANG  Viewer language for the YouTube No Ads check (default: ru)
  -o, --output FILE    Save results to file (.json or .csv)

Examples:
  $SCRIPT_NAME                       # Curated default: GeoIP, messengers, DNS health
  $SCRIPT_NAME --full                # Every check in all groups
  $SCRIPT_NAME -g primary            # Check only GeoIP services
  $SCRIPT_NAME -g custom             # Check only popular websites
  $SCRIPT_NAME -g cdn                # Check only CDN nodes
  $SCRIPT_NAME -g devinfra           # Check only developer infrastructure
  $SCRIPT_NAME -4                    # Test only IPv4
  $SCRIPT_NAME -6                    # Test only IPv6
  $SCRIPT_NAME -p 127.0.0.1:1080     # Use SOCKS5 proxy
  $SCRIPT_NAME -i eth1               # Use network interface eth1
  $SCRIPT_NAME -j                    # Output result as JSON
  $SCRIPT_NAME -v                    # Enable verbose logging
  $SCRIPT_NAME -d                    # Enable debug and save full trace to file (upload on consent)
  $SCRIPT_NAME -P 6                  # Check services using 6 parallel jobs
  $SCRIPT_NAME --progress-log        # Print progress lines instead of spinner
  $SCRIPT_NAME --show-cache         # Show cached IP addresses
  $SCRIPT_NAME --clear-cache         # Clear the IP cache
  $SCRIPT_NAME --no-cache            # Disable IP address caching
  $SCRIPT_NAME --cache-ttl 1800      # Set cache TTL to 30 minutes
  $SCRIPT_NAME --include-service MAXMIND --include-service GOOGLE
  $SCRIPT_NAME --exclude-service YOUTUBE
  $SCRIPT_NAME --metrics
  $SCRIPT_NAME --output result.json
  $SCRIPT_NAME --output result.csv

EOF
}

print_startup_message() {
  local parallel_display="$PARALLEL_JOBS"
  local ipv4="auto" ipv6="auto"
  local proxy="${PROXY_ADDR:-none}"
  local iface="${INTERFACE_NAME:-auto}"
  local cache_status="${CACHE_ENABLED:-false}"
  local cache_ttl_display="${CACHE_TTL}s"

  if ((PARALLEL_JOBS <= 0)); then
    parallel_display="unknown"
  fi

  if [[ "$IPV4_ONLY" == true ]]; then
    ipv4="only"
    ipv6="off"
  elif [[ "$IPV6_ONLY" == true ]]; then
    ipv4="off"
    ipv6="only"
  fi

  if [[ "$CACHE_ENABLED" == true ]]; then
    cache_status="enabled (TTL: ${CACHE_TTL}s)"
  else
    cache_status="disabled"
  fi

  if [[ "$JSON_OUTPUT" == true ]]; then
    return
  fi

  printf "%s %s: %s\n" \
    "$(color INFO '[INFO]')" \
    "$(color HEADER 'Version')" \
    "$(get_script_version)" >&2

  printf "%s %s\n" \
    "$(color INFO '[INFO]')" \
    "Starting with group=$GROUPS_TO_SHOW timeout=${CURL_TIMEOUT}s parallel=$parallel_display ipv4=$ipv4 ipv6=$ipv6 proxy=$proxy interface=$iface cache=$cache_status metrics=$SHOW_METRICS output=${OUTPUT_FILE:-stdout} verbose=$VERBOSE debug=$DEBUG" >&2

  if [[ "$VERBOSE" == true ]]; then
    if [[ -n "$INTERFACE_NAME" ]]; then
      printf "%s %s\n" \
        "$(color INFO '[INFO]')" \
        "Interface: $INTERFACE_NAME (--interface)" >&2
    elif [[ -n "$MAIN_INTERFACE" ]]; then
      printf "%s %s\n" \
        "$(color INFO '[INFO]')" \
        "Interface: $MAIN_INTERFACE (main, carries the default route)" >&2
    fi
    if [[ -n "$PROXY_ADDR" ]]; then
      printf "%s %s\n" \
        "$(color INFO '[INFO]')" \
        "Proxy: socks5h://$PROXY_ADDR" >&2
    fi
  fi

  if [[ -n "$PROXY_ADDR" ]]; then
    printf "%s %s\n" \
      "$(color INFO '[INFO]')" \
      "Through a proxy each service is checked once: the proxy picks IPv4 or IPv6" >&2
  fi
}

setup_debug() {
  if [[ "$DEBUG" != true ]]; then
    return 1
  fi

  umask 077
  DEBUG_LOG_FILE=$(mktemp "${TMPDIR:-/tmp}/ipregion_debug_XXXXXX")

  exec 3>&1 4>&2

  exec 1> >(tee -a "$DEBUG_LOG_FILE" >&3)
  exec 2> >(tee -a "$DEBUG_LOG_FILE" >&4)

  set -x
  return 0
}

grep_wrapper() {
  grep "$@"
}

# Print the first capture group of an ERE across stdin (portable grep -P \K replacement)
sed_capture() {
  local pattern="$1"

  sed -nE "s/^.*$pattern.*/\\1/p" | head -n 1
}

normalize_ascii() {
  local value="$1"

  if command -v iconv >/dev/null 2>&1; then
    printf "%s" "$value" | iconv -f UTF-8 -t ASCII//TRANSLIT 2>/dev/null
    return
  fi

  printf "%s" "$value"
}

html_decode() {
  local value="$1"

  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import html,sys; sys.stdout.write(html.unescape(sys.stdin.read()))' <<<"$value"
    return
  fi

  if command -v perl >/dev/null 2>&1; then
    perl -MHTML::Entities -pe 'decode_entities($_)' <<<"$value"
    return
  fi

  if command -v php >/dev/null 2>&1; then
    php -r 'echo html_entity_decode(stream_get_contents(STDIN), ENT_QUOTES | ENT_HTML5);' <<<"$value"
    return
  fi

  if command -v sed >/dev/null 2>&1; then
    printf "%s" "$value" | sed -E \
      -e 's/&amp;/\&/g' \
      -e 's/&lt;/</g' \
      -e 's/&gt;/>/g' \
      -e 's/&quot;/"/g' \
      -e "s/&#39;/'/g"
    return
  fi

  printf "%s" "$value"
}

redact_debug_log() {
  local source_file="$1"
  local redacted_file
  redacted_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_debug_redacted_XXXXXX")

  sed -E \
    -e 's/([A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9]{0,4}/[REDACTED_IPV6]/g' \
    -e 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/[REDACTED_IPV4]/g' \
    -e 's/([Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]:)[^[:cntrl:]]*/\1 [REDACTED]/g' \
    -e 's/([Pp]roxy-[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]:)[^[:cntrl:]]*/\1 [REDACTED]/g' \
    -e 's/([Xx]-[Aa][Pp][Ii]-[Kk][Ee][Yy]:)[^[:cntrl:]]*/\1 [REDACTED]/g' \
    -e 's/([Xx]-[Aa][Uu][Tt][Hh]-[Tt][Oo][Kk][Ee][Nn]:)[^[:cntrl:]]*/\1 [REDACTED]/g' \
    -e 's/([Cc][Oo][Oo][Kk][Ii][Ee]:)[^[:cntrl:]]*/\1 [REDACTED]/g' \
    -e 's/([Ss][Ee][Tt]-[Cc][Oo][Oo][Kk][Ii][Ee]:)[^[:cntrl:]]*/\1 [REDACTED]/g' \
    -e 's/([?&]([Tt][Oo][Kk][Ee][Nn]|[Aa][Cc][Cc][Ee][Ss][Ss]_[Tt][Oo][Kk][Ee][Nn]|[Rr][Ee][Ff][Rr][Ee][Ss][Hh]_[Tt][Oo][Kk][Ee][Nn]|[Aa][Pp][Ii]_[Kk][Ee][Yy]|[Aa][Pp][Ii][Kk][Ee][Yy]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd])=)[^&[:space:]]+/\1[REDACTED]/g' \
    "$source_file" >"$redacted_file"

  printf "%s" "$redacted_file"
}

debug_paste_upload() {
  local service_name="$1"
  local endpoint="$2"
  shift 2
  local response_file http_code curl_exit response_body
  local ip_version curl_args=()

  ip_version=$(preferred_ip_version)
  if [[ "$ip_version" == "4" ]]; then
    curl_args+=(-4)
  else
    curl_args+=(-6)
  fi

  if [[ -n "$PROXY_ADDR" ]]; then
    curl_args+=(--proxy "socks5h://$PROXY_ADDR")
  fi

  response_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_upload_XXXXXX")

  http_code=$(curl \
    --silent \
    --http1.1 \
    --output "$response_file" \
    --write-out '%{http_code}' \
    --max-time 60 \
    --speed-limit 1024 \
    --speed-time 10 \
    "${curl_args[@]}" \
    "$@" \
    "$endpoint" 2>/dev/null)
  curl_exit=$?

  response_body=$(<"$response_file")
  rm -f "$response_file"

  if ((curl_exit != 0)); then
    printf "%s\n" "[WARN] $service_name upload failed: curl exit $curl_exit" >&2
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    printf "%s\n" "[WARN] $service_name upload failed: HTTP ${http_code:-unknown}" >&2
    return 1
  fi

  if [[ ! "$response_body" =~ $UPLOADED_URL_PATTERN ]]; then
    printf "%s\n" "[WARN] $service_name upload failed: invalid response" >&2
    return 1
  fi

  printf "%s" "$response_body"
}

upload_debug() {
  local upload_file upload_url

  upload_file=$(redact_debug_log "$DEBUG_LOG_FILE")

  upload_url=$(debug_paste_upload "x0.at" "https://x0.at" \
    --form "file=@$upload_file")

  if [[ -z "$upload_url" ]]; then
    upload_url=$(debug_paste_upload "litterbox" "https://litterbox.catbox.me/resources/internals/api.php" \
      --form "reqtype=fileupload" \
      --form "time=24h" \
      --form "fileToUpload=@$upload_file")
  fi

  rm -f "$upload_file"
  printf "%s" "$upload_url"
}

cleanup_debug() {
  local debug_url

  if [[ ! -f "$DEBUG_LOG_FILE" ]]; then
    return 1
  fi

  set +x
  exec 1>&3 2>&4 3>&- 4>&-

  printf "\n%s\n  %s\n" \
    "$(color WARN 'Debug information:')" \
    "Local file: $DEBUG_LOG_FILE"
  printf "%s\n" \
    "$(color WARN 'Privacy notice: the debug log may contain sensitive data. Upload uses a redacted copy, but review it before sharing.')"

  if [[ -t 0 ]] && prompt_for_debug_upload </dev/tty; then
    debug_url="$(upload_debug)"
    if [[ "$debug_url" =~ $UPLOADED_URL_PATTERN ]]; then
      printf "  %s\n\n%s\n%s\n\n%s\n" \
        "Remote URL: $debug_url" \
        "$(color INFO 'PRIVACY NOTICE: This file is uploaded to x0.at - a public file hoster.')" \
        "$(color INFO 'The file will be automatically deleted in 24 hours.')" \
        "$(color INFO 'If you open a GitHub Issue, please download the log and attach it')"
    else
      printf "  %s\n" \
        "$(color WARN 'Upload failed (see log above). You can share the local file manually if needed.')"
    fi
  else
    printf "\n%s\n" \
      "$(color INFO 'Upload skipped. You can share the local file manually if needed.')"
  fi
}

is_command_available() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1
}

supports_wait_n() {
  local major minor
  major=${BASH_VERSINFO[0]:-0}
  minor=${BASH_VERSINFO[1]:-0}

  ((major > 4 || (major == 4 && minor >= 3)))
}

prune_parallel_pids() {
  local pid
  local -a remaining=()

  for pid in "${PARALLEL_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      remaining+=("$pid")
    else
      wait "$pid" 2>/dev/null
    fi
  done

  PARALLEL_PIDS=("${remaining[@]}")
}

wait_for_parallel_slot() {
  while ((${#PARALLEL_PIDS[@]} >= PARALLEL_JOBS)); do
    if supports_wait_n; then
      wait -n 2>/dev/null || true
      prune_parallel_pids
    else
      log "$LOG_INFO" "Bash < 4.3 detected; using legacy parallel wait loop"
      prune_parallel_pids
      if ((${#PARALLEL_PIDS[@]} < PARALLEL_JOBS)); then
        break
      fi
      sleep 0.1
    fi
  done
}

register_parallel_pid() {
  local pid="$1"
  PARALLEL_PIDS+=("$pid")
}

detect_parallel_jobs() {
  local cpus=""

  if is_command_available "nproc"; then
    cpus=$(nproc 2>/dev/null)
  elif is_command_available "getconf"; then
    cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null)
  fi

  if [[ "$cpus" =~ ^[0-9]+$ ]] && ((10#$cpus >= 1)); then
    echo "$cpus"
  else
    echo 4
  fi
}

detect_distro() {
  if [[ -f /etc/os-release ]]; then
    distro=$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')
  elif [[ -f /etc/redhat-release ]]; then
    distro="rhel"
  elif [[ -d /data/data/com.termux ]]; then
    distro="termux"
  elif [[ "$(uname -s)" == "Darwin" ]]; then
    distro="macos"
  fi
}

detect_package_manager() {
  local pkg_manager

  case "$distro" in
  ubuntu | debian | termux)
    pkg_manager="apt"
    ;;
  arch | manjaro)
    pkg_manager="pacman"
    ;;
  fedora)
    pkg_manager="dnf"
    ;;
  centos | rhel)
    if is_command_available "dnf"; then
      pkg_manager="dnf"
    else
      pkg_manager="yum"
    fi
    ;;
  opensuse*)
    pkg_manager="zypper"
    ;;
  alpine)
    pkg_manager="apk"
    ;;
  macos)
    pkg_manager="brew"
    ;;
  *)
    error_exit "Unknown distro: $distro"
    ;;
  esac

  echo "$pkg_manager"
}

get_missing_commands() {
  local missing=()

  for cmd in "${!DEPENDENCIES[@]}"; do
    if ! is_command_available "$cmd"; then
      missing+=("$cmd")
    fi
  done

  printf '%s\n' "${missing[@]}"
}

get_package_name() {
  local pkg_manager="$1"
  local command="$2"
  local mapping_key="${pkg_manager}:${command}"

  if [[ -n "${PACKAGE_MAPPING[$mapping_key]}" ]]; then
    echo "${PACKAGE_MAPPING[$mapping_key]}"
    return
  fi

  echo "${DEPENDENCIES[$command]:-$command}"
}

is_sudo_required() {
  if [[ "${EUID:-$(id -u)}" -eq 0 || "$distro" == "termux" || "$distro" == "macos" ]]; then
    return 1
  fi

  return 0
}

get_install_args() {
  local pkg_manager="$1"
  local install_args

  case "$pkg_manager" in
  apt)
    install_args=("install" "-y")
    ;;
  pacman)
    install_args=("-Sy" "--noconfirm")
    ;;
  dnf | yum | zypper)
    install_args=("install" "-y")
    ;;
  apk)
    install_args=("add" "--no-cache")
    ;;
  brew)
    install_args=("install")
    ;;
  esac

  echo "${install_args[@]}"
}

install_packages() {
  local pkg_manager="$1"
  shift
  local packages=("$@")
  local cmd_prefix=()
  local install_cmd=()

  if is_sudo_required; then
    cmd_prefix=("sudo")
    log "$LOG_INFO" "Running as non-root user, using sudo"
  fi

  cmd_prefix+=("$pkg_manager")

  if [[ "$pkg_manager" == "apt" ]]; then
    log "$LOG_INFO" "Updating package lists"
    if ! "${cmd_prefix[@]}" update; then
      error_exit "Error occurred while updating package lists"
    fi
  fi

  for pkg in "${packages[@]}"; do
    if ! is_valid_package_name "$pkg"; then
      error_exit "Invalid package name: $pkg"
    fi
  done

  read -ra install_args <<<"$(get_install_args "$pkg_manager")"
  if ((${#install_args[@]} == 0)); then
    error_exit "No install arguments available for package manager: $pkg_manager"
  fi
  install_cmd+=("${cmd_prefix[@]}" "${install_args[@]}" "${packages[@]}")

  log "$LOG_INFO" "Running: ${install_cmd[*]}"

  if ! "${install_cmd[@]}"; then
    error_exit "Error occurred while installing packages"
  fi
}

prompt_for_installation() {
  local missing=("$@")
  local response
  local formatted_deps=""

  for dep in "${missing[@]}"; do
    formatted_deps+="  $dep\n"
  done

  printf "\n%s\n%b\n%s " \
    "$(color WARN 'Missing dependencies:')" \
    "$formatted_deps" \
    "$(color INFO 'Do you want to install them? [y/N]:')"

  read -r response
  response=${response,,}

  case "$response" in
  y | yes)
    return 0
    ;;
  *)
    return 1
    ;;
  esac
}

prompt_for_debug_upload() {
  local response

  printf "\n%s %s " \
    "$(color WARN 'Debug log upload?')" \
    "$(color INFO 'This will upload to 0x0.st (public). Proceed? [y/N]:')"

  read -r response
  response=${response,,}

  case "$response" in
  y | yes)
    return 0
    ;;
  *)
    return 1
    ;;
  esac
}

install_dependencies() {
  local missing_dependencies=()
  local missing_commands pkg_manager package_name

  log "$LOG_INFO" "Checking dependencies"

  mapfile -t missing_commands < <(get_missing_commands)

  if [[ "${missing_commands[*]}" =~ ^[[:space:]]*$ ]]; then
    log "$LOG_INFO" "All dependencies are installed"
    return 0
  fi

  log "$LOG_INFO" "Missing commands: ${missing_commands[*]}"

  pkg_manager=$(detect_package_manager)

  log "$LOG_INFO" "Detected package manager: $pkg_manager"

  for cmd in "${missing_commands[@]}"; do
    package_name=$(get_package_name "$pkg_manager" "$cmd")
    missing_dependencies+=("$package_name")
  done

  log "$LOG_INFO" "Missing dependencies: ${missing_dependencies[*]}"

  if ! prompt_for_installation "${missing_dependencies[@]}" </dev/tty; then
    printf "%s\n" "$(color WARN 'Installation canceled by user')"
    exit 1
  fi

  log "$LOG_INFO" "Installing missing dependencies"
  install_packages "$pkg_manager" "${missing_dependencies[@]}"
}

is_valid_json() {
  local json="$1"
  jq -e . >/dev/null 2>&1 <<<"$json"
}

process_json() {
  local json="$1"
  local jq_filter="$2"

  if is_status_string "$json"; then
    echo "$json"
    return
  fi

  if [[ -z "$json" ]]; then
    echo ""
    return
  fi

  if ! is_valid_json "$json"; then
    log "$LOG_WARN" "Invalid JSON input for filter: $jq_filter"
    echo ""
    return
  fi

  jq -r "$jq_filter" <<<"$json"
}

print_value_or_colored() {
  local value="$1"
  local color_name="$2"

  if [[ "$JSON_OUTPUT" == true ]]; then
    echo "$value"
    return
  fi

  color "$color_name" "$value"
}

mask_ipv4() {
  local ip="$1"
  echo "${ip%.*.*}.*.*"
}

mask_ipv6() {
  local ip="$1"
  local left_part right_part
  local -a left_arr right_arr expanded
  local h total missing=0

  if [[ -z "$ip" || "$ip" == "null" ]]; then
    echo "$ip"
    return
  fi

  if [[ "$ip" == *"."* || ! "$ip" =~ ^[0-9A-Fa-f:]+$ ]]; then
    echo "$ip"
    return
  fi

  if [[ "$ip" == *"::"* ]]; then
    if [[ "${ip#*::}" == *"::"* ]]; then
      echo "$ip"
      return
    fi
    left_part="${ip%%::*}"
    right_part="${ip##*::}"
  else
    left_part="$ip"
    right_part=""
  fi

  if [[ -n "$left_part" ]]; then
    IFS=':' read -r -a left_arr <<<"$left_part"
  fi

  if [[ -n "$right_part" ]]; then
    IFS=':' read -r -a right_arr <<<"$right_part"
  fi

  for h in "${left_arr[@]}" "${right_arr[@]}"; do
    if [[ -z "$h" || ! "$h" =~ ^[0-9A-Fa-f]{1,4}$ ]]; then
      echo "$ip"
      return
    fi
  done

  total=$((${#left_arr[@]} + ${#right_arr[@]}))
  if [[ "$ip" == *"::"* ]]; then
    missing=$((8 - total))
    if ((missing < 1)); then
      echo "$ip"
      return
    fi
  elif ((total != 8)); then
    echo "$ip"
    return
  fi

  expanded=("${left_arr[@]}")
  for ((h = 0; h < missing; h++)); do
    expanded+=("0")
  done
  expanded+=("${right_arr[@]}")

  if ((${#expanded[@]} < 3)); then
    echo "$ip"
    return
  fi

  printf "%s:%s:%s::\n" "${expanded[0]}" "${expanded[1]}" "${expanded[2]}"
}

is_valid_port() {
  local port="$1"

  if [[ ! "$port" =~ ^[0-9]+$ ]]; then
    return 1
  fi

  ((10#$port >= 1 && 10#$port <= 65535))
}

is_valid_proxy_addr() {
  local addr="$1"
  local host port

  if [[ "$addr" =~ ^\[(.+)\]:([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    [[ "$host" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
  elif [[ "$addr" =~ ^([^:]+):([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    [[ "$host" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
  else
    return 1
  fi

  is_valid_port "$port"
}

# Parse version metadata and return formatted version string
get_script_version() {
  IFS='|' read -r version_type version_value build_date commit_hash <<<"$SCRIPT_VERSION_METADATA"

  case "$version_type" in
  tag)
    # Release build: v2.1.0 (1a2b3c4d)
    if [[ -n "$commit_hash" ]]; then
      echo "${version_value} (${commit_hash})"
    else
      echo "$version_value"
    fi
    ;;
  commit)
    # Development build: 1a2b3c4d (2025-01-15 10:30 UTC)
    if [[ -n "$build_date" ]]; then
      local formatted_date=$(echo "$build_date" | sed 's/T/ /; s/Z/ UTC/')
      echo "${version_value} (${formatted_date})"
    else
      echo "$version_value"
    fi
    ;;
  *)
    # Fallback for unknown version
    echo "unknown"
    ;;
  esac
}

is_valid_interface_name() {
  local name="$1"
  [[ "$name" =~ ^[A-Za-z0-9._:@-]+$ ]]
}

is_valid_ipv4() {
  local ip="$1"
  local IFS=.
  local -a parts
  local part

  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  read -r -a parts <<<"$ip"
  for part in "${parts[@]}"; do
    [[ "$part" =~ ^[0-9]+$ ]] || return 1
    ((10#$part >= 0 && 10#$part <= 255)) || return 1
  done
  return 0
}

is_valid_ipv6() {
  local ip="$1"
  local part
  local -a parts
  local group_count=0
  local double_colon_count=0
  local tmp

  [[ -n "$ip" && "$ip" == *:* ]] || return 1

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$ip" <<'PY'
import ipaddress
import sys
try:
    ipaddress.IPv6Address(sys.argv[1])
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
    return $?
  fi

  [[ "$ip" =~ ^[0-9A-Fa-f:]+$ ]] || return 1

  tmp="$ip"
  while [[ "$tmp" == *"::"* ]]; do
    double_colon_count=$((double_colon_count + 1))
    tmp="${tmp#*::}"
  done

  ((double_colon_count <= 1)) || return 1

  if [[ "$ip" == *"::"* ]]; then
    ip="${ip#::}"
    ip="${ip%::}"
  fi

  IFS=':' read -r -a parts <<<"$ip"
  for part in "${parts[@]}"; do
    [[ -z "$part" ]] && continue
    [[ "$part" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    group_count=$((group_count + 1))
  done

  if ((double_colon_count == 1)); then
    ((group_count <= 8)) || return 1
  else
    ((group_count == 8)) || return 1
  fi

  return 0
}

is_valid_package_name() {
  local name="$1"
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9+._-]*$ ]]
}

normalize_service_name() {
  local name="$1"
  name="${name^^}"
  name="${name//-/_}"
  echo "$name"
}

is_service_in_list() {
  local needle="$1"
  shift
  local item

  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done

  return 1
}

validate_known_service() {
  local service_name="$1"

  if [[ -n "${PRIMARY_SERVICES[$service_name]:-}" || -n "${CUSTOM_SERVICES[$service_name]:-}" || -n "${CDN_SERVICES[$service_name]:-}" || -n "${DEVINFRA_SERVICES[$service_name]:-}" || -n "${DNS_DIAG_SERVICES[$service_name]:-}" ]]; then
    return 0
  fi

  return 1
}

should_skip_service() {
  local service_name="$1"

  if ((${#INCLUDED_SERVICES[@]} > 0)); then
    # Explicit inclusion wins over both exclusion lists: a default-excluded
    # check must stay runnable via --include-service.
    if is_service_in_list "$service_name" "${INCLUDED_SERVICES[@]}"; then
      return 1
    fi
    return 0
  fi

  # Curated default profile: outside -g default nothing is filtered.
  if [[ "$DEFAULT_PROFILE" == true ]]; then
    if [[ -z "${PRIMARY_SERVICES[$service_name]:-}" ]] && ! is_service_in_list "$service_name" "${DEFAULT_PROFILE_SERVICES[@]}"; then
      return 0
    fi
  fi

  if is_service_in_list "$service_name" "${EXCLUDED_SERVICES[@]}" || is_service_in_list "$service_name" "${EXCLUDED_SERVICES_CLI[@]}"; then
    return 0
  fi

  return 1
}

count_group_checks() {
  local group="$1"
  local count=0
  local -a group_services
  read -ra group_services <<<"${SERVICE_GROUPS[$group]:-}"
  local service_name
  for service_name in "${group_services[@]}"; do
    should_skip_service "$service_name" || ((count++))
  done
  echo "$count"
}

# Removes temp files left behind by runs that died before their cleanup
# traps could run (SIGKILL, dropped SSH sessions). Files newer than 24h
# are kept: a concurrent instance may still be using them.
cleanup_stale_temp_files() {
  local tmp_dir="${TMPDIR:-/tmp}"
  find "$tmp_dir" -maxdepth 1 -user "$(id -un)" -name 'ipregion_*' -type f -mmin +1440 -exec rm -f {} + 2>/dev/null || true
  find "$tmp_dir" -maxdepth 1 -user "$(id -un)" -name 'ipregion_parallel_*' -type d -mmin +1440 -exec rm -rf {} + 2>/dev/null || true
}

parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case $1 in
    -h | --help)
      display_help
      exit 0
      ;;
    -v | --verbose)
      VERBOSE=true
      shift
      ;;
    -d | --debug)
      DEBUG=true
      shift
      ;;
    -j | --json)
      JSON_OUTPUT=true
      shift
      ;;
    -g | --group)
      case "$2" in
      primary | custom | cdn | devinfra | dns | default | all)
        GROUPS_TO_SHOW="$2"
        ;;
      "")
        error_exit "Missing value for --group. Expected: primary, custom, cdn, devinfra, dns, default, or all"
        ;;
      *)
        error_exit "Invalid group: $2. Expected: primary, custom, cdn, devinfra, dns, default, or all"
        ;;
      esac
      shift 2
      ;;
    --full)
      GROUPS_TO_SHOW="all"
      shift
      ;;
    -t | --timeout)
      if [[ "$2" =~ ^[0-9]+$ ]]; then
        CURL_TIMEOUT="$2"
      else
        error_exit "Invalid timeout value: $2. Timeout must be a positive integer"
      fi
      shift 2
      ;;
    --only-changes)
      ONLY_CHANGES=true
      shift
      ;;
    --dns-summary)
      DNS_SUMMARY=true
      shift
      ;;
    --fail-on-block)
      [[ -z "${2:-}" ]] && error_exit "Missing value for --fail-on-block"
      local fob_key
      fob_key=$(normalize_service_name "$2")
      if ! validate_known_service "$fob_key"; then
        error_exit "Unknown service for --fail-on-block: $2"
      fi
      FAIL_ON_BLOCK_KEYS+=("$fob_key")
      shift 2
      ;;
    --watch)
      WATCH_INTERVAL="${2:-}"
      if ! [[ "$WATCH_INTERVAL" =~ ^[1-9][0-9]*$ ]]; then
        error_exit "Invalid watch interval: ${WATCH_INTERVAL:-missing}. Must be a positive integer (seconds)"
      fi
      shift 2
      ;;
    --compare)
      COMPARE_OLD="${2:-}"
      COMPARE_NEW="${3:-}"
      if [[ -z "$COMPARE_OLD" || -z "$COMPARE_NEW" ]]; then
        error_exit "--compare requires two files: --compare OLD.json NEW.json"
      fi
      shift 3
      ;;
    -P | --parallel)
      if [[ "$2" =~ ^[0-9]+$ ]] && ((10#$2 >= 1)); then
        PARALLEL_JOBS="$2"
      else
        error_exit "Invalid parallel value: $2. Parallel jobs must be a positive integer"
      fi
      shift 2
      ;;
    --progress-log)
      PROGRESS_LOG=true
      shift
      ;;
    --emoji)
      SHOW_EMOJI=true
      shift
      ;;
    --no-attention)
      SHOW_ATTENTION=false
      shift
      ;;
    -4 | --ipv4)
      IPV4_ONLY=true
      shift
      ;;
    -6 | --ipv6)
      IPV6_ONLY=true
      shift
      ;;
    -p | --proxy)
      if ! is_valid_proxy_addr "$2"; then
        error_exit "Invalid proxy address: $2. Expected host:port or [ipv6]:port"
      fi
      PROXY_ADDR="$2"
      log "$LOG_INFO" "Using SOCKS5 proxy: $PROXY_ADDR"
      shift 2
      ;;
    -i | --interface)
      if ! is_valid_interface_name "$2"; then
        error_exit "Invalid interface name: $2"
      fi
      INTERFACE_NAME="$2"
      log "$LOG_INFO" "Using interface: $INTERFACE_NAME"
      shift 2
      ;;
    --no-cache)
      CACHE_ENABLED=false
      log "$LOG_INFO" "Cache disabled"
      shift
      ;;
    --cache-ttl)
      if [[ "$2" =~ ^[0-9]+$ ]] && ((10#$2 >= 0)); then
        CACHE_TTL="$2"
        log "$LOG_INFO" "Cache TTL set to ${CACHE_TTL}s"
      else
        error_exit "Invalid cache TTL value: $2. TTL must be a non-negative integer"
      fi
      shift 2
      ;;
    --clear-cache)
      CACHE_CLEARED=true
      shift
      ;;
    --show-cache)
      CACHE_SHOWN=true
      shift
      ;;
    --list)
      LIST_ONLY=true
      shift
      ;;
    --include-service)
      if [[ -z "$2" ]]; then
        error_exit "Missing value for --include-service"
      fi
      local include_service
      include_service=$(normalize_service_name "$2")
      if ! validate_known_service "$include_service"; then
        error_exit "Unknown service for --include-service: $2"
      fi
      INCLUDED_SERVICES+=("$include_service")
      shift 2
      ;;
    --exclude-service)
      if [[ -z "$2" ]]; then
        error_exit "Missing value for --exclude-service"
      fi
      local exclude_service
      exclude_service=$(normalize_service_name "$2")
      if ! validate_known_service "$exclude_service"; then
        error_exit "Unknown service for --exclude-service: $2"
      fi
      EXCLUDED_SERVICES_CLI+=("$exclude_service")
      shift 2
      ;;
    --metrics)
      SHOW_METRICS=true
      shift
      ;;
    --youtube-lang)
      if [[ -z "$2" ]]; then
        error_exit "Missing value for --youtube-lang"
      fi
      YOUTUBE_LANG="$2"
      shift 2
      ;;
    -o | --output)
      if [[ -z "$2" ]]; then
        error_exit "Missing value for --output"
      fi
      OUTPUT_FILE="$2"
      shift 2
      ;;
    *)
      error_exit "Unknown option: $1"
      ;;
    esac
  done

  if [[ ! "$YOUTUBE_LANG" =~ ^[a-z]{2,3}(-[A-Za-z0-9]{2,4})?$ ]]; then
    error_exit "Invalid YouTube language: $YOUTUBE_LANG"
  fi
}

is_status_string() {
  local value="$1"

  case "$value" in
  "$STATUS_DENIED" | "$STATUS_SERVER_ERROR" | "$STATUS_RATE_LIMIT" | "$STATUS_NA" | "$STATUS_REGION_BLOCKED")
    return 0
    ;;
  *)
    return 1
    ;;
  esac
}

status_from_http_code() {
  local code="$1"

  case "$code" in
  403)
    echo "$STATUS_DENIED"
    ;;
  429)
    echo "$STATUS_RATE_LIMIT"
    ;;
  451)
    echo "$STATUS_REGION_BLOCKED"
    ;;
  5*)
    echo "$STATUS_SERVER_ERROR"
    ;;
  4*)
    echo "$STATUS_NA"
    ;;
  *)
    echo ""
    ;;
  esac
}

get_ping_command() {
  local version="$1"
  local ping_cmd

  if [[ "$version" == "4" ]]; then
    if is_command_available "ping"; then
      ping_cmd="ping"
    fi
  else
    if is_command_available "ping6"; then
      ping_cmd="ping6"
    elif is_command_available "ping"; then
      ping_cmd="ping -6"
    fi
  fi

  if [[ -n "$ping_cmd" ]]; then
    echo "$ping_cmd"
    return 0
  else
    return 1
  fi
}

check_ip_interfaces() {
  local version="$1"
  local ifconfig_output

  log "$LOG_INFO" "Checking for IPv${version} interfaces"

  if is_command_available "ip"; then
    if [[ -n $(ip -"${version}" addr show scope global 2>/dev/null) ]]; then
      log "$LOG_INFO" "IPv${version} global interfaces found"
      return 0
    fi
  elif is_command_available "ifconfig"; then
    ifconfig_output=$(ifconfig -a 2>/dev/null)
    if [[ "$version" == "4" ]]; then
      if echo "$ifconfig_output" | grep -E '\binet [0-9]+' | grep -Ev '\binet 127\.' >/dev/null; then
        log "$LOG_INFO" "IPv${version} global interfaces found (ifconfig)"
        return 0
      fi
    else
      if echo "$ifconfig_output" | grep -E '\binet6 [0-9A-Fa-f:]+' | grep -Ev '\binet6 (fe80:|::1)' >/dev/null; then
        log "$LOG_INFO" "IPv${version} global interfaces found (ifconfig)"
        return 0
      fi
    fi
  else
    log "$LOG_WARN" "Neither ip nor ifconfig is available to check IPv${version} interfaces"
    return 1
  fi

  log "$LOG_ERROR" "No global IPv${version} addresses found on interfaces"
  return 1
}

check_ip_connectivity() {
  local version="$1"
  local test_hosts_v4=("8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1" "9.9.9.9")
  local test_hosts_v6=("2001:4860:4860::8888" "2001:4860:4860::8844" "2606:4700:4700::1111" "2606:4700:4700::1001" "2620:fe::9")
  local timeout=3
  local count=1
  local test_hosts ping_cmd

  log "$LOG_INFO" "Checking IPv${version} connectivity"

  ping_cmd=($(get_ping_command "$version"))

  if [[ ${#ping_cmd[@]} -eq 0 ]]; then
    log "$LOG_ERROR" "Ping command for IPv${version} is not available"
    return 1
  fi

  if [[ "$version" == "4" ]]; then
    test_hosts=("${test_hosts_v4[@]}")
  else
    test_hosts=("${test_hosts_v6[@]}")
  fi

  for host in "${test_hosts[@]}"; do
    if "${ping_cmd[@]}" -c "$count" -W "$timeout" "$host" >/dev/null 2>&1; then
      log "$LOG_INFO" "IPv${version} connectivity confirmed via $host"
      return 0
    fi
  done

  log "$LOG_ERROR" "IPv${version} connectivity test failed"
  return 1
}

check_ip_dns() {
  local version="$1"
  local test_domain="google.com"
  local record_type
  local dig_result

  log "$LOG_INFO" "Checking IPv${version} DNS resolution"

  if [[ "$version" == "4" ]]; then
    record_type="A"
  else
    record_type="AAAA"
  fi

  if is_command_available "nslookup"; then
    if nslookup -type="$record_type" "$test_domain" >/dev/null 2>&1; then
      log "$LOG_INFO" "IPv${version} DNS resolution works via nslookup"
      return 0
    fi
  elif is_command_available "dig"; then
    dig_result=$(dig +short -t "$record_type" "$test_domain" 2>/dev/null)
    if [[ -n "$dig_result" ]]; then
      log "$LOG_INFO" "IPv${version} DNS resolution works via dig"
      return 0
    fi
  elif is_command_available "host"; then
    if host -t "$record_type" "$test_domain" >/dev/null 2>&1; then
      log "$LOG_INFO" "IPv${version} DNS resolution works via host"
      return 0
    fi
  else
    log "$LOG_WARN" "Neither nslookup, dig, nor host is available to check IPv${version} DNS resolution"
    return 1
  fi

  log "$LOG_ERROR" "IPv${version} DNS resolution failed"
  return 1
}

print_ipv4_default_routes() {
  local iface destination flags mask

  if [[ ! -r "$IPV4_ROUTE_TABLE" ]]; then
    return
  fi

  while read -r iface destination _ flags _ _ _ mask _; do
    if [[ "$destination" == "$IPV4_DEFAULT_ROUTE" && "$mask" == "$IPV4_DEFAULT_ROUTE" ]]; then
      printf '%s %s\n' "$iface" "$flags"
    fi
  done <"$IPV4_ROUTE_TABLE"
}

print_ipv6_default_routes() {
  local destination prefix_length flags iface

  if [[ ! -r "$IPV6_ROUTE_TABLE" ]]; then
    return
  fi

  while read -r destination prefix_length _ _ _ _ _ _ flags iface; do
    if [[ "$destination" == "$IPV6_DEFAULT_ROUTE" && "$prefix_length" == "$IPV6_DEFAULT_PREFIX_LENGTH" ]]; then
      printf '%s %s\n' "$iface" "$flags"
    fi
  done <"$IPV6_ROUTE_TABLE"
}

print_default_routes() {
  local ip_version="$1"

  case "$ip_version" in
  4) print_ipv4_default_routes ;;
  6) print_ipv6_default_routes ;;
  esac
}

has_route_flag() {
  local flags="$1"
  local flag="$2"

  ((16#$flags & flag))
}

print_gateway_interface() {
  local ip_version="$1"
  local iface flags

  while read -r iface flags; do
    if has_route_flag "$flags" "$ROUTE_FLAG_UP" && has_route_flag "$flags" "$ROUTE_FLAG_GATEWAY"; then
      printf '%s' "$iface"
      return
    fi
  done < <(print_default_routes "$ip_version")
}

has_default_route_through() {
  local ip_version="$1"
  local interface="$2"
  local iface flags

  while read -r iface flags; do
    if [[ "$iface" == "$interface" ]] && has_route_flag "$flags" "$ROUTE_FLAG_UP"; then
      return 0
    fi
  done < <(print_default_routes "$ip_version")

  return 1
}

has_default_route() {
  local ip_version="$1"
  local iface flags

  while read -r iface flags; do
    if has_route_flag "$flags" "$ROUTE_FLAG_UP"; then
      return 0
    fi
  done < <(print_default_routes "$ip_version")

  return 1
}

ignore_ip_version_with_proxy() {
  if [[ -z "$PROXY_ADDR" ]] || [[ "$IPV4_ONLY" == false && "$IPV6_ONLY" == false ]]; then
    return
  fi

  printf "%s %s\n" \
    "$(color WARN '[WARN]')" \
    "--ipv4 and --ipv6 are ignored with --proxy, the proxy picks the protocol" >&2
  IPV4_ONLY=false
  IPV6_ONLY=false
}

detect_main_interface() {
  if [[ -n "$INTERFACE_NAME" || -n "$PROXY_ADDR" || "$IPV4_ONLY" == true || "$IPV6_ONLY" == true ]]; then
    return
  fi

  MAIN_INTERFACE=$(print_gateway_interface 4)
  if [[ -z "$MAIN_INTERFACE" ]]; then
    MAIN_INTERFACE=$(print_gateway_interface 6)
  fi
}

check_ip_default_route() {
  local version="$1"

  # Route tables are Linux-only; without them the remaining checks stay authoritative.
  if [[ ! -r "$IPV4_ROUTE_TABLE" && ! -r "$IPV6_ROUTE_TABLE" ]]; then
    return 0
  fi

  if has_default_route "$version"; then
    log "$LOG_INFO" "IPv${version} has a default route"
    return 0
  fi

  log "$LOG_ERROR" "No IPv${version} default route found"
  return 1
}

check_ip_support() {
  local version="$1"
  local -a checks=("interfaces" "connectivity" "dns")
  local -a failed=()

  spinner_update "IPv$version support"
  log "$LOG_INFO" "Starting comprehensive IPv${version} support check"

  if ! check_ip_default_route "$version"; then
    log "$LOG_ERROR" "IPv${version} is not fully supported. Failed checks: no-default-route"
    return 1
  fi

  for check in "${checks[@]}"; do
    if ! "check_ip_${check}" "$version"; then
      failed+=("$check")
      break
    fi
  done

  if [[ ${#failed[@]} -eq 0 ]]; then
    log "$LOG_INFO" "IPv${version} is fully supported (${checks[*]})"
    return 0
  else
    log "$LOG_ERROR" "IPv${version} is not fully supported. Failed checks: ${failed[*]}"
    return 1
  fi
}

ipv4_enabled() {
  [[ "$IPV6_ONLY" != true ]] && [[ "$IPV4_SUPPORTED" -eq 0 ]]
}

ipv6_enabled() {
  [[ "$IPV4_ONLY" != true ]] && [[ "$IPV6_SUPPORTED" -eq 0 ]]
}

can_use_ipv4() {
  ipv4_enabled && [[ -n "$EXTERNAL_IPV4" ]]
}

can_use_ipv6() {
  ipv6_enabled && [[ "$IPV6_SUPPORTED" -eq 0 ]] && [[ -n "$EXTERNAL_IPV6" ]]
}

preferred_ip_version() {
  can_use_ipv4 && echo 4 || echo 6
}

preferred_ip() {
  can_use_ipv4 && echo "$EXTERNAL_IPV4" || echo "$EXTERNAL_IPV6"
}

# Cache Management Functions
load_ip_cache() {
  local ip_version="$1"
  local cache_content cached_ip cached_timestamp cached_source current_timestamp cache_age

  CACHE_LAST_SOURCE=""
  CACHE_LAST_TIMESTAMP=""

  if [[ "$CACHE_ENABLED" != true ]]; then
    return 1
  fi

  if [[ ! -f "$CACHE_FILE" ]]; then
    log "$LOG_DEBUG" "Cache file not found: $CACHE_FILE"
    return 1
  fi

  cache_content=$(cat "$CACHE_FILE" 2>/dev/null)

  if [[ -z "$cache_content" ]]; then
    log "$LOG_WARN" "Cache file is empty"
    return 1
  fi

  if ! is_valid_json "$cache_content"; then
    log "$LOG_WARN" "Cache file contains invalid JSON"
    return 1
  fi

  cached_ip=$(echo "$cache_content" | jq -r --arg v "ipv$ip_version" '.[$v].address // empty' 2>/dev/null)
  cached_timestamp=$(echo "$cache_content" | jq -r --arg v "ipv$ip_version" '.[$v].timestamp // empty' 2>/dev/null)
  cached_source=$(echo "$cache_content" | jq -r --arg v "ipv$ip_version" '.[$v].source // empty' 2>/dev/null)

  if [[ -z "$cached_ip" ]] || [[ -z "$cached_timestamp" ]]; then
    log "$LOG_WARN" "Cache missing IPv${ip_version} data"
    return 1
  fi

  current_timestamp=$(date +%s)
  cache_age=$((current_timestamp - cached_timestamp))

  if [[ $cache_age -gt $CACHE_TTL ]]; then
    log "$LOG_INFO" "Cached IPv${ip_version} expired (age: ${cache_age}s, TTL: ${CACHE_TTL}s)"
    return 1
  fi

  if [[ "$ip_version" == "4" ]]; then
    if ! is_valid_ipv4 "$cached_ip"; then
      log "$LOG_WARN" "Cached IPv4 address is invalid: $cached_ip"
      return 1
    fi
  else
    if ! is_valid_ipv6 "$cached_ip"; then
      log "$LOG_WARN" "Cached IPv6 address is invalid: $cached_ip"
      return 1
    fi
  fi

  log "$LOG_INFO" "Using cached IPv${ip_version} address: $cached_ip (age: ${cache_age}s)"
  CACHE_LAST_SOURCE="$cached_source"
  CACHE_LAST_TIMESTAMP="$cached_timestamp"
  echo "$cached_ip"
  return 0
}

save_ip_cache() {
  local ip_version="$1"
  local ip_address="$2"
  local service="$3"
  local cache_content current_timestamp
  local temp_file

  if [[ "$CACHE_ENABLED" != true ]]; then
    return 0
  fi

  if [[ -z "$ip_address" ]]; then
    log "$LOG_WARN" "Cannot save empty IP address to cache"
    return 1
  fi

  current_timestamp=$(date +%s)

  if [[ -f "$CACHE_FILE" ]]; then
    cache_content=$(cat "$CACHE_FILE" 2>/dev/null)
  fi

  if [[ -n "$cache_content" ]] && is_valid_json "$cache_content"; then
    cache_content=$(echo "$cache_content" | jq \
      --arg v "ipv$ip_version" \
      --arg ip "$ip_address" \
      --arg ts "$current_timestamp" \
      --arg src "$service" \
      '.[$v] = {address: $ip, timestamp: ($ts | tonumber), source: $src}')
  else
    cache_content=$(jq -n \
      --arg v "ipv$ip_version" \
      --arg ip "$ip_address" \
      --arg ts "$current_timestamp" \
      --arg src "$service" \
      '{version: 1, ($v): {address: $ip, timestamp: ($ts | tonumber), source: $src}}')
  fi

  mkdir -p "$CACHE_DIR"
  temp_file=$(mktemp "$CACHE_FILE.XXXXXX")
  echo "$cache_content" >"$temp_file"
  chmod 0600 "$temp_file"
  mv "$temp_file" "$CACHE_FILE"

  log "$LOG_INFO" "Saved IPv${ip_version} address to cache: $ip_address"
}

clear_ip_cache() {
  if [[ -f "$CACHE_FILE" ]]; then
    rm -f "$CACHE_FILE"
    log "$LOG_INFO" "Cache file cleared: $CACHE_FILE"
  fi
}

show_ip_cache() {
  local cache_content cached_ipv4 cached_ipv6 ipv4_ts ipv6_ts ipv4_src ipv6_src
  local current_timestamp ipv4_age ipv6_age ipv4_status ipv6_status

  if [[ ! -f "$CACHE_FILE" ]]; then
    echo "No cache file found at $CACHE_FILE"
    return 0
  fi

  cache_content=$(cat "$CACHE_FILE" 2>/dev/null)

  if [[ -z "$cache_content" ]] || ! is_valid_json "$cache_content"; then
    echo "Cache file exists but contains invalid data"
    return 1
  fi

  current_timestamp=$(date +%s)

  cached_ipv4=$(echo "$cache_content" | jq -r '.ipv4.address // empty' 2>/dev/null)
  cached_ipv6=$(echo "$cache_content" | jq -r '.ipv6.address // empty' 2>/dev/null)
  ipv4_ts=$(echo "$cache_content" | jq -r '.ipv4.timestamp // empty' 2>/dev/null)
  ipv6_ts=$(echo "$cache_content" | jq -r '.ipv6.timestamp // empty' 2>/dev/null)
  ipv4_src=$(echo "$cache_content" | jq -r '.ipv4.source // empty' 2>/dev/null)
  ipv6_src=$(echo "$cache_content" | jq -r '.ipv6.source // empty' 2>/dev/null)

  echo "IP Cache Contents"
  echo "================="
  echo "Cache file: $CACHE_FILE"
  echo "Cache TTL: ${CACHE_TTL}s"
  echo ""

  if [[ -n "$cached_ipv4" ]] && [[ -n "$ipv4_ts" ]]; then
    ipv4_age=$((current_timestamp - ipv4_ts))
    if [[ $ipv4_age -le $CACHE_TTL ]]; then
      ipv4_status="Valid"
    else
      ipv4_status="Expired"
    fi
    echo "IPv4: $cached_ipv4"
    echo "  Status: $ipv4_status"
    echo "  Age: ${ipv4_age}s"
    echo "  Source: $ipv4_src"
  else
    echo "IPv4: Not cached"
  fi
  echo ""

  if [[ -n "$cached_ipv6" ]] && [[ -n "$ipv6_ts" ]]; then
    ipv6_age=$((current_timestamp - ipv6_ts))
    if [[ $ipv6_age -le $CACHE_TTL ]]; then
      ipv6_status="Valid"
    else
      ipv6_status="Expired"
    fi
    echo "IPv6: $cached_ipv6"
    echo "  Status: $ipv6_status"
    echo "  Age: ${ipv6_age}s"
    echo "  Source: $ipv6_src"
  else
    echo "IPv6: Not cached"
  fi
}

shuffle_identity_services() {
  local i tmp size rand_idx
  size=${#IDENTITY_SERVICES[@]}

  for ((i = size - 1; i > 0; i--)); do
    rand_idx=$((RANDOM % (i + 1)))

    if ((rand_idx != i)); then
      tmp=${IDENTITY_SERVICES[i]}
      IDENTITY_SERVICES[i]=${IDENTITY_SERVICES[rand_idx]}
      IDENTITY_SERVICES[rand_idx]=$tmp
    fi
  done
}

fetch_ip_from_service_with_retry() {
  local service="$1"
  local ip_version="$2"
  local response attempt delay
  local max_retries=$IP_FETCH_MAX_RETRIES

  for ((attempt = 1; attempt <= max_retries; attempt++)); do
    response=$(curl_wrapper GET "https://$service" --ip-version "$ip_version")

    if [[ -n "$response" ]]; then
      echo "$response"
      return 0
    fi

    if ((attempt < max_retries)); then
      delay=$((IP_FETCH_RETRY_DELAY * (2 ** (attempt - 1))))
      log "$LOG_DEBUG" "Retry $attempt/$max_retries for $service after ${delay}s delay"
      sleep "$delay"
    fi
  done

  log "$LOG_WARN" "Failed to fetch IP from $service after $max_retries retries"
  return 1
}

fetch_external_ip() {
  local ip_version="$1"
  local service ip
  local now

  spinner_update "External IPv$ip_version address"
  log "$LOG_INFO" "Getting external IPv${ip_version} address"

  shuffle_identity_services

  for service in "${IDENTITY_SERVICES[@]}"; do
    ip=$(fetch_ip_from_service_with_retry "$service" "$ip_version")
    ip=${ip//$'\r'/}
    ip=${ip//$'\n'/}
    ip=${ip//[[:space:]]/}

    if [[ "$ip_version" == "4" ]]; then
      if ! is_valid_ipv4 "$ip"; then
        log "$LOG_WARN" "Invalid IPv4 from $service: $ip"
        continue
      fi
    else
      if ! is_valid_ipv6 "$ip"; then
        log "$LOG_WARN" "Invalid IPv6 from $service: $ip"
        continue
      fi
    fi

    if [[ -n "$ip" ]]; then
      log "$LOG_INFO" "Successfully obtained IPv${ip_version} address from $service: $ip"
      save_ip_cache "$ip_version" "$ip" "$service"
      now=$(date +%s)
      if [[ "$ip_version" == "4" ]]; then
        EXTERNAL_IPV4_SOURCE="$service"
        EXTERNAL_IPV4_CACHE_HIT=false
        EXTERNAL_IPV4_TIMESTAMP="$now"
      else
        EXTERNAL_IPV6_SOURCE="$service"
        EXTERNAL_IPV6_CACHE_HIT=false
        EXTERNAL_IPV6_TIMESTAMP="$now"
      fi
      echo "$ip"
      return 0
    else
      log "$LOG_WARN" "No response from $service for IPv${ip_version}"
    fi
  done

  log "$LOG_WARN" "Failed to obtain IPv${ip_version} address from any service, trying cache"
  ip=$(load_ip_cache "$ip_version")
  if [[ -n "$ip" ]]; then
    if [[ "$ip_version" == "4" ]]; then
      EXTERNAL_IPV4_SOURCE="${CACHE_LAST_SOURCE:-cache}"
      EXTERNAL_IPV4_CACHE_HIT=true
      EXTERNAL_IPV4_TIMESTAMP="$CACHE_LAST_TIMESTAMP"
    else
      EXTERNAL_IPV6_SOURCE="${CACHE_LAST_SOURCE:-cache}"
      EXTERNAL_IPV6_CACHE_HIT=true
      EXTERNAL_IPV6_TIMESTAMP="$CACHE_LAST_TIMESTAMP"
    fi
    echo "$ip"
    return 0
  fi

  log "$LOG_ERROR" "Failed to obtain IPv${ip_version} address from any service or cache"
  return 1
}

discover_external_ips() {
  local ipv4_failed=false ipv6_failed=false
  local ipv4_tmp ipv4_pid

  # IPv4 and IPv6 discovery hit the same identity services independently -
  # run them concurrently instead of paying both latencies sequentially
  if ipv4_enabled; then
    ipv4_tmp=$(mktemp "${TMPDIR:-/tmp}/ipregion_ipv4_XXXXXX")
    (fetch_external_ip 4 >"$ipv4_tmp") &
    ipv4_pid=$!
  fi

  if ipv6_enabled; then
    EXTERNAL_IPV6=$(fetch_external_ip 6)
    if [[ -z "$EXTERNAL_IPV6" ]]; then
      ipv6_failed=true
    fi
  fi

  if ipv4_enabled; then
    wait "$ipv4_pid"
    EXTERNAL_IPV4=$(<"$ipv4_tmp")
    rm -f "$ipv4_tmp"
    if [[ -z "$EXTERNAL_IPV4" ]]; then
      ipv4_failed=true
    fi
  fi

  if [[ "$ipv4_failed" == true ]] && [[ "$ipv6_failed" == true ]]; then
    if [[ -n "$INTERFACE_NAME" ]]; then
      error_exit "Failed to obtain external IPv4 and IPv6 address through interface $INTERFACE_NAME. Check network connectivity, DNS settings, proxy configuration, and firewall rules."
    fi
    error_exit "Failed to obtain external IPv4 and IPv6 address. Check network connectivity, DNS settings, proxy configuration, and firewall rules."
  fi

  if [[ "$ipv4_failed" == true ]]; then
    log "$LOG_WARN" "IPv4 address not available, continuing with IPv6 only"
  fi

  if [[ "$ipv6_failed" == true ]]; then
    log "$LOG_WARN" "IPv6 address not available, continuing with IPv4 only"
  fi
}

load_maxmind_profile() {
  local ip_version="$1"
  local response

  if [[ "$ip_version" == "4" && -n "$MAXMIND_PROFILE_IPV4" ]]; then
    return 0
  fi

  if [[ "$ip_version" == "6" && -n "$MAXMIND_PROFILE_IPV6" ]]; then
    return 0
  fi

  response=$(curl_wrapper GET "https://geoip.maxmind.com/geoip/v2.1/city/me" \
    --header "Referer: https://www.maxmind.com" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]] || ! is_valid_json "$response"; then
    log "$LOG_WARN" "Failed to load MaxMind profile for IPv${ip_version}"
    return 1
  fi

  if [[ "$ip_version" == "4" ]]; then
    MAXMIND_PROFILE_IPV4="$response"
  else
    MAXMIND_PROFILE_IPV6="$response"
  fi

  return 0
}

get_registered_country() {
  local ip_version="$1"
  local ip="$2"
  local response

  if [[ -z "$ip" ]]; then
    echo ""
    return 1
  fi

  response=$(curl_wrapper GET "https://stat.ripe.net/data/rir-stats-country/data.json?resource=$ip" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    echo ""
    return 1
  fi

  local country
  country=$(process_json "$response" ".data.located_resources[0].location")
  if [[ -z "$country" || "$country" == "null" ]]; then
    echo ""
    return 1
  fi

  printf "%s" "$country"
}

get_asn() {
  local ip_version ip profile traits

  ip_version=$(preferred_ip_version)
  ip=$(preferred_ip)

  spinner_update "ASN info"
  log "$LOG_INFO" "Getting ASN info for IP $ip"
  ASN_NUMBER=""
  ASN_NAME=""

  if ! load_maxmind_profile "$ip_version"; then
    return 1
  fi

  if [[ "$ip_version" == "4" ]]; then
    profile="$MAXMIND_PROFILE_IPV4"
  else
    profile="$MAXMIND_PROFILE_IPV6"
  fi

  traits=$(process_json "$profile" ".traits")
  ASN_NUMBER=$(process_json "$traits" ".autonomous_system_number")
  ASN_NAME=$(process_json "$traits" ".autonomous_system_organization")

  if [[ "$ASN_NUMBER" == "null" ]]; then
    ASN_NUMBER=""
  fi
  if [[ "$ASN_NAME" == "null" ]]; then
    ASN_NAME=""
  fi

  if [[ -n "$ASN_NUMBER" ]]; then
    log "$LOG_INFO" "ASN info: AS$ASN_NUMBER $ASN_NAME"
  fi
}

load_registered_countries() {
  if can_use_ipv4; then
    REGISTERED_COUNTRY_IPV4=$(get_registered_country 4 "$EXTERNAL_IPV4")
  fi

  if can_use_ipv6; then
    REGISTERED_COUNTRY_IPV6=$(get_registered_country 6 "$EXTERNAL_IPV6")
  fi
}

is_ipv6_over_ipv4_service() {
  local service="$1"
  for s in "${IPV6_OVER_IPV4_SERVICES[@]}"; do
    [[ "$s" == "$service" ]] && return 0
  done
  return 1
}

spinner_start() {
  local delay=0.1
  # Braille spinner frames; an array keeps multibyte characters whole in
  # any locale (byte-wise substring slicing would split them under LC_ALL=C)
  local -a spin_frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local current_service frame
  local checks_done=0

  SPINNER_SERVICE_FILE=$(mktemp "${TMPDIR:-/tmp}/ipregion_spinner_XXXXXX")
  CHECKS_DONE_FILE=$(mktemp "${TMPDIR:-/tmp}/ipregion_done_XXXXXX")
  : >"$CHECKS_DONE_FILE"
  CHECKS_TOTAL_FILE=$(mktemp "${TMPDIR:-/tmp}/ipregion_total_XXXXXX")
  CHECKS_GROUP_FILE=$(mktemp "${TMPDIR:-/tmp}/ipregion_group_XXXXXX")
  SPINNER_ACTIVE=true
  spinner_running=true

  (
    COLOR_TARGET=stderr
    while $spinner_running; do
      # Self-termination sentinel: when the parent's cleanup removed the
      # service file (or the parent died without cleanup and a later run
      # swept the stale files), stop spinning instead of looping forever.
      [[ -f "$SPINNER_SERVICE_FILE" ]] || break
      for frame in "${spin_frames[@]}"; do
        current_service=""
        # BSD wc pads its output with spaces even for stdin reads - strip
        # them or the numeric regex below fails and the count resets to 0
        checks_done=$(wc -l <"$CHECKS_DONE_FILE" 2>/dev/null | tr -d ' ')
        [[ "$checks_done" =~ ^[0-9]+ ]] || checks_done=0
        # Markers carry the verdict color code: the done counter renders
        # in the color of the most recent check verdict
        last_verdict_color=$(tail -n 1 "$CHECKS_DONE_FILE" 2>/dev/null)
        [[ "$last_verdict_color" =~ ^[0-9]+(;[0-9]+)?$ ]] || last_verdict_color="$COLOR_SERVICE"
        # The total is written by main AFTER this subshell forked, so read
        # it from the file (variable updates do not cross the boundary)
        checks_total=$(cat "$CHECKS_TOTAL_FILE" 2>/dev/null)
        [[ "$checks_total" =~ ^[0-9]+ ]] || checks_total=$CHECKS_TOTAL
        current_group=$(cat "$CHECKS_GROUP_FILE" 2>/dev/null)

        if [[ -f "$SPINNER_SERVICE_FILE" ]]; then
          current_service="$(cat "$SPINNER_SERVICE_FILE")"
        fi

        local elapsed=$((SECONDS - RUN_START_SECONDS))
        local time_str=""
        if ((elapsed > 0)); then
          if ((elapsed >= 60)); then
            printf -v time_str '%d:%02d' $((elapsed / 60)) $((elapsed % 60))
          else
            time_str="${elapsed}s"
          fi
        fi

        # Progressive segments joined by dim middle dots:
        #   glyph · 12s · custom · 9/194 · service
        local -a parts=()
        [[ -n "$time_str" ]] && parts+=("$(color NULL "$time_str")")
        [[ -n "$current_group" ]] && parts+=("$(color HEADER "$current_group")")
        if [[ "$checks_total" =~ ^[0-9]+$ && "$checks_total" -gt 0 ]]; then
          # the done counter renders in the color of the last verdict
          parts+=("$(color "$last_verdict_color" "$checks_done")$(color NULL "/$checks_total")")
        fi
        [[ -n "$current_service" ]] && parts+=("$(bold "$(color SERVICE "$current_service")")")

        local part joined="" separator=""
        for part in "${parts[@]}"; do
          joined+="$separator$part"
          separator=" $(color NULL "·") "
        done

        printf "\r\033[K%s %s" \
          "$(color HEADER "$frame")" \
          "$joined" >&2

        sleep $delay
      done
    done
  ) &

  spinner_pid=$!
}

spinner_stop() {
  spinner_running=false

  if [[ -n "${spinner_pid:-}" ]]; then
    # The rendering subshell may already have died from an INT delivered
    # to the whole process group - or been reaped by an earlier wait;
    # kill and reap unconditionally (errors are harmless here).
    kill "$spinner_pid" 2>/dev/null || true
    wait "$spinner_pid" 2>/dev/null || true
    spinner_pid=""
  fi

  # Wipe the frame line completely: the old 40-column space overwrite
  # left trailing residue on lines longer than 40 columns.
  if [[ "${SPINNER_ACTIVE:-}" == true ]]; then
    printf "\r\033[K" >&2
    SPINNER_ACTIVE=false
  fi

  if [[ -f "$SPINNER_SERVICE_FILE" ]]; then
    rm -f "$SPINNER_SERVICE_FILE"
    unset SPINNER_SERVICE_FILE
  fi

  if [[ -f "${CHECKS_DONE_FILE:-}" ]]; then
    rm -f "$CHECKS_DONE_FILE"
    unset CHECKS_DONE_FILE
  fi

  if [[ -f "${CHECKS_TOTAL_FILE:-}" ]]; then
    rm -f "$CHECKS_TOTAL_FILE"
    unset CHECKS_TOTAL_FILE
  fi

  if [[ -f "${CHECKS_GROUP_FILE:-}" ]]; then
    rm -f "$CHECKS_GROUP_FILE"
    unset CHECKS_GROUP_FILE
  fi
}

spinner_update() {
  local value="$1"

  if [[ -n "$SPINNER_SERVICE_FILE" ]]; then
    echo "$value" >"$SPINNER_SERVICE_FILE"
  fi

  if [[ "$PROGRESS_LOG" == true && "$JSON_OUTPUT" != "true" ]]; then
    if [[ "$value" != "$LAST_PROGRESS_MSG" ]]; then
      LAST_PROGRESS_MSG="$value"
      printf "%s %s\n" \
        "$(color INFO '[INFO]')" \
        "Checking: $value" >&2
    fi
  fi
}

cleanup_on_exit() {
  spinner_stop
  if [[ "$DEBUG" == true ]]; then
    cleanup_debug
  fi
}

cleanup_on_interrupt() {
  cleanup_on_exit
  exit 130
}

curl_wrapper() {
  local method="$1"
  local url="$2"
  shift 2
  local ip_version user_agent json data data_urlencode file forms headers cookie cookie_jar
  local effective_url_flag=false effective_url="" meta_effective=""
  local response_with_meta response http_code latency_seconds latency_ms curl_exit
  local error_type=""
  local curl_args=(
    --silent
    --compressed
    --location
    --retry-connrefused
    --retry "$CURL_RETRIES"
    --max-time "$CURL_TIMEOUT"
  )

  case "$method" in
  HEAD)
    curl_args+=(--head)
    ;;
  *)
    curl_args+=(--request "$method")
    ;;
  esac

  while (($#)); do
    case "$1" in
    --ip-version)
      ip_version="$2"
      shift 2
      ;;
    --effective-url)
      effective_url_flag=true
      shift
      ;;
    --user-agent)
      user_agent="$2"
      shift 2
      ;;
    --header)
      headers+=("$2")
      shift 2
      ;;
    --json)
      json="$2"
      shift 2
      ;;
    --data)
      data="$2"
      shift 2
      ;;
    --data-urlencode)
      data_urlencode="$2"
      shift 2
      ;;
    --file)
      file="$2"
      shift 2
      ;;
    --cookie-jar)
      cookie_jar="$2"
      shift 2
      ;;
    --cookie)
      cookie="$2"
      shift 2
      ;;
    --form)
      forms+=("$2")
      shift 2
      ;;
    esac
  done

  case "$ip_version" in
  4)
    curl_args+=(-4)
    ;;
  6)
    curl_args+=(-6)
    ;;
  proxy)
    : # let the proxy pick the protocol
    ;;
  esac

  for h in "${headers[@]}"; do
    curl_args+=(-H "$h")
  done

  if [[ -n "$user_agent" ]]; then
    curl_args+=(-A "$user_agent")
  fi

  if [[ -n "$json" ]]; then
    # curl --json needs curl >= 7.82 (missing on older macOS); emulate it
    curl_args+=(--data "$json")
    curl_args+=(--header "Content-Type: application/json")
    curl_args+=(--header "Accept: application/json")
  fi

  if [[ -n "$cookie_jar" ]]; then
    curl_args+=(--cookie-jar "$cookie_jar")
  fi

  if [[ -n "$cookie" ]]; then
    curl_args+=(--cookie "$cookie")
  fi

  if [[ -n "$data" ]]; then
    curl_args+=(--data "$data")
  fi

  if [[ -n "$data_urlencode" ]]; then
    curl_args+=(--data-urlencode "$data_urlencode")
  fi

  if [[ -n "$file" ]]; then
    curl_args+=(--upload-file "$file")
  fi

  for f in "${forms[@]}"; do
    curl_args+=(-F "$f")
  done

  if [[ -n "$PROXY_ADDR" ]]; then
    curl_args+=(--proxy "socks5h://$PROXY_ADDR")
  fi

  if [[ -n "$INTERFACE_NAME" ]]; then
    curl_args+=(--interface "$INTERFACE_NAME")
  fi

  if [[ "$effective_url_flag" == true ]]; then
    curl_args+=(-w '\n%{http_code}\n%{time_total}\n%{url_effective}\n%{redirect_url}')
  else
    curl_args+=(-w '\n%{http_code}\n%{time_total}')
  fi

  curl_args+=("$url")

  response_with_meta=$(curl "${curl_args[@]}")
  curl_exit=$?
  if [[ $curl_exit -ne 0 || -z "$response_with_meta" ]]; then
    error_type="curl_error"
    if [[ -n "$CURL_META_FILE" ]]; then
      printf "http_code=;latency_ms=;error_type=%s%s\n" "$error_type" "$meta_effective" >"$CURL_META_FILE"
    fi
    log "$LOG_WARN" "curl request failed for $url"
    echo ""
    return
  fi

  if [[ "$effective_url_flag" == true ]]; then
    redirect_url=$(printf '%s\n' "$response_with_meta" | tail -n 1)
    effective_url=$(printf '%s\n' "$response_with_meta" | tail -n 2 | head -n 1)
    latency_seconds=$(printf '%s\n' "$response_with_meta" | tail -n 3 | head -n 1)
    http_code=$(printf '%s\n' "$response_with_meta" | tail -n 4 | head -n 1)
    response=$(printf '%s\n' "$response_with_meta" | sed -e '$d' -e '$d' -e '$d' -e '$d')
    meta_effective=";effective_url=$effective_url;redirect_url=$redirect_url"
  else
    latency_seconds=$(printf '%s\n' "$response_with_meta" | tail -n 1)
    http_code=$(printf '%s\n' "$response_with_meta" | tail -n 2 | head -n 1)
    response=$(printf '%s\n' "$response_with_meta" | sed '$d' | sed '$d')
  fi

  if [[ "$latency_seconds" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    latency_ms=$(awk -v t="$latency_seconds" 'BEGIN { printf "%d", t * 1000 }')
  else
    latency_ms=""
  fi

  if [[ ! "$http_code" =~ ^[0-9]{3}$ ]]; then
    error_type="invalid_http_code"
    if [[ -n "$CURL_META_FILE" ]]; then
      printf "http_code=;latency_ms=%s;error_type=%s%s\n" "$latency_ms" "$error_type" "$meta_effective" >"$CURL_META_FILE"
    fi
    log "$LOG_WARN" "Unexpected HTTP code for $url"
    echo "$response"
    return
  fi

  if [[ "$http_code" =~ ^[45][0-9]{2}$ ]]; then
    error_type="http_${http_code}"
    if [[ -n "$CURL_META_FILE" ]]; then
      printf "http_code=%s;latency_ms=%s;error_type=%s%s\n" "$http_code" "$latency_ms" "$error_type" "$meta_effective" >"$CURL_META_FILE"
    fi
    status_from_http_code "$http_code"
    return 0
  fi

  if [[ -n "$CURL_META_FILE" ]]; then
    printf "http_code=%s;latency_ms=%s;error_type=none%s\n" "$http_code" "$latency_ms" "$meta_effective" >"$CURL_META_FILE"
  fi

  echo "$response"
}

service_build_request() {
  local service="$1" ip="$2" ip_version="$3"
  local cfg="${PRIMARY_SERVICES[$service]}"
  local display_name domain url_template url headers_str response_format

  IFS='|' read -r display_name domain url_template response_format <<<"$cfg"

  if [[ -z "$display_name" ]]; then
    display_name="$service"
  fi

  # ip-api.com free tier only supports HTTP, not HTTPS
  if [[ "$service" == "IPAPI_COM" ]]; then
    url="http://$domain${url_template//\{ip\}/$ip}"
  else
    url="https://$domain${url_template//\{ip\}/$ip}"
  fi

  if [[ -n "${SERVICE_HEADERS[$service]}" ]]; then
    headers_str="${SERVICE_HEADERS[$service]}"
  fi

  printf "%s\n%s\n%s\n%s" "$display_name" "$url" "${response_format:-json}" "$headers_str"
}

probe_service() {
  local service="$1"
  local ip_version="$2"
  local ip="$3"
  local built display_name url response_format headers_line request_params response

  mapfile -t built < <(service_build_request "$service" "$ip" "$ip_version")
  display_name="${built[0]}"
  url="${built[1]}"
  response_format="${built[2]}"
  headers_line="${built[3]}"

  if [[ -n "$headers_line" ]]; then
    IFS='||' read -ra hs <<<"$headers_line"
    for h in "${hs[@]}"; do
      if [[ -n "$h" ]]; then
        request_params+=(--header "$h")
      fi
    done
  fi

  if [[ "$ip_version" == "6" ]] && is_ipv6_over_ipv4_service "$service"; then
    ip_version="4"
  fi

  response=$(curl_wrapper GET "$url" "${request_params[@]}" --ip-version "$ip_version")

  process_response "$service" "$response" "$display_name" "$response_format"
}

process_response() {
  local service="$1"
  local response="$2"
  local display_name="$3"
  local response_format="${4:-json}"
  local jq_filter

  if is_status_string "$response"; then
    echo "$response"
    return
  fi

  if [[ -z "$response" || "$response" == *"<html"* ]]; then
    echo "$STATUS_NA"
    return
  fi

  if [[ "$response_format" == "plain" ]]; then
    echo "$response" | tr -d '\r\n '
    return
  fi

  if ! is_valid_json "$response"; then
    log "$LOG_ERROR" "Invalid JSON response from $display_name: $response"
    return 1
  fi

  case "$service" in
  MAXMIND)
    jq_filter='.country.iso_code'
    ;;
  RIPE)
    jq_filter='.country'
    ;;
  IP2LOCATION_IO)
    jq_filter='.country_code'
    ;;
  IPINFO_IO)
    jq_filter='.data.country'
    ;;
  IPREGISTRY)
    jq_filter='.location.country.code'
    ;;
  IPAPI_CO)
    jq_filter='.country'
    ;;
  CLOUDFLARE)
    jq_filter='.country'
    ;;
  COUNTRY_IS)
    jq_filter='.country'
    ;;
  GEOJS_IO)
    jq_filter='.[0].country'
    ;;
  GEOAPIFY_COM)
    jq_filter='.country.iso_code'
    ;;
  IPAPI_IS)
    jq_filter='.location.country_code'
    ;;
  IPBASE_COM)
    jq_filter='.data.location.country.alpha2'
    ;;
  IPQUERY_IO)
    jq_filter='.location.country_code'
    ;;
  IPWHOIS_IO)
    jq_filter='.country_code'
    ;;
  IPWHO_IS)
    jq_filter='.country_code'
    ;;
  IPAPI_COM)
    jq_filter='.countryCode'
    ;;
  DETECTOR404)
    # Detector404 returns the country code in lowercase ("us"); every
    # other provider reports uppercase - normalize to match.
    local detector404_country
    detector404_country=$(process_json "$response" '.data.country.ccode')
    echo "${detector404_country^^}"
    return
    ;;
  *)
    echo "$response"
    ;;
  esac

  process_json "$response" "$jq_filter"
}

read_curl_metric_field() {
  local file="$1"
  local key="$2"

  if [[ ! -f "$file" ]]; then
    echo ""
    return
  fi

  sed -n "s/.*${key}=\\([^;]*\\).*/\\1/p" "$file" | head -n1
}

build_service_metric() {
  local metric_file="$1"
  local transport_version="$2"
  local http_code latency_ms error_type

  http_code=$(read_curl_metric_field "$metric_file" "http_code")
  latency_ms=$(read_curl_metric_field "$metric_file" "latency_ms")
  error_type=$(read_curl_metric_field "$metric_file" "error_type")

  if [[ -z "$error_type" ]]; then
    error_type="none"
  fi

  printf "http_code=%s;latency_ms=%s;transport_ip_version=%s;error_type=%s" \
    "$http_code" "$latency_ms" "$transport_version" "$error_type"
}

process_with_custom_handler() {
  local service="$1"
  local display_name="$2"
  local handler_func="${PRIMARY_SERVICES_CUSTOM_HANDLERS[$service]}"
  local ipv4_result=""
  local ipv6_result=""
  local ipv4_metric=""
  local ipv6_metric=""
  local metric_file

  if [[ -n "$PROXY_ADDR" ]]; then
    log "$LOG_INFO" "Checking $display_name through proxy (custom handler)"
    metric_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_metric_XXXXXX")
    CURL_META_FILE="$metric_file"
    ipv4_result=$("$handler_func" proxy proxy)
    ipv6_result="$ipv4_result"
    ipv4_metric=$(build_service_metric "$metric_file" proxy)
    ipv6_metric="$ipv4_metric"
    rm -f "$metric_file"
    CURL_META_FILE=""
    add_result "primary" "$display_name" "$ipv4_result" "$ipv6_result" "$ipv4_metric" "$ipv6_metric"
    return
  fi

  if can_use_ipv4; then
    log "$LOG_INFO" "Checking $display_name via IPv4 (custom handler)"
    metric_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_metric_XXXXXX")
    CURL_META_FILE="$metric_file"
    ipv4_result=$("$handler_func" 4 4)
    ipv4_metric=$(build_service_metric "$metric_file" 4)
    rm -f "$metric_file"
    CURL_META_FILE=""
  fi

  if can_use_ipv6; then
    local transport=6
    local log_msg="Checking $display_name via IPv6 (custom handler)"

    if is_ipv6_over_ipv4_service "$service"; then
      transport=4
      log_msg="Checking $display_name (IPv6 address, IPv4 transport) (custom handler)"
    fi

    log "$LOG_INFO" "$log_msg"
    metric_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_metric_XXXXXX")
    CURL_META_FILE="$metric_file"
    ipv6_result=$("$handler_func" "$transport" 6)
    ipv6_metric=$(build_service_metric "$metric_file" "$transport")
    rm -f "$metric_file"
    CURL_META_FILE=""
  fi

  add_result "primary" "$display_name" "$ipv4_result" "$ipv6_result" "$ipv4_metric" "$ipv6_metric"
}

process_with_probe() {
  local service="$1"
  local display_name="$2"
  local ipv4_result=""
  local ipv6_result=""
  local ipv4_metric=""
  local ipv6_metric=""
  local metric_file
  local transport

  if [[ -n "$PROXY_ADDR" ]]; then
    log "$LOG_INFO" "Checking $display_name through proxy"
    metric_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_metric_XXXXXX")
    CURL_META_FILE="$metric_file"
    ipv4_result=$(probe_service "$service" proxy "$(preferred_ip)")
    ipv6_result="$ipv4_result"
    ipv4_metric=$(build_service_metric "$metric_file" proxy)
    ipv6_metric="$ipv4_metric"
    rm -f "$metric_file"
    CURL_META_FILE=""
    add_result "primary" "$display_name" "$ipv4_result" "$ipv6_result" "$ipv4_metric" "$ipv6_metric"
    return
  fi

  if can_use_ipv4; then
    log "$LOG_INFO" "Checking $display_name via IPv4"
    metric_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_metric_XXXXXX")
    CURL_META_FILE="$metric_file"
    ipv4_result=$(probe_service "$service" 4 "$EXTERNAL_IPV4")
    ipv4_metric=$(build_service_metric "$metric_file" 4)
    rm -f "$metric_file"
    CURL_META_FILE=""
  fi

  if can_use_ipv6; then
    transport=6
    local log_msg="Checking $display_name via IPv6"

    if is_ipv6_over_ipv4_service "$service"; then
      transport=4
      log_msg="Checking $display_name (IPv6 address, IPv4 transport)"
    fi

    log "$LOG_INFO" "$log_msg"
    metric_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_metric_XXXXXX")
    CURL_META_FILE="$metric_file"
    ipv6_result=$(probe_service "$service" 6 "$EXTERNAL_IPV6")
    ipv6_metric=$(build_service_metric "$metric_file" "$transport")
    rm -f "$metric_file"
    CURL_META_FILE=""
  fi

  add_result "primary" "$display_name" "$ipv4_result" "$ipv6_result" "$ipv4_metric" "$ipv6_metric"
}

process_service() {
  local service="$1"
  local custom="${2:-false}"
  local service_config="${PRIMARY_SERVICES[$service]}"
  local display_name domain url_template response_format handler_func

  IFS='|' read -r display_name domain url_template response_format <<<"$service_config"
  display_name="${display_name:-$service}"

  if [[ "$custom" == true ]]; then
    process_custom_service "$service"
    return
  fi

  spinner_update "$display_name"

  if [[ -n "${PRIMARY_SERVICES_CUSTOM_HANDLERS[$service]}" ]]; then
    process_with_custom_handler "$service" "$display_name"
    return
  fi

  process_with_probe "$service" "$display_name"
}

process_custom_service() {
  local service="$1"
  local ipv4_result=""
  local ipv6_result=""
  local ipv4_metric=""
  local ipv6_metric=""
  local display_name handler_func group
  local metric_file

  if [[ -n "${DEVINFRA_SERVICES[$service]}" ]]; then
    display_name="${DEVINFRA_SERVICES[$service]}"
    handler_func="${CUSTOM_SERVICES_HANDLERS[$service]}"
    group="devinfra"
  elif [[ -n "${DNS_DIAG_SERVICES[$service]}" ]]; then
    display_name="${DNS_DIAG_SERVICES[$service]}"
    handler_func="${CUSTOM_SERVICES_HANDLERS[$service]}"
    group="dns"
  elif [[ -n "${CDN_SERVICES[$service]}" ]]; then
    display_name="${CDN_SERVICES[$service]}"
    handler_func="${CUSTOM_SERVICES_HANDLERS[$service]}"
    group="cdn"
  elif [[ -n "${CUSTOM_SERVICES[$service]}" ]]; then
    display_name="${CUSTOM_SERVICES[$service]}"
    handler_func="${CUSTOM_SERVICES_HANDLERS[$service]}"
    group="custom"
  else
    display_name="$service"
    handler_func="${CUSTOM_SERVICES_HANDLERS[$service]}"
    group="custom"
  fi

  spinner_update "$display_name"

  if [[ -z "$handler_func" ]]; then
    log "$LOG_WARN" "Unknown service handler: $service"
    return
  fi

  if [[ -n "$PROXY_ADDR" ]]; then
    log "$LOG_INFO" "Checking $display_name through proxy"
    metric_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_metric_XXXXXX")
    CURL_META_FILE="$metric_file"
    ipv4_result=$("$handler_func" proxy)
    ipv6_result="$ipv4_result"
    ipv4_metric=$(build_service_metric "$metric_file" proxy)
    ipv6_metric="$ipv4_metric"
    rm -f "$metric_file"
    CURL_META_FILE=""
    add_result "$group" "$display_name" "$ipv4_result" "$ipv6_result" "$ipv4_metric" "$ipv6_metric"
    return
  fi

  if can_use_ipv4; then
    log "$LOG_INFO" "Checking $display_name via IPv4"
    metric_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_metric_XXXXXX")
    CURL_META_FILE="$metric_file"
    ipv4_result=$("$handler_func" 4)
    ipv4_metric=$(build_service_metric "$metric_file" 4)
    rm -f "$metric_file"
    CURL_META_FILE=""
  fi

  if can_use_ipv6; then
    log "$LOG_INFO" "Checking $display_name via IPv6"
    metric_file=$(mktemp "${TMPDIR:-/tmp}/ipregion_metric_XXXXXX")
    CURL_META_FILE="$metric_file"
    ipv6_result=$("$handler_func" 6)
    ipv6_metric=$(build_service_metric "$metric_file" 6)
    rm -f "$metric_file"
    CURL_META_FILE=""
  fi

  add_result "$group" "$display_name" "$ipv4_result" "$ipv6_result" "$ipv4_metric" "$ipv6_metric"
}

run_service_group() {
  local group="$1"
  local services_string="${SERVICE_GROUPS[$group]}"
  local services_array service_name handler_func display_name result

  [[ -n "${CHECKS_GROUP_FILE:-}" ]] && printf '%s' "$group" >"$CHECKS_GROUP_FILE"

  read -ra services_array <<<"$services_string"

  log "$LOG_INFO" "Running $group group services"

  for service_name in "${services_array[@]}"; do
    if should_skip_service "$service_name"; then
      log "$LOG_INFO" "Skipping service: $service_name"
      continue
    fi

    # Route per key, not per group: the default profile mixes registries.
    if [[ -n "${CUSTOM_SERVICES[$service_name]:-}${CDN_SERVICES[$service_name]:-}${DEVINFRA_SERVICES[$service_name]:-}${DNS_DIAG_SERVICES[$service_name]:-}" ]]; then
      process_service "$service_name" true
    else
      process_service "$service_name"
    fi
  done
}

run_service_group_parallel() {
  local group="$1"
  local services_string="${SERVICE_GROUPS[$group]}"
  local services_array service_name temp_dir result_file

  [[ -n "${CHECKS_GROUP_FILE:-}" ]] && printf '%s' "$group" >"$CHECKS_GROUP_FILE"

  read -ra services_array <<<"$services_string"

  temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/ipregion_parallel_XXXXXX")

  for service_name in "${services_array[@]}"; do
    if should_skip_service "$service_name"; then
      log "$LOG_INFO" "Skipping service: $service_name"
      continue
    fi

    result_file="$temp_dir/$service_name"
    (
      RESULT_FILE="$result_file"
      # Route per key, not per group: the default profile mixes registries.
      if [[ -n "${CUSTOM_SERVICES[$service_name]:-}${CDN_SERVICES[$service_name]:-}${DEVINFRA_SERVICES[$service_name]:-}${DNS_DIAG_SERVICES[$service_name]:-}" ]]; then
        process_service "$service_name" true
      else
        process_service "$service_name"
      fi
    ) &

    register_parallel_pid "$!"
    wait_for_parallel_slot
  done

  if [[ "$PROGRESS_LOG" == true && "$JSON_OUTPUT" != "true" ]]; then
    printf "%s %s\n" \
      "$(color INFO '[INFO]')" \
      "Waiting for remaining $group checks..." >&2
  fi

  local pid
  local -a remaining_group_pids=("${PARALLEL_PIDS[@]}")
  for pid in "${remaining_group_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  PARALLEL_PIDS=()

  for service_name in "${services_array[@]}"; do
    if should_skip_service "$service_name"; then
      continue
    fi

    result_file="$temp_dir/$service_name"
    if [[ -f "$result_file" ]]; then
      while IFS= read -r line; do
        [[ -n "$line" ]] && add_result_line "$line"
      done <"$result_file"
    fi
  done

  rm -rf "$temp_dir"
}

run_all_services() {
  local service_name

  for func in $(declare -F | awk '{print $3}' | grep_wrapper '^lookup_'); do
    service_name=${func#lookup_}
    service_name_uppercase=${service_name^^}

    if should_skip_service "$service_name_uppercase"; then
      log "$LOG_INFO" "Skipping service: $service_name_uppercase"
      continue
    fi

    if [[ -n "${CUSTOM_SERVICES[$service_name_uppercase]}" ]]; then
      process_service "$service_name_uppercase" true
      continue
    fi

    "$func"
  done
}

finalize_json() {
  local t_primary t_custom t_cdn t_devinfra
  local IFS=$'\n'

  if ((${#ARR_PRIMARY[@]} > 0)); then
    t_primary=$(printf '%s\n' "${ARR_PRIMARY[@]//|||/$'\t'}")
  fi

  if ((${#ARR_CUSTOM[@]} > 0)); then
    t_custom=$(printf '%s\n' "${ARR_CUSTOM[@]//|||/$'\t'}")
  fi

  if ((${#ARR_CDN[@]} > 0)); then
    t_cdn=$(printf '%s\n' "${ARR_CDN[@]//|||/$'\t'}")
  fi

  if ((${#ARR_DEVINFRA[@]} > 0)); then
    t_devinfra=$(printf '%s\n' "${ARR_DEVINFRA[@]//|||/$'\t'}")
  fi

  if ((${#ARR_DNS[@]} > 0)); then
    t_dns=$(printf '%s\n' "${ARR_DNS[@]//|||/$'\t'}")
  fi

  RESULT_JSON=$(
    jq -n \
      --rawfile p <(printf "%s" "$t_primary") \
      --rawfile c <(printf "%s" "$t_custom") \
      --rawfile d <(printf "%s" "$t_cdn") \
      --rawfile e <(printf "%s" "$t_devinfra") \
      --rawfile n <(printf "%s" "$t_dns") \
      --arg ipv4 "$EXTERNAL_IPV4" \
      --arg ipv6 "$EXTERNAL_IPV6" \
      --arg ipv4_source "$EXTERNAL_IPV4_SOURCE" \
      --arg ipv6_source "$EXTERNAL_IPV6_SOURCE" \
      --arg ipv4_cache_hit "$EXTERNAL_IPV4_CACHE_HIT" \
      --arg ipv6_cache_hit "$EXTERNAL_IPV6_CACHE_HIT" \
      --arg ipv4_ts "$EXTERNAL_IPV4_TIMESTAMP" \
      --arg ipv6_ts "$EXTERNAL_IPV6_TIMESTAMP" \
      --arg registered_country_ipv4 "$REGISTERED_COUNTRY_IPV4" \
      --arg registered_country_ipv6 "$REGISTERED_COUNTRY_IPV6" \
      --arg asn_number "$ASN_NUMBER" \
      --arg asn_name "$ASN_NAME" \
      --arg version "1" '
        def parse_metric($raw):
          if ($raw | length) == 0 then null
          else
            ($raw | split(";") | map(select(length > 0) | split("="))) as $pairs
            | ($pairs | map({key: .[0], value: (.[1] // "")}) | from_entries) as $m
            | {
                http_code: ($m.http_code | if . == null or . == "" then null else (tonumber? // null) end),
                latency_ms: ($m.latency_ms | if . == null or . == "" then null else (tonumber? // null) end),
                transport_ip_version: ($m.transport_ip_version | if . == null or . == "" then null else (tonumber? // null) end),
                error_type: ($m.error_type | if . == null or . == "" or . == "none" then null else . end)
              }
          end;

        def lines_to_array($raw):
          if ($raw | length) == 0 then [] else
          ($raw | split("\n"))
          | map(select(length > 0))
          | map(
              (split("\t")) as $f
              | {
                  service: $f[0],
                  ipv4: ( ($f[1] // "") | if length>0 then . else null end ),
                  ipv6: ( ($f[2] // "") | if length>0 then . else null end ),
                  metrics: {
                    ipv4: parse_metric($f[3] // ""),
                    ipv6: parse_metric($f[4] // "")
                  }
                }
            )
          end;

        def country_consensus($rows; $field):
          ($rows
           | map(if $field == "ipv4" then .ipv4 else .ipv6 end)
           | map(select(. != null and (. | test("^[A-Z]{2}$"))))
          ) as $codes
          | ($codes | length) as $total
          | if $total == 0 then null
            else
              ($codes | group_by(.) | map({country: .[0], count: length}) | sort_by(-.count, .country) | .[0]) as $top
              | {
                  country: $top.country,
                  count: $top.count,
                  total: $total,
                  confidence: (($top.count / $total) * 100 | floor)
                }
            end;

        (lines_to_array($p)) as $primary
        | (lines_to_array($c)) as $custom
        | (lines_to_array($d)) as $cdn
        | (lines_to_array($e)) as $devinfra
        | (lines_to_array($n)) as $dns
        | {
          version: ($version|tonumber),
          ip: {
            ipv4: {
              address: ($ipv4 | select(length > 0) // null),
              source: ($ipv4_source | select(length > 0) // null),
              cache_hit: ($ipv4_cache_hit == "true"),
              timestamp: ($ipv4_ts | if length == 0 or . == "null" then null else (tonumber? // null) end),
              registered_country: ($registered_country_ipv4 | select(length > 0 and . != "null") // null)
            },
            ipv6: {
              address: ($ipv6 | select(length > 0) // null),
              source: ($ipv6_source | select(length > 0) // null),
              cache_hit: ($ipv6_cache_hit == "true"),
              timestamp: ($ipv6_ts | if length == 0 or . == "null" then null else (tonumber? // null) end),
              registered_country: ($registered_country_ipv6 | select(length > 0 and . != "null") // null)
            }
          },
          asn: {
            number: ($asn_number | if length == 0 or . == "null" then null else (tonumber? // null) end),
            name: ($asn_name | if length == 0 or . == "null" then null else . end)
          },
          consensus: {
            ipv4: country_consensus($primary; "ipv4"),
            ipv6: country_consensus($primary; "ipv6")
          },
          results: {
            primary: $primary,
            custom:  $custom,
            cdn:     $cdn,
            devinfra: $devinfra,
            dns:     $dns
          }
        }
      '
  )
}

add_result() {
  local group="$1"
  local service="$2"
  local ipv4="$3"
  local ipv6="$4"
  local ipv4_metric="$5"
  local ipv6_metric="$6"

  ipv4=${ipv4//$'\n'/}
  ipv4=${ipv4//$'\t'/ }
  ipv6=${ipv6//$'\n'/}
  ipv6=${ipv6//$'\t'/ }
  ipv4_metric=${ipv4_metric//$'\n'/}
  ipv4_metric=${ipv4_metric//$'\t'/ }
  ipv6_metric=${ipv6_metric//$'\n'/}
  ipv6_metric=${ipv6_metric//$'\t'/ }

  if [[ "$PROGRESS_LOG" == true && "$JSON_OUTPUT" != "true" ]]; then
    printf "%s %s\n" \
      "$(color INFO '[INFO]')" \
      "Done: $service" >&2
  fi

  # Live feedback: one line per completed check below the spinner, and a
  # done-marker for the spinner counter (both on stderr; parallel workers
  # print here too, so results appear the moment each check finishes)
  if [[ "${spinner_running:-}" == true ]]; then
    local result_symbol result_color
    # Handler results arrive ANSI-colored when color() is active; strip
    # the escapes so the verdict case sees the bare value.
    local ipv4_plain
    ipv4_plain=$(printf '%s' "$ipv4" | sed "s/$(printf '\033')\\[[0-9;]*m//g")
    case "$ipv4_plain" in
    "Yes")
      result_symbol="✔"
      result_color="SERVICE"
      ;;
    "No" | "Denied" | "Server error")
      result_symbol="✘"
      result_color="HEART"
      ;;
    "" | "N/A")
      result_symbol="●"
      result_color="NULL"
      ;;
    "Rate-limit" | "$STATUS_REGION_BLOCKED")
      result_symbol="▲"
      result_color="WARN"
      ;;
    *)
      # Informational values (e.g. CDN locations) - neither good nor bad
      result_symbol="●"
      result_color="NULL"
      ;;
    esac
    # Wipe the spinner frame line first, then print the result in its
    # place - otherwise the frame (which does not end in a newline) and
    # the result line concatenate and the service name shows twice
    local done_marker_color
    case "$result_color" in
    SERVICE) done_marker_color="$COLOR_SERVICE" ;;
    HEART) done_marker_color="$COLOR_HEART" ;;
    NULL) done_marker_color="$COLOR_NULL" ;;
    WARN) done_marker_color="$COLOR_WARN" ;;
    *) done_marker_color="$COLOR_SERVICE" ;;
    esac
    printf "\r\033[K%s %s: %s\n" \
      "$(color "$result_color" "$result_symbol")" \
      "$(bold "$(color SERVICE "$service")")" \
      "$(
        local -a verdict_parts=()
        [[ -n "$ipv4" ]] && verdict_parts+=("$ipv4")
        [[ -n "$ipv6" ]] && verdict_parts+=("$ipv6")
        IFS='/'
        printf '%s' "${verdict_parts[*]:-}"
      )" >&2
    [[ -n "${CHECKS_DONE_FILE:-}" ]] && printf '%s\n' "$done_marker_color" >>"$CHECKS_DONE_FILE"
  fi

  if [[ -n "${RESULT_FILE:-}" ]]; then
    printf "%s|||%s|||%s|||%s|||%s|||%s\n" "$group" "$service" "$ipv4" "$ipv6" "$ipv4_metric" "$ipv6_metric" >>"$RESULT_FILE"
    return
  fi

  case "$group" in
  primary) ARR_PRIMARY+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  custom) ARR_CUSTOM+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  cdn) ARR_CDN+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  dns) ARR_DNS+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  devinfra) ARR_DEVINFRA+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  esac
}

add_result_line() {
  local line="$1"
  local group rest service ipv4 ipv6 ipv4_metric ipv6_metric

  group="${line%%|||*}"
  rest="${line#*|||}"
  service="${rest%%|||*}"
  rest="${rest#*|||}"
  ipv4="${rest%%|||*}"
  rest="${rest#*|||}"
  ipv6="${rest%%|||*}"
  rest="${rest#*|||}"
  ipv4_metric="${rest%%|||*}"
  ipv6_metric="${rest#*|||}"

  case "$group" in
  primary) ARR_PRIMARY+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  custom) ARR_CUSTOM+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  cdn) ARR_CDN+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  dns) ARR_DNS+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  devinfra) ARR_DEVINFRA+=("$service|||$ipv4|||$ipv6|||$ipv4_metric|||$ipv6_metric") ;;
  esac
}

# ---------------------------------------------------------------------------
# Card-based report renderer (presentation ported from vernette/ipregion)
# ---------------------------------------------------------------------------

strip_ansi() {
  local text="$1"
  local re=$'\033\\[[0-9;]*m'

  while [[ "$text" =~ $re ]]; do
    text="${text//${BASH_REMATCH[0]}/}"
  done

  printf '%s' "$text"
}

# Display width in terminal cells: ANSI sequences take none, listed emoji
# take two cells, everything else one
visible_length() {
  local plain
  plain="$(strip_ansi "$1")"
  local narrow="${plain//$WIDE_EMOJI_PATTERN/}"

  printf '%d' $((2 * ${#plain} - ${#narrow}))
}

repeat_char() {
  local char="$1"
  local count="$2"
  local line

  if ((count <= 0)); then
    return
  fi

  printf -v line '%*s' "$count" ''
  printf '%s' "${line// /$char}"
}

pad() {
  local text="$1"
  local width="$2"
  local fill

  fill=$((width - $(visible_length "$text")))
  if ((fill < 0)); then
    fill=0
  fi

  printf '%s%*s' "$text" "$fill" ''
}

max_visible_length() {
  local max=0 item len
  for item in "$@"; do
    len=$(visible_length "$item")
    if ((len > max)); then
      max=$len
    fi
  done
  printf '%d' "$max"
}

format_flag() {
  local country="$1"
  local first second

  first=$((0x1F1E6 + $(printf '%d' "'${country:0:1}") - 65))
  second=$((0x1F1E6 + $(printf '%d' "'${country:1:1}") - 65))

  printf '%b' "\\U$(printf '%08X' "$first")\\U$(printf '%08X' "$second")"
}

label_country() {
  local country="$1"

  if [[ "$SHOW_EMOJI" != true || ! "$country" =~ ^[A-Z]{2}$ ]]; then
    printf '%s' "$country"
    return
  fi

  printf '%s %s' "$(format_flag "$country")" "$country"
}

label_group() {
  local title="$1"

  if [[ "$SHOW_EMOJI" != true || -z "$title" ]]; then
    printf '%s' "$title"
    return
  fi

  printf '%s %s' "${GROUP_EMOJI[$title]:-}" "$title"
}

# Cell classification: which family a result value belongs to
classify_cell_value() {
  local value="$1"

  case "$value" in
  "$STATUS_YES") echo "yes" ;;
  "$STATUS_NO") echo "no" ;;
  "$STATUS_NA" | "$STATUS_RATE_LIMIT" | "$STATUS_SERVER_ERROR") echo "unknown" ;;
  "$STATUS_DENIED" | "IP block" | "DNS block") echo "ipblock" ;;
  "$STATUS_REGION_BLOCKED") echo "region" ;;
  [A-Z][A-Z]) echo "country" ;;
  *) echo "info" ;;
  esac
}

format_cell() {
  local value="$1"
  local width="$2"
  local class text

  if [[ -z "$value" ]]; then
    printf '%s' "$(pad "$(color NULL "-")" "$width")"
    return
  fi

  class="$(classify_cell_value "$value")"
  case "$class" in
  yes) text="$(color SERVICE "$SYMBOL_YES")" ;;
  no) text="$(color ERROR "$SYMBOL_NO")" ;;
  ipblock) text="$(color ERROR "$SYMBOL_IPBLOCK")" ;;
  region) text="$(color WARN "$SYMBOL_NO")" ;;
  unknown) text="$(color NULL "$SYMBOL_UNKNOWN")" ;;
  country)
    if is_verdict_country "$value"; then
      text="$(bold "$(label_country "$value")")"
    else
      text="$(color WARN "$(label_country "$value")")"
    fi
    ;;
  *) text="$(color NULL "$value")" ;;
  esac

  printf '%s' "$(pad "$text" "$width")"
}

print_card_top() {
  local title="$1"
  local width="$2"
  local label

  label=" $(label_group "$title") "
  label="$(color HEADER "$label")"
  printf '%s%s%s%s%s\n' \
    "$(color NULL "$CARD_TOP_LEFT")" \
    "$(repeat_char "$CARD_HORIZONTAL" "$CARD_TITLE_OFFSET")" \
    "$label" \
    "$(repeat_char "$CARD_HORIZONTAL" $((width - CARD_SIDES_WIDTH - CARD_TITLE_OFFSET - $(visible_length "$label"))))" \
    "$(color NULL "$CARD_TOP_RIGHT")"
}

print_card_line() {
  local line="$1"
  local width="$2"
  local fill

  fill=$((width - CARD_SIDES_WIDTH - CARD_CONTENT_INDENT - CARD_TRAILING_GAP - $(visible_length "$line")))
  if ((fill < 0)); then
    fill=0
  fi

  printf '%s%*s%s%*s%s\n' \
    "$(color NULL "$CARD_SIDE")" \
    "$CARD_CONTENT_INDENT" '' \
    "$line" \
    "$((fill + CARD_TRAILING_GAP))" '' \
    "$(color NULL "$CARD_SIDE")"
}

print_card_bottom() {
  local width="$1"

  printf '%s%s%s\n' \
    "$(color NULL "$CARD_BOTTOM_LEFT")" \
    "$(repeat_char "$CARD_HORIZONTAL" $((width - CARD_SIDES_WIDTH)))" \
    "$(color NULL "$CARD_BOTTOM_RIGHT")"
}

# Render one card: title, width, height on arguments, content lines on stdin.
# Shorter content is padded with empty lines up to height.
print_titled_card() {
  local title="$1"
  local width="$2"
  local height="$3"
  local -a content_lines=()
  local index

  mapfile -t content_lines
  while ((${#content_lines[@]} > 0)) && [[ -z "${content_lines[-1]}" ]]; do
    unset 'content_lines[-1]'
  done
  if ((${#content_lines[@]} > height)); then
    height="${#content_lines[@]}"
  fi

  print_card_top "$title" "$width"
  for ((index = 0; index < height; index++)); do
    print_card_line "${content_lines[index]:-}" "$width"
  done
  print_card_bottom "$width"
}

# Render two cards side by side with equalized heights
print_titled_card_pair() {
  local left_title="$1"
  local left_width="$2"
  local right_title="$3"
  local right_width="$4"
  local left_text="$5"
  local right_text="$6"
  local -a left_card=() right_card=()
  local height index

  mapfile -t left_card <<<"$left_text"
  mapfile -t right_card <<<"$right_text"
  height="${#left_card[@]}"
  if ((${#right_card[@]} > height)); then
    height="${#right_card[@]}"
  fi

  mapfile -t left_card < <(printf '%s\n' "${left_card[@]}" | print_titled_card "$left_title" "$left_width" "$height")
  mapfile -t right_card < <(printf '%s\n' "${right_card[@]}" | print_titled_card "$right_title" "$right_width" "$height")

  for ((index = 0; index < ${#left_card[@]}; index++)); do
    printf '%s%*s%s\n' "${left_card[index]}" "$CARD_GAP" '' "${right_card[index]:-}"
  done
}

declare -A GROUP_TITLES=(
  [primary]="GeoIP services"
  [custom]="Popular services"
  [cdn]="CDN"
  [devinfra]="Dev Infra"
  [dns]="DNS diagnostics"
)

group_has_results() {
  local group="$1"

  jq -e --arg group "$group" '(.results[$group] // []) | length > 0' <<<"$RESULT_JSON" >/dev/null
}

# Groups to render for the current selection, in card order
selected_display_groups() {
  local -a wanted=()
  local group

  case "$GROUPS_TO_SHOW" in
  default) wanted=(primary custom dns) ;;
  all) wanted=(primary custom cdn devinfra dns) ;;
  *) wanted=("$GROUPS_TO_SHOW") ;;
  esac

  for group in "${wanted[@]}"; do
    if group_has_results "$group"; then
      printf '%s\n' "$group"
    fi
  done
}

# Card content lines for one group: "name  IPv4-cell  IPv6-cell".
# Prints the card width on the first line (marked "width:"), then the lines.
group_card_text() {
  local group="$1"
  local show_ipv4=false show_ipv6=false
  local -a rows=() names=() vals4=() vals6=() lines=()
  local row service v4 v6
  local name_w=14 v4_w=4 v6_w=4 item len
  local index line header

  can_use_ipv4 && show_ipv4=true
  can_use_ipv6 && show_ipv6=true

  mapfile -t rows < <(jq -r --arg group "$group" '
    (.results[$group] // [])[]
    | [(.service // ""), ((.ipv4 // "") | if . == "null" then "" else . end),
       ((.ipv6 // "") | if . == "null" then "" else . end)]
    | @tsv
  ' <<<"$RESULT_JSON")

  for row in "${rows[@]}"; do
    IFS=$'\t' read -r service v4 v6 <<<"$row"
    names+=("$service")
    if [[ "$show_ipv4" == true ]]; then
      vals4+=("${v4:-}")
    fi
    if [[ "$show_ipv6" == true ]]; then
      vals6+=("${v6:-}")
    fi
  done

  name_w="$(max_visible_length "${names[@]}")"
  ((name_w < 14)) && name_w=14
  ((name_w > 26)) && name_w=26
  v4_w="$(max_visible_length "${vals4[@]}")"
  ((v4_w < 4)) && v4_w=4
  ((v4_w > 12)) && v4_w=12
  v6_w="$(max_visible_length "${vals6[@]}")"
  ((v6_w < 4)) && v6_w=4
  ((v6_w > 12)) && v6_w=12

  header="$(color TABLE_HEADER "$(pad "Service" "$name_w")")"
  local v4_col=0 v6_col=0
  [[ "$show_ipv4" == true ]] && v4_col=1
  [[ "$show_ipv6" == true ]] && v6_col=1
  if [[ "$show_ipv4" == true ]]; then
    header+="  $(color TABLE_HEADER "$(pad "IPv4" "$v4_w")")"
  fi
  if [[ "$show_ipv6" == true ]]; then
    header+="  $(color TABLE_HEADER "$(pad "IPv6" "$v6_w")")"
  fi
  lines+=("$header")

  for ((index = 0; index < ${#names[@]}; index++)); do
    line="$(color SERVICE "$(pad "${names[index]}" "$name_w")")"
    if [[ "$show_ipv4" == true ]]; then
      line+="  $(format_cell "${vals4[index]}" "$v4_w")"
    fi
    if [[ "$show_ipv6" == true ]]; then
      line+="  $(format_cell "${vals6[index]}" "$v6_w")"
    fi
    lines+=("$line")
  done

  printf 'width:%d\n' "$((name_w + 2 + (v4_col ? v4_w + 2 : 0) + (v6_col ? v6_w + 2 : 0) + CARD_SIDES_WIDTH))"
  printf '%s\n' "${lines[@]}"
}

print_group_cards() {
  local -a groups=()
  local group left_group right_group
  local left_text right_text left_width right_width

  mapfile -t groups < <(selected_display_groups)
  if ((${#groups[@]} == 0)); then
    return
  fi

  local index=0
  while ((index < ${#groups[@]})); do
    left_group="${groups[index]}"
    if ((index + 1 < ${#groups[@]})); then
      right_group="${groups[index + 1]}"
      left_text="$(group_card_text "$left_group")"
      right_text="$(group_card_text "$right_group")"
      left_width="${left_text%%$'\n'*}"
      left_width="${left_width#width:}"
      right_width="${right_text%%$'\n'*}"
      right_width="${right_width#width:}"
      left_text="${left_text#*$'\n'}"
      right_text="${right_text#*$'\n'}"
      print_titled_card_pair \
        "${GROUP_TITLES[$left_group]}" "$left_width" \
        "${GROUP_TITLES[$right_group]}" "$right_width" \
        "$left_text" "$right_text"
      printf '\n'
      index=$((index + 2))
    else
      left_text="$(group_card_text "$left_group")"
      left_width="${left_text%%$'\n'*}"
      left_width="${left_width#width:}"
      left_text="${left_text#*$'\n'}"
      printf '%s\n' "$left_text" | print_titled_card \
        "${GROUP_TITLES[$left_group]}" "$left_width" 0
      printf '\n'
      index=$((index + 1))
    fi
  done
}

print_metrics_group() {
  local group="$1"
  local title="$2"
  local show_ipv4=false show_ipv6=false
  local -a rows=() names=() vals4=() vals6=() lines=()
  local row s m4 m6
  local name_w=14 m4_w=10 m6_w=10 index line

  if [[ "$SHOW_METRICS" != true ]]; then
    return
  fi

  can_use_ipv4 && show_ipv4=true
  can_use_ipv6 && show_ipv6=true

  mapfile -t rows < <(jq -r --arg group "$group" '
    def metric:
      if . == null then "N/A" else
        ((.http_code // "n/a")|tostring) + " / " +
        ((.latency_ms // "n/a")|tostring) + "ms / " +
        ((.error_type // "ok")|tostring)
      end;
    (.results // {}) as $r
    | ($r[$group] // [])
    | .[]
    | [.service, (.metrics.ipv4 | metric), (.metrics.ipv6 | metric)]
    | @tsv
  ' <<<"$RESULT_JSON")

  for row in "${rows[@]}"; do
    IFS=$'\t' read -r s m4 m6 <<<"$row"
    names+=("$s")
    if [[ "$show_ipv4" == true ]]; then
      vals4+=("$m4")
    fi
    if [[ "$show_ipv6" == true ]]; then
      vals6+=("$m6")
    fi
  done

  ((${#names[@]} > 0)) || return 0

  name_w="$(max_visible_length "${names[@]}")"
  ((name_w < 14)) && name_w=14
  if [[ "$show_ipv4" == true ]]; then
    m4_w="$(max_visible_length "${vals4[@]}")"
    ((m4_w < 10)) && m4_w=10
  fi
  if [[ "$show_ipv6" == true ]]; then
    m6_w="$(max_visible_length "${vals6[@]}")"
    ((m6_w < 10)) && m6_w=10
  fi

  printf "%s\n\n" "$(color HEADER "$title")"

  line="$(color TABLE_HEADER "$(pad "Service" "$name_w")")"
  if [[ "$show_ipv4" == true ]]; then
    line+="  $(color TABLE_HEADER "$(pad "IPv4 metric" "$m4_w")")"
  fi
  if [[ "$show_ipv6" == true ]]; then
    line+="  $(color TABLE_HEADER "$(pad "IPv6 metric" "$m6_w")")"
  fi
  printf "%s\n" "$line"

  for ((index = 0; index < ${#names[@]}; index++)); do
    line="$(color SERVICE "$(pad "${names[index]}" "$name_w")")"
    if [[ "$show_ipv4" == true ]]; then
      line+="  $(pad "${vals4[index]}" "$m4_w")"
    fi
    if [[ "$show_ipv6" == true ]]; then
      line+="  $(pad "${vals6[index]}" "$m6_w")"
    fi
    printf "%s\n" "$line"
  done

  printf "\n"
}

# ---------------------------------------------------------------------------
# Verdict, header block, attention card, legend
# ---------------------------------------------------------------------------

VERDICT_COUNTRY=""
VERDICT_TIED=()
CHECKS_TOTAL=0
CHECKS_NORMAL=0
FULL_REPORT_WIDTH=90
COUNTRY_NAMES_JSON=""
readonly CLDR_TERRITORIES_URL="https://cdn.jsdelivr.net/npm/cldr-localenames-full/main/en/territories.json"

# Pool per-protocol consensus into a single verdict: the country most
# GeoIP services agree on across IPv4 and IPv6
compute_report_verdict() {
  local -a leaders=()
  local row top_count=""

  VERDICT_COUNTRY=""
  VERDICT_TIED=()

  mapfile -t leaders < <(jq -r '
    [.consensus.ipv4, .consensus.ipv6]
    | map(select(. != null and .country != null))
    | if length == 0 then [] else
        group_by(.country)
        | map({country: .[0].country, count: (map(.count) | add)})
        | sort_by(-.count, .country)
      end
    | .[] | "\(.count)\t\(.country)"
  ' <<<"$RESULT_JSON")

  ((${#leaders[@]} > 0)) || return 0

  top_count="${leaders[0]%%$'\t'*}"
  for row in "${leaders[@]}"; do
    if [[ "${row%%$'\t'*}" == "$top_count" ]]; then
      VERDICT_TIED+=("${row#*$'\t'}")
    fi
  done

  if ((${#VERDICT_TIED[@]} == 1)); then
    VERDICT_COUNTRY="${VERDICT_TIED[0]}"
    VERDICT_TIED=()
  fi
}

is_verdict_country() {
  local country="$1"

  [[ "$country" == "$VERDICT_COUNTRY" ]] || is_in_list "$country" "${VERDICT_TIED[@]}"
}

# Full country name from CLDR, only fetched for interactive output; falls
# back to the code when piped or offline
country_display_name() {
  local code="$1"
  local name=""

  if [[ -z "$COUNTRY_NAMES_JSON" && "$USE_COLOR_STDOUT" == true && -n "$code" ]]; then
    COUNTRY_NAMES_JSON="$(curl_wrapper GET "$CLDR_TERRITORIES_URL" --ip-version 4 2>/dev/null || true)"
    if ! jq -e '.main.en.localeDisplayNames.territories' >/dev/null 2>&1 <<<"$COUNTRY_NAMES_JSON"; then
      COUNTRY_NAMES_JSON=""
    fi
  fi

  if [[ -n "$COUNTRY_NAMES_JSON" ]]; then
    name="$(jq -r --arg c "$code" '.main.en.localeDisplayNames.territories[$c] // empty' <<<"$COUNTRY_NAMES_JSON")"
  fi

  printf '%s' "${name:-$code}"
}

# Count every rendered cell and how many of them look normal (working,
# informational, or agreeing with the verdict)
count_report_checks() {
  local -a groups=()
  local summary

  CHECKS_TOTAL=0
  CHECKS_NORMAL=0

  mapfile -t groups < <(selected_display_groups)
  ((${#groups[@]} > 0)) || return 0

  summary="$(jq -r -n \
    --argjson groups "$(printf '%s\n' "${groups[@]}" | jq -R . | jq -s .)" \
    --argjson verdicts "$(printf '%s\n' "$VERDICT_COUNTRY" "${VERDICT_TIED[@]}" | jq -R 'select(length > 0)' | jq -s .)" \
    --arg v4 "$(if can_use_ipv4; then echo true; else echo false; fi)" \
    --arg v6 "$(if can_use_ipv6; then echo true; else echo false; fi)" \
    --rawfile body <(printf '%s' "$RESULT_JSON") '
    def cls($v):
      if $v == "Yes" then "yes"
      elif $v == "No" then "no"
      elif ($v | test("^[A-Z]{2}$")) then "country"
      elif ($v == "N/A" or $v == "Rate-limit" or $v == "Server error") then "unknown"
      elif ($v == "Denied" or $v == "IP block" or $v == "DNS block") then "ipblock"
      elif ($v == "Region blocked") then "region"
      else "info"
      end;
    ($body | fromjson) as $r
    | [$groups[] as $g
        | ($r.results[$g] // [])[] as $row
        | ((if ($v4 == "true") then $row.ipv4 else null end),
           (if ($v6 == "true") then $row.ipv6 else null end))
        | select(. != null and . != "null")
        | {value: ., class: cls(.)}
      ] as $cells
    | [$cells[] as $cell
        | select($cell.class == "yes"
          or $cell.class == "info"
          or ($cell.class == "country" and any($verdicts[]; . == $cell.value)))
      ] | length
    | "\(($cells | length))\t\(.)"
  ' 2>/dev/null || true)"

  [[ "$summary" == *$'\t'* ]] || return 0
  CHECKS_TOTAL="${summary%%$'\t'*}"
  CHECKS_NORMAL="${summary#*$'\t'}"
  [[ "$CHECKS_TOTAL" =~ ^[0-9]+$ && "$CHECKS_NORMAL" =~ ^[0-9]+$ ]] || {
    CHECKS_TOTAL=0
    CHECKS_NORMAL=0
  }
}

checks_health_color() {
  local percent

  ((CHECKS_TOTAL > 0)) || {
    printf '1;32'
    return
  }

  percent=$((CHECKS_NORMAL * 100 / CHECKS_TOTAL))
  if ((percent >= 85)); then
    printf '1;32'
  elif ((percent >= 50)); then
    printf '1;33'
  else
    printf '1;31'
  fi
}

bar_prefix() {
  local line

  while IFS= read -r line; do
    if [[ -z "$line" ]]; then
      printf '%s\n' "$(color "0;36" "$HEADER_MARK")"
    else
      printf '%s %s\n' "$(color "0;36" "$HEADER_MARK")" "$line"
    fi
  done
}

print_checks_bar_line() {
  local width filled_width color

  ((CHECKS_TOTAL > 0)) || return 0
  ((CHECKS_NORMAL < 0)) && CHECKS_NORMAL=0
  ((CHECKS_NORMAL > CHECKS_TOTAL)) && CHECKS_NORMAL=$CHECKS_TOTAL

  width=$((FULL_REPORT_WIDTH - CHECKS_BAR_MARGIN))
  ((width < 10)) && width=10
  filled_width=$((width * CHECKS_NORMAL / CHECKS_TOTAL))
  color="$(checks_health_color)"

  printf '  %s%s  %s\n' \
    "$(color "$color" "$(repeat_char "$CHECKS_BAR_CHAR" "$filled_width")")" \
    "$(color NULL "$(repeat_char "$CHECKS_BAR_REST_CHAR" $((width - filled_width)))")" \
    "$(color NULL "$CHECKS_NORMAL/$CHECKS_TOTAL checks passed")"
}

print_report_ip_lines() {
  local ipv4 ipv6 asn_display country4 country6 line

  ipv4="$(process_json "$RESULT_JSON" ".ip.ipv4.address")"
  ipv6="$(process_json "$RESULT_JSON" ".ip.ipv6.address")"
  country4="$REGISTERED_COUNTRY_IPV4"
  country6="$REGISTERED_COUNTRY_IPV6"

  [[ "$ipv4" == "null" ]] && ipv4=""
  [[ "$ipv6" == "null" ]] && ipv6=""

  asn_display=""
  if [[ -n "$ASN_NUMBER" && "$ASN_NUMBER" != "null" ]]; then
    asn_display="AS$ASN_NUMBER"
    [[ -n "$ASN_NAME" && "$ASN_NAME" != "null" ]] && asn_display+=" $ASN_NAME"
  fi

  if [[ -n "$ipv4" ]]; then
    local ip_cell
    ip_cell="$(pad "$(mask_ipv4 "$ipv4")" 16)"
    line="$(color HEADER "$(pad 'IPv4' 5)") $(bold "$ip_cell")"
    [[ -n "$asn_display" ]] && line+="  $(color ASN "$asn_display")"
    [[ -n "$country4" && "$country4" != "null" ]] && line+="  registered in $(bold "$(label_country "$country4")")"
    printf '%s\n' "$line"
    asn_display=""
  fi

  if [[ -n "$ipv6" ]]; then
    local ip6_cell
    ip6_cell="$(pad "$(mask_ipv6 "$ipv6")" 16)"
    line="$(color HEADER "$(pad 'IPv6' 5)") $(bold "$ip6_cell")"
    [[ -n "$asn_display" ]] && line+="  $(color ASN "$asn_display")"
    [[ -n "$country6" && "$country6" != "null" ]] && line+="  registered in $(bold "$(label_country "$country6")")"
    printf '%s\n' "$line"
  fi
}

print_report_verdict_line() {
  local name badge_color verdict_label

  [[ -n "$VERDICT_COUNTRY" || ${#VERDICT_TIED[@]} -gt 0 ]] || return 0

  if [[ -n "$VERDICT_COUNTRY" ]]; then
    verdict_label="$VERDICT_COUNTRY"
    name="$(country_display_name "$VERDICT_COUNTRY")"
    [[ "$name" == "$verdict_label" ]] && name=""
  else
    verdict_label="${VERDICT_TIED[0]}"
    name="tie: ${VERDICT_TIED[*]}"
  fi

  badge_color="$(checks_health_color)"
  printf '  %s %s %s\n' \
    "$(color "$badge_color" " $verdict_label ")" \
    "$(bold "$name")" \
    "$(color NULL "$VERDICT_NOTE")"
}

print_report_header() {
  printf '%s\n' "$(color "0;36" "$HEADER_MARK")  Made with$(color HEART " <3 ")by vladon $(color NULL "·") github.com/vladon/ipregion"
  printf '%s\n' "$(color "0;36" "$HEADER_MARK")"

  {
    print_report_ip_lines
    print_report_verdict_line
    print_checks_bar_line
  } | bar_prefix

  printf '\n'
}

# Human-readable reason for an abnormal cell
attention_issue_text() {
  local value="$1"
  local class

  class="$(classify_cell_value "$value")"
  case "$class" in
  no) echo "blocked" ;;
  region) echo "region blocked" ;;
  ipblock) echo "$value" ;;
  unknown)
    if [[ "$value" == "$STATUS_NA" ]]; then
      echo "no answer"
    else
      echo "$value"
    fi
    ;;
  country) echo "different country" ;;
  *) echo "$value" ;;
  esac
}

attention_value_text() {
  local value="$1"
  local class

  class="$(classify_cell_value "$value")"
  case "$class" in
  country) label_country "$value" ;;
  yes) echo "$SYMBOL_YES" ;;
  no | region) echo "$SYMBOL_NO" ;;
  ipblock) echo "$SYMBOL_IPBLOCK" ;;
  *) echo "$SYMBOL_UNKNOWN" ;;
  esac
}

# One attention row per abnormal cell: service, value
collect_attention_rows() {
  local -a groups=()
  local group

  mapfile -t groups < <(selected_display_groups)
  ((${#groups[@]} > 0)) || return 0

  jq -r -n \
    --argjson groups "$(printf '%s\n' "${groups[@]}" | jq -R . | jq -s .)" \
    --argjson verdicts "$(printf '%s\n' "$VERDICT_COUNTRY" "${VERDICT_TIED[@]}" | jq -R 'select(length > 0)' | jq -s .)" \
    --arg v4 "$(if can_use_ipv4; then echo true; else echo false; fi)" \
    --arg v6 "$(if can_use_ipv6; then echo true; else echo false; fi)" \
    --rawfile body <(printf '%s' "$RESULT_JSON") '
    def cls($v):
      if $v == "Yes" then "yes"
      elif $v == "No" then "no"
      elif ($v | test("^[A-Z]{2}$")) then "country"
      elif ($v == "N/A" or $v == "Rate-limit" or $v == "Server error") then "unknown"
      elif ($v == "Denied" or $v == "IP block" or $v == "DNS block") then "ipblock"
      elif ($v == "Region blocked") then "region"
      else "info"
      end;
    def abnormal($class; $value):
      ($class == "no" or $class == "ipblock" or $class == "region" or $class == "unknown")
      or ($class == "country" and (($verdicts | length) > 0) and ([$verdicts[] | select(. == $value)] | length) == 0);
    ($body | fromjson) as $r
    | [$groups[] as $g
        | ($r.results[$g] // [])[] as $row
        | ((if ($v4 == "true") then {service: $row.service, value: ($row.ipv4 // null)} else empty end),
           (if ($v6 == "true") then {service: $row.service, value: ($row.ipv6 // null)} else empty end))
        | select(.value != null and .value != "null")
        | (.value | cls(.)) as $class
        | select(abnormal($class; .value))
      ]
    | unique_by([.service, .value])
    | .[] | "\(.service)\t\(.value)"
  ' 2>/dev/null
}

# Wrap a ", "-separated service list into lines no wider than the width
wrap_words() {
  local text="$1"
  local width="$2"
  local line="" word
  local -a words out=()

  readarray -t words < <(printf '%s' "$text" | sed 's/, /\n/g')
  for word in "${words[@]}"; do
    if [[ -z "$line" ]]; then
      line="$word"
    elif (($(visible_length "$line") + 2 + $(visible_length "$word") <= width)); then
      line+=", $word"
    else
      out+=("$line")
      line="$word"
    fi
  done
  [[ -n "$line" ]] && out+=("$line")

  if ((${#out[@]} > 0)); then
    printf '%s\n' "${out[@]}"
  fi
}

print_attention_card() {
  [[ "$SHOW_ATTENTION" == true ]] || return 0

  local -a rows=() keys=() card_lines=() wrapped_lines=()
  local row service value issue key wrapped
  local -A services_by_key=() count_by_key=()
  local name_w=16 value_w=6 issue_w wrap_w

  mapfile -t rows < <(collect_attention_rows)
  ((${#rows[@]} > 0)) || return 0

  for row in "${rows[@]}"; do
    IFS=$'\t' read -r service value <<<"$row"
    issue="$(attention_issue_text "$value")"
    value="$(attention_value_text "$value")"
    key="$value"$'\x1f'"$issue"
    if [[ -z "${count_by_key[$key]:-}" ]]; then
      keys+=("$key")
      services_by_key[$key]=""
    fi
    count_by_key[$key]="$((${count_by_key[$key]:-0} + 1))"
    services_by_key[$key]+="${services_by_key[$key]:+, }$service"
  done

  issue_w=$((FULL_REPORT_WIDTH - CARD_SIDES_WIDTH - CARD_CONTENT_INDENT - CARD_TRAILING_GAP - name_w - value_w - 4))
  ((issue_w < 10)) && issue_w=10
  wrap_w=$((FULL_REPORT_WIDTH - CARD_SIDES_WIDTH - CARD_CONTENT_INDENT - CARD_TRAILING_GAP))

  card_lines+=("$(color TABLE_HEADER "$(pad "Service" "$name_w")")  $(color TABLE_HEADER "$(pad "Value" "$value_w")")  $(color TABLE_HEADER "Issue")")

  for key in "${keys[@]}"; do
    value="${key%%$'\x1f'*}"
    issue="${key#*$'\x1f'}"
    if ((count_by_key[$key] == 1)); then
      card_lines+=("$(pad "${services_by_key[$key]}" "$name_w")  $(color NULL "$(pad "$value" "$value_w")")  $(color WARN "$issue")")
    else
      card_lines+=("$(color NULL "$(pad "${count_by_key[$key]} services" "$name_w")")  $(color NULL "$(pad "$value" "$value_w")")  $(color WARN "$issue"):")
      mapfile -t wrapped_lines < <(wrap_words "${services_by_key[$key]}" "$wrap_w")
      for wrapped in "${wrapped_lines[@]}"; do
        card_lines+=("$(color NULL "$wrapped")")
      done
    fi
  done

  printf '%s\n' "${card_lines[@]}" | print_titled_card "Attention" "$FULL_REPORT_WIDTH" 0
  printf '\n'
}

print_report_legend() {
  printf '  %s\n\n' "$(color NULL "$LEGEND_LINE")"
}

print_report() {
  compute_report_verdict
  count_report_checks

  print_report_header
  print_attention_card
  print_group_cards
  print_report_legend
}

detect_output_format() {
  local output_file="$1"
  local lower_file
  lower_file="${output_file,,}"

  if [[ "$lower_file" == *.csv ]]; then
    echo "csv"
    return 0
  fi

  if [[ "$lower_file" == *.json ]]; then
    echo "json"
    return 0
  fi

  return 1
}

write_output_file() {
  local output_format

  if [[ -z "$OUTPUT_FILE" ]]; then
    return 0
  fi

  output_format=$(detect_output_format "$OUTPUT_FILE")
  if [[ -z "$output_format" ]]; then
    error_exit "Unsupported output format for $OUTPUT_FILE. Use .json or .csv"
  fi

  mkdir -p "$(dirname "$OUTPUT_FILE")"

  if [[ "$output_format" == "json" ]]; then
    printf "%s\n" "$RESULT_JSON" | jq >"$OUTPUT_FILE"
  else
    jq -r '
      ["group","service","ipv4","ipv6","ipv4_http_code","ipv4_latency_ms","ipv4_transport_ip_version","ipv4_error_type","ipv6_http_code","ipv6_latency_ms","ipv6_transport_ip_version","ipv6_error_type"],
      (.results.primary[] | [
        "primary",
        .service,
        (.ipv4 // ""),
        (.ipv6 // ""),
        (.metrics.ipv4.http_code // ""),
        (.metrics.ipv4.latency_ms // ""),
        (.metrics.ipv4.transport_ip_version // ""),
        (.metrics.ipv4.error_type // ""),
        (.metrics.ipv6.http_code // ""),
        (.metrics.ipv6.latency_ms // ""),
        (.metrics.ipv6.transport_ip_version // ""),
        (.metrics.ipv6.error_type // "")
      ]),
      (.results.custom[] | [
        "custom",
        .service,
        (.ipv4 // ""),
        (.ipv6 // ""),
        (.metrics.ipv4.http_code // ""),
        (.metrics.ipv4.latency_ms // ""),
        (.metrics.ipv4.transport_ip_version // ""),
        (.metrics.ipv4.error_type // ""),
        (.metrics.ipv6.http_code // ""),
        (.metrics.ipv6.latency_ms // ""),
        (.metrics.ipv6.transport_ip_version // ""),
        (.metrics.ipv6.error_type // "")
      ])
      | @csv
    ' <<<"$RESULT_JSON" >"$OUTPUT_FILE"
  fi

  if [[ "$JSON_OUTPUT" != true ]]; then
    printf "%s %s\n" \
      "$(color INFO '[INFO]')" \
      "Saved output to $OUTPUT_FILE" >&2
  fi
}

print_results() {
  finalize_json
  write_output_file

  if [[ "$JSON_OUTPUT" == true ]]; then
    echo "$RESULT_JSON" | jq
    return
  fi

  local restart_spinner=false
  if [[ "$spinner_running" == true ]]; then
    restart_spinner=true
    spinner_stop
  fi

  print_report

  case "$GROUPS_TO_SHOW" in
  primary) print_metrics_group "primary" "GeoIP service metrics" ;;
  custom) print_metrics_group "custom" "Popular service metrics" ;;
  cdn) print_metrics_group "cdn" "CDN metrics" ;;
  devinfra) print_metrics_group "devinfra" "Dev Infra metrics" ;;
  dns) print_metrics_group "dns" "DNS diagnostics metrics" ;;
  default)
    print_metrics_group "primary" "GeoIP service metrics"
    print_metrics_group "custom" "Popular service metrics"
    print_metrics_group "dns" "DNS diagnostics metrics"
    ;;
  *)
    print_metrics_group "custom" "Popular service metrics"
    print_metrics_group "cdn" "CDN metrics"
    print_metrics_group "devinfra" "Dev Infra metrics"
    print_metrics_group "dns" "DNS diagnostics metrics"
    print_metrics_group "primary" "GeoIP service metrics"
    ;;
  esac

  if [[ "$restart_spinner" == true ]]; then
    spinner_start
  fi
}

lookup_maxmind() {
  process_service "MAXMIND"
}

lookup_ripe() {
  process_service "RIPE"
}

lookup_ip2location_io() {
  process_service "IP2LOCATION_IO"
}

lookup_ipinfo_io() {
  process_service "IPINFO_IO"
}

lookup_ipapi_co() {
  process_service "IPAPI_CO"
}

lookup_cloudflare() {
  process_service "CLOUDFLARE"
}

lookup_ifconfig_co() {
  process_service "IFCONFIG_CO"
}

lookup_detector404() {
  process_service "DETECTOR404"
}

lookup_iplocation_com() {
  dns_unresolved "iplocation.com" && return
  local transport="$1"
  local ip_version="$2"
  local ip response country_code

  if [[ "$ip_version" == "6" ]]; then
    ip="$EXTERNAL_IPV6"
  else
    ip="$EXTERNAL_IPV4"
  fi

  if [[ -z "$ip" ]]; then
    log "$LOG_WARN" "Skipping iplocation.com lookup: empty IP for IPv${ip_version}"
    echo ""
    return
  fi

  if [[ "$ip_version" == "6" ]]; then
    if ! is_valid_ipv6 "$ip"; then
      log "$LOG_WARN" "Skipping iplocation.com lookup: invalid IPv6 address"
      echo ""
      return
    fi
  elif ! is_valid_ipv4 "$ip"; then
    log "$LOG_WARN" "Skipping iplocation.com lookup: invalid IPv4 address"
    echo ""
    return
  fi

  response=$(curl_wrapper POST "https://iplocation.com" --ip-version "$transport" --user-agent "$USER_AGENT" --data-urlencode "ip=$ip")
  country_code=$(process_json "$response" ".country_code")

  if [[ "$country_code" == "IPV6_NOT_SUPPORTED" ]]; then
    country_code="$STATUS_NA"
  fi

  echo "$country_code"
}

lookup_google() {
  dns_unresolved "accounts.google.com" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper GET "https://accounts.google.com/v3/signin/identifier?flowName=GlifSetupAndroid" \
    --user-agent "$USER_AGENT" \
    --ip-version "$ip_version")

  sed_capture 'name="region" value="([^"]*)' <<<"$response"
}

lookup_youtube() {
  dns_unresolved "www.youtube.com" && return
  local ip_version="$1"
  local response json_result

  response=$(curl_wrapper GET "https://www.youtube.com/sw.js_data" --ip-version "$ip_version")

  json_result=$(tail -n +3 <<<"$response")
  process_json "$json_result" ".[0][2][0][0][1]"
}

lookup_youtube_premium() {
  dns_unresolved "www.youtube.com" && return
  local ip_version="$1"
  local response is_available color_name

  response=$(curl_wrapper POST "https://www.youtube.com/youtubei/v1/browse" \
    --json '{"context":{"client":{"clientName":"MWEB","clientVersion":"2.20261020.00.00","hl":"en","gl":"US"}},"browseId":"SPunlimited"}' \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    echo ""
    return
  fi

  if grep_wrapper -qi "premiumPurchaseButtonRenderer" <<<"$response"; then
    is_available="Yes"
    color_name="SERVICE"
  else
    is_available="No"
    color_name="HEART"
  fi

  print_value_or_colored "$is_available" "$color_name"
}

lookup_youtube_premium_web() {
  dns_unresolved "www.youtube.com" && return
  local ip_version="$1"
  local response is_available color_name

  response=$(curl_wrapper GET "https://www.youtube.com/premium" \
    --user-agent "$USER_AGENT" \
    --header "Accept-Language: en-US,en;q=0.9" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    echo ""
    return
  fi

  if is_status_string "$response"; then
    echo "$response"
    return
  fi

  if grep_wrapper -qi "youtube premium is not available in your country" <<<"$response"; then
    is_available="No"
    color_name="HEART"
  else
    is_available="Yes"
    color_name="SERVICE"
  fi

  print_value_or_colored "$is_available" "$color_name"
}

lookup_google_search_captcha() {
  dns_unresolved "www.google.com" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper GET "https://www.google.com/search?q=cats" --ip-version "$ip_version" \
    --user-agent "$USER_AGENT" \
    --header "Accept-Language: en-US,en;q=0.9")

  if [[ -z "$response" ]]; then
    echo ""
    return
  fi

  if [[ "$response" == "$STATUS_RATE_LIMIT" ]] ||
    grep_wrapper -qiE "unusual traffic from|is blocked|unaddressed abuse" <<<"$response"; then
    print_value_or_colored "IP block" "ERROR"
    return
  fi

  print_value_or_colored "No" "SERVICE"
}

parse_gemini_user_status_code() {
  local batch_response="$1"
  local line inner_json status

  if [[ -z "$batch_response" ]]; then
    echo ""
    return
  fi

  line=$(grep_wrapper '^\[\["wrb.fr","otAQ7b"' <<<"$batch_response" | head -n1)

  if [[ -z "$line" ]]; then
    echo ""
    return
  fi

  inner_json=$(process_json "$line" '.[0][2]')

  if [[ -z "$inner_json" ]]; then
    echo ""
    return
  fi

  status=$(process_json "$inner_json" '.[14]')
  echo "$status"
}

gemini_batch_needs_stream_probe() {
  local batch_response="$1"
  local line inner_json status session_ok enabled_models

  if [[ -z "$batch_response" ]]; then
    echo ""
    return
  fi

  line=$(grep_wrapper '^\[\["wrb.fr","otAQ7b"' <<<"$batch_response" | head -n1)

  if [[ -z "$line" ]]; then
    echo ""
    return
  fi

  inner_json=$(process_json "$line" '.[0][2]')

  if [[ -z "$inner_json" ]]; then
    echo ""
    return
  fi

  status=$(process_json "$inner_json" '.[14]')

  case "$status" in
  1060 | 1014 | 1033)
    echo "no"
    ;;
  1000 | 1040)
    echo "stream"
    ;;
  1016)
    session_ok=$(process_json "$inner_json" '.[2]')
    enabled_models=$(process_json "$inner_json" '
      [.[15][]? | select(type == "array" and (.[7] == true or .[7] == "true"))] | length
    ')
    if [[ "$session_ok" == "true" && "$enabled_models" =~ ^[0-9]+$ && "$enabled_models" -gt 0 ]]; then
      echo "stream"
    else
      echo "no"
    fi
    ;;
  *)
    echo ""
    ;;
  esac
}

gemini_build_stream_generate_freq() {
  local uuid

  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    uuid=$(</proc/sys/kernel/random/uuid)
  else
    uuid=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n' | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/')
  fi

  jq -nc --arg uuid "$uuid" '
    (
      [range(80)] | map(null)
      | .[0] = ["hi", 0, null, null, null, null, 0]
      | .[1] = ["en"]
      | .[2] = ["", "", "", null, null, null, null, null, null, ""]
      | .[6] = [0]
      | .[7] = 1
      | .[10] = 1
      | .[11] = 0
      | .[17] = [[4]]
      | .[18] = 0
      | .[27] = 1
      | .[30] = [4]
      | .[41] = [2]
      | .[53] = 0
      | .[59] = $uuid
      | .[61] = []
      | .[68] = 1
      | .[79] = 1
    ) as $inner
    | [null, ($inner | tojson)]
  '
}

gemini_stream_generate_has_reply() {
  local response="$1"
  local line inner_json reply blocked_code

  if [[ -z "$response" ]]; then
    echo "no"
    return
  fi

  if grep_wrapper -qiE 'not available in your|isn.t available|not supported in your|unsupported country|location.rejected' <<<"$response"; then
    echo "no"
    return
  fi

  while IFS= read -r line; do
    [[ ! "$line" =~ ^\[\[\"wrb\.fr\" ]] && continue

    inner_json=$(process_json "$line" '.[0][2]')

    if [[ -z "$inner_json" || ${#inner_json} -lt 50 ]]; then
      continue
    fi

    blocked_code=$(process_json "$inner_json" '
      [.. | numbers | select(. == 1060 or . == 1014 or . == 1033)] | first // empty
    ')

    if [[ -n "$blocked_code" ]]; then
      echo "no"
      return
    fi

    reply=$(process_json "$inner_json" '
      [
        .. | arrays
        | select(
            length >= 2
            and (.[0] | type) == "string"
            and (.[0] | startswith("rc_"))
            and (.[1] | type) == "array"
          )
        | .[1][]
        | select(type == "string" and length > 1)
      ] | last // empty
    ')

    if [[ -n "$reply" ]]; then
      echo "yes"
      return
    fi
  done < <(grep_wrapper '^\[\["wrb.fr"' <<<"$response")

  echo "no"
}

# NotebookLM (rebranded "Gemini Notebook") - application availability
# without sign-in. For non-browser clients unsupported regions are sent
# a redirect whose URL carries location=unsupported (possibly
# percent-encoded and possibly only as an intermediate hop), so the
# gate is checked against both the final effective URL and the
# recorded redirect Location. Google edges alternate between the gate
# and a clean landing for one egress, so the check probes three times:
# any gated response confirms No, and Yes requires ALL three attempts
# to return HTTP 200 on an application domain (notebooklm.google.com /
# notebook.google.com) with non-empty HTML carrying application signs.
# Sign-in, the marketing page (notebook.google), CAPTCHA and error
# pages are not the application. Timeouts, transport errors,
# 429/5xx and unrecognized responses leave the verdict undetermined
# (N/A) - they are neither a confirmed ban nor confirmed availability.
# A browser UA skips the server-side gate (the verdict then only
# appears in-app after sign-in), so no custom user agent is sent.
is_notebook_gate_url() {
  local url decoded
  for url in "$@"; do
    [[ -z "$url" ]] && continue
    decoded=${url//\%3D/=}
    decoded=${decoded//\%3d/=}
    [[ "${decoded,,}" == *location=unsupported* ]] && return 0
  done
  return 1
}

is_notebook_app_page() {
  local url="$1"
  local body="$2"

  [[ -n "$body" ]] || return 1
  case "$url" in
  *"://notebooklm.google.com/"* | *"://notebook.google.com/"*) ;;
  *) return 1 ;;
  esac

  local lower=${body,,}
  [[ "$lower" == *notebooklm* || "$lower" == *"gemini notebook"* ]]
}

lookup_gemini_notebook() {
  dns_unresolved "notebooklm.google.com" && return
  local ip_version="$1"
  local effective_url redirect_url response error_type http_code attempt
  local gate_found=false ok_attempts=0

  for attempt in 1 2 3; do
    response=$(curl_wrapper GET "https://notebooklm.google.com/" \
      --ip-version "$ip_version" \
      --effective-url)

    effective_url=$(read_curl_metric_field "${CURL_META_FILE:-}" "effective_url")
    redirect_url=$(read_curl_metric_field "${CURL_META_FILE:-}" "redirect_url")
    http_code=$(read_curl_metric_field "${CURL_META_FILE:-}" "http_code")

    if is_notebook_gate_url "$effective_url" "$redirect_url"; then
      gate_found=true
    fi

    # Anything that is not a successful application response (transport
    # errors, timeouts, 429/5xx/451, sign-in, marketing, CAPTCHA, empty
    # or unrecognized bodies) stays undetermined for this attempt.
    if [[ "$http_code" == "200" ]] &&
      is_notebook_app_page "$effective_url" "$response" &&
      ! is_status_string "$response"; then
      ok_attempts=$((ok_attempts + 1))
    fi
  done

  if [[ "$gate_found" == true ]]; then
    print_value_or_colored "No" "HEART"
  elif ((ok_attempts == 3)); then
    print_value_or_colored "Yes" "SERVICE"
  else
    echo ""
  fi
}

lookup_gemini() {
  dns_unresolved "gemini.google.com" && return
  local ip_version="$1"
  local response batch_response sid bl encoded_bl availability color_name reqid batch_url
  local probe_status stream_freq stream_url stream_response stream_reply

  response=$(curl_wrapper GET "https://gemini.google.com" \
    --user-agent "$USER_AGENT" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    echo ""
    return
  fi

  sid=$(sed_capture '"FdrFJe":"([^"]*)' <<<"$response")
  bl=$(sed_capture '"cfb2h":"([^"]*)' <<<"$response")

  if [[ -z "$sid" || -z "$bl" ]]; then
    echo ""
    return
  fi

  encoded_bl=$(jq -nr --arg bl "$bl" '$bl|@uri')
  reqid=$((RANDOM % 900000 + 100000))
  batch_url="https://gemini.google.com/_/BardChatUi/data/batchexecute?rpcids=otAQ7b&source-path=%2Fapp&bl=${encoded_bl}&f.sid=${sid}&hl=en&_reqid=${reqid}&rt=c"

  batch_response=$(curl_wrapper POST "$batch_url" \
    --ip-version "$ip_version" \
    --user-agent "$USER_AGENT" \
    --header "Content-Type: application/x-www-form-urlencoded;charset=UTF-8" \
    --header "Origin: https://gemini.google.com" \
    --header "Referer: https://gemini.google.com/" \
    --header "X-Same-Domain: 1" \
    --data 'f.req=%5B%5B%5B%22otAQ7b%22%2C%22%5B%5D%22%2Cnull%2C%22generic%22%5D%5D%5D')

  probe_status=$(gemini_batch_needs_stream_probe "$batch_response")

  case "$probe_status" in
  stream)
    stream_freq=$(gemini_build_stream_generate_freq)
    if [[ -z "$stream_freq" ]]; then
      echo ""
      return
    fi

    reqid=$((reqid + 1))
    stream_url="https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?bl=${encoded_bl}&hl=en&_reqid=${reqid}&rt=c"
    stream_response=$(curl_wrapper POST "$stream_url" \
      --ip-version "$ip_version" \
      --user-agent "$USER_AGENT" \
      --header "Content-Type: application/x-www-form-urlencoded;charset=UTF-8" \
      --header "Origin: https://gemini.google.com" \
      --header "Referer: https://gemini.google.com/app" \
      --header "X-Same-Domain: 1" \
      --data-urlencode "f.req=$stream_freq")

    stream_reply=$(gemini_stream_generate_has_reply "$stream_response")
    if [[ "$stream_reply" == "yes" ]]; then
      availability="Yes"
    else
      availability="No"
    fi
    ;;
  no)
    availability="No"
    ;;
  *)
    echo ""
    return
    ;;
  esac

  if [[ "$availability" == "Yes" ]]; then
    color_name="SERVICE"
  else
    color_name="HEART"
  fi

  print_value_or_colored "$availability" "$color_name"
}

lookup_apple() {
  dns_unresolved "gspe1-ssl.ls.apple.com" && return
  local ip_version="$1"
  curl_wrapper GET "https://gspe1-ssl.ls.apple.com/pep/gcc" --ip-version "$ip_version"
}

lookup_steam() {
  dns_unresolved "store.steampowered.com" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper HEAD "https://store.steampowered.com" --ip-version "$ip_version")
  sed_capture 'steamCountry=([^%;]*)' <<<"$response"
}

lookup_tiktok() {
  dns_unresolved "www.tiktok.com" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper GET "https://www.tiktok.com/api/v1/web-cookie-privacy/config?appId=1988" --ip-version "$ip_version")
  process_json "$response" ".body.appProps.region"
}

lookup_ookla_speedtest() {
  dns_unresolved "www.speedtest.net" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper GET "https://www.speedtest.net/api/js/config-sdk" --ip-version "$ip_version")
  process_json "$response" ".location.countryCode"
}

lookup_jetbrains() {
  dns_unresolved "data.services.jetbrains.com" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper GET "https://data.services.jetbrains.com/geo" --ip-version "$ip_version")
  process_json "$response" ".code"
}

lookup_playstation() {
  dns_unresolved "www.playstation.com" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper HEAD "https://www.playstation.com" --ip-version "$ip_version")
  sed_capture 'country=([^;]*)' <<<"$response"
}

lookup_microsoft() {
  dns_unresolved "login.live.com" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper GET "https://login.live.com" --ip-version "$ip_version")
  sed_capture '"sRequestCountry":"([^"]*)' <<<"$response"
}

lookup_twitch() {
  dns_unresolved "gql.twitch.tv" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper POST "https://gql.twitch.tv/gql" \
    --header "Client-Id: $TWITCH_CLIENT_ID" \
    --json '[{"operationName":"VerifyEmail_CurrentUser","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"f9e7dcdf7e99c314c82d8f7f725fab5f99d1df3d7359b53c9ae122deec590198"}}}]' \
    --ip-version "$ip_version")

  process_json "$response" ".[0].data.requestInfo.countryCode"
}

lookup_chatgpt() {
  dns_unresolved "ab.chatgpt.com" && return
  local ip_version="$1"
  local response fragment

  response=$(curl_wrapper POST "https://ab.chatgpt.com/v1/initialize" \
    --header "Statsig-Api-Key: $CHATGPT_STATSIG_API_KEY" \
    --ip-version "$ip_version")

  fragment=$(grep_wrapper -oE '"derived_fields":\{[^}]*\}' <<<"$response" | head -n 1)

  process_json "${fragment#"$CHATGPT_DERIVED_FIELDS_PREFIX"}" ".country"
}

lookup_disney_plus() {
  dns_unresolved "disney.api.edge.bamgrid.com" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper POST "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" \
    --header "Authorization: Bearer $DISNEY_PLUS_API_KEY" \
    --json "$DISNEY_PLUS_JSON_BODY" \
    --ip-version "$ip_version")

  local country
  country=$(process_json "$response" ".extensions.sdk.session.location.countryCode")
  if [[ -z "$country" || "$country" == "null" ]]; then
    echo ""
    return
  fi

  printf "%s" "$country"
}

lookup_disney_plus_access() {
  dns_unresolved "disney.api.edge.bamgrid.com" && return
  local ip_version="$1"
  local response errors_count in_supported_location is_available color_name

  response=$(curl_wrapper POST "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" \
    --header "Authorization: Bearer $DISNEY_PLUS_API_KEY" \
    --json "$DISNEY_PLUS_JSON_BODY" \
    --ip-version "$ip_version")

  {
    read -r errors_count
    read -r in_supported_location
  } < <(process_json "$response" "(.errors | length), .extensions.sdk.session.inSupportedLocation")

  if [[ "$errors_count" == "0" && "$in_supported_location" == "true" ]]; then
    is_available="Yes"
    color_name="SERVICE"
  else
    is_available="No"
    color_name="HEART"
  fi

  print_value_or_colored "$is_available" "$color_name"
}

get_iata_location() {
  local iata_code="$1"
  local response

  response=$(curl_wrapper POST "https://www.air-port-codes.com/api/v1/single" \
    --header "APC-Auth: 96dc04b3fb" \
    --header "Referer: https://www.air-port-codes.com/" \
    --data "iata=$iata_code" \
    --ip-version 4)

  process_json "$response" ".airport.country.iso // empty"
}

parse_youtube_cdn_iata() {
  local node="$1"
  local google_node_regex='^([a-z]{3})[0-9]'
  local isp_iata_regex='^[a-z]+-([a-z]{3})[0-9]'
  local ggc_node_regex='^[a-z]{2}([a-z]{3})[a-z]-[a-z0-9]+$'

  if [[ "$node" =~ $google_node_regex || "$node" =~ $isp_iata_regex || "$node" =~ $ggc_node_regex ]]; then
    echo "${BASH_REMATCH[1]^^}"
  fi
}

lookup_youtube_cdn() {
  dns_unresolved "redirector.googlevideo.com" && return
  local ip_version="$1"
  local response iata location

  response=$(curl_wrapper GET "https://redirector.googlevideo.com/report_mapping?di=no" --ip-version "$ip_version")
  iata=$(parse_youtube_cdn_iata "$(awk '{print $3}' <<<"$response")")

  if [[ -z "$iata" ]]; then
    echo ""
    return
  fi

  if is_status_string "$iata"; then
    echo "$iata"
    return
  fi

  location=$(get_iata_location "$iata")
  echo "$location ($iata)"
}

lookup_cloudflare_cdn() {
  dns_unresolved "speed.cloudflare.com" && return
  local ip_version="$1"
  local response iata location

  response=$(curl_wrapper GET "https://speed.cloudflare.com/meta" \
    --header "Referer: https://speed.cloudflare.com" \
    --ip-version "$ip_version")

  iata=$(process_json "$response" ".colo.iata")

  if [[ -z "$iata" || "$iata" == "null" ]]; then
    echo ""
    return
  fi

  if is_status_string "$iata"; then
    echo "$iata"
    return
  fi

  location=$(get_iata_location "$iata")
  echo "$location ($iata)"
}

lookup_reddit_guest_access() {
  dns_unresolved "www.reddit.com" && return
  local ip_version="$1"
  local response is_available color_name

  response=$(curl_wrapper GET "https://www.reddit.com" --ip-version "$ip_version" --user-agent "$USER_AGENT")

  if [[ -z "$response" ]]; then
    echo ""
    return
  fi

  if [[ "$response" == "$STATUS_DENIED" ]]; then
    print_value_or_colored "No" "HEART"
    return
  fi

  if is_status_string "$response"; then
    echo "$response"
    return
  fi

  print_value_or_colored "Yes" "SERVICE"
}

lookup_netflix() {
  dns_unresolved "api.fast.com" && return
  local ip_version="$1"
  local response country

  response=$(curl_wrapper GET "https://api.fast.com/netflix/speedtest/v2?https=true&token=$NETFLIX_API_KEY&urlCount=1" --ip-version "$ip_version")

  country=$(process_json "$response" ".client.location.country")
  if [[ -z "$country" || "$country" == "null" ]]; then
    echo ""
    return
  fi

  printf "%s" "$country"
}

lookup_netflix_cdn() {
  dns_unresolved "api.fast.com" && return
  local ip_version="$1"
  local response country

  response=$(curl_wrapper GET "https://api.fast.com/netflix/speedtest/v2?https=true&token=$NETFLIX_API_KEY&urlCount=1" --ip-version "$ip_version")

  country=$(process_json "$response" ".targets[0].location.country")
  if [[ -z "$country" || "$country" == "null" ]]; then
    echo ""
    return
  fi

  printf "%s" "$country"
}

lookup_spotify() {
  dns_unresolved "spclient.wg.spotify.com" && return
  local ip_version="$1"
  local response country

  response=$(curl_wrapper GET "https://spclient.wg.spotify.com/signup/public/v1/account/?validate=1&key=$SPOTIFY_API_KEY" \
    --header "X-Client-Id: $SPOTIFY_CLIENT_ID" \
    --ip-version "$ip_version")

  country=$(process_json "$response" ".country")
  if [[ -z "$country" || "$country" == "null" ]]; then
    echo ""
    return
  fi

  printf "%s" "$country"
}

lookup_spotify_signup() {
  dns_unresolved "spclient.wg.spotify.com" && return
  local ip_version="$1"
  local response status is_country_launched available color_name

  response=$(curl_wrapper GET "https://spclient.wg.spotify.com/signup/public/v1/account/?validate=1&key=$SPOTIFY_API_KEY" \
    --header "X-Client-Id: $SPOTIFY_CLIENT_ID" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    echo ""
    return
  fi

  if is_status_string "$response"; then
    echo "$response"
    return
  fi

  {
    read -r status
    read -r is_country_launched
  } < <(process_json "$response" ".status, .is_country_launched")

  if [[ "$status" == "120" || "$status" == "320" || "$is_country_launched" == "false" ]]; then
    available="No"
    color_name="HEART"
  else
    available="Yes"
    color_name="SERVICE"
  fi

  print_value_or_colored "$available" "$color_name"
}

# Portable single-record resolver: 0 when the host resolves to any address.
# With no resolver tool available there is no data, which is not a DNS block.
host_resolves() {
  local host="$1"
  local addr=""

  # IP literals need no resolution: asking a resolver for an address
  # yields PTR data or nothing, which would fake a DNS block verdict.
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$host" == *:* ]]; then
    return 0
  fi

  if command -v getent >/dev/null 2>&1; then
    addr=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NF {print $1; exit}')
  elif command -v nslookup >/dev/null 2>&1; then
    # Bound the resolver: some networks silently DROP queries (filtered
    # zones), and default retries then stall each lookup for minutes.
    addr=$(nslookup -timeout=2 -retry=1 "$host" 2>/dev/null | awk '/^Address/ {print $NF}' | grep -v '#' | tail -n 1)
  elif command -v host >/dev/null 2>&1; then
    addr=$(host -W 2 "$host" 2>/dev/null | awk '/has address/{print $NF; exit}')
  else
    return 1
  fi

  [[ -n "$addr" ]]
}

# TCP connect probe via the bash /dev/tcp builtin; no external tools needed.
# Returns 0 when the connection succeeds within timeout seconds, 1 otherwise.
tcp_probe() {
  local host="$1"
  local port="$2"
  local timeout_s="${3:-3}"
  local probe_pid waited=0

  (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null &
  probe_pid=$!

  while kill -0 "$probe_pid" 2>/dev/null && ((waited < timeout_s * 10)); do
    sleep 0.1
    waited=$((waited + 1))
  done

  if kill -0 "$probe_pid" 2>/dev/null; then
    kill -TERM "$probe_pid" 2>/dev/null
    wait "$probe_pid" 2>/dev/null
    return 1
  fi

  wait "$probe_pid" 2>/dev/null
}

# Hostname of an http(s) URL: scheme, port and path stripped.
url_host() {
  local host="${1#*://}"
  host="${host%%/*}"
  host="${host%%:*}"
  echo "$host"
}

# Prints the DNS-block verdict and returns 0 when the host fails to
# resolve, 1 otherwise. First line of custom handlers whose curl bodies
# bypass the shared site/gate/tcp helpers.
dns_unresolved() {
  if host_resolves "$1"; then
    return 1
  fi
  print_value_or_colored "DNS block" "WARN"
  return 0
}

# Addresses the SYSTEM resolver returns for the host and record type
# (A or AAAA), one per line; empty when the name does not resolve or no
# resolver tool exists. Tool preference mirrors host_resolves.
system_dns_answers() {
  local host="$1"
  local record_type="${2:-A}"
  local -a answers=()
  if command -v getent >/dev/null 2>&1; then
    if [[ "$record_type" == "AAAA" ]]; then
      mapfile -t answers < <(getent ahostsv6 "$host" 2>/dev/null | awk 'NF {print $1}' | sort -u)
    else
      mapfile -t answers < <(getent ahostsv4 "$host" 2>/dev/null | awk 'NF {print $1}' | sort -u)
    fi
  elif command -v nslookup >/dev/null 2>&1; then
    # macOS nslookup prints AAAA answers in host(1) style ("has AAAA
    # address"), Linux bind prints "Address:" lines; catch both. The
    # server header carries a "#53" suffix and is filtered below.
    mapfile -t answers < <(nslookup -type="$record_type" "$host" 2>/dev/null | awk '/^Address/ {print $NF} /has .*address/ {print $NF}' | grep_wrapper -v '#' | sort -u)
  elif command -v host >/dev/null 2>&1; then
    if [[ "$record_type" == "AAAA" ]]; then
      mapfile -t answers < <(host -t AAAA "$host" 2>/dev/null | awk '/has IPv6 address/ {print $NF}' | sort -u)
    else
      mapfile -t answers < <(host -t A "$host" 2>/dev/null | awk '/has address/ {print $NF}' | sort -u)
    fi
  fi
  printf '%s\n' "${answers[@]+"${answers[@]}"}"
}

# DoH-JSON reference answer set (one address per line) fetched over TLS so
# port-53 interception cannot influence it. Tries Cloudflare then Google;
# returns 1 when neither answered.
doh_dns_answers() {
  local host="$1"
  local record_type="${2:-A}"
  local ip_version="$3"
  local answer_type=1
  case "$record_type" in
  AAAA) answer_type=28 ;;
  PTR) answer_type=12 ;;
  esac
  local -a endpoints=(
    "https://cloudflare-dns.com/dns-query?name=${host}&type=${record_type}"
    "https://dns.google/resolve?name=${host}&type=${record_type}"
  )
  local endpoint response
  for endpoint in "${endpoints[@]}"; do
    response=$(curl_wrapper GET "$endpoint" \
      --header "Accept: application/dns-json" \
      --ip-version "$ip_version")
    [[ -z "$response" ]] && continue
    if [[ -z "$(process_json "$response" '.Status // empty' 2>/dev/null)" ]]; then
      continue
    fi
    process_json "$response" "(.Answer // [])[] | select(.type == $answer_type) | .data" 2>/dev/null | sort -u
    return 0
  done
  return 1
}

# First egress address echoed by an explicitly addressed resolver for the
# whoami canary; empty when the query failed or no tool supports server
# selection (getent cannot). Output format handling mirrors
# system_dns_answers.
resolver_echo_answer() {
  local server="$1"
  local answer=""
  if command -v nslookup >/dev/null 2>&1; then
    answer=$(nslookup -type=A whoami.akamai.net "$server" 2>/dev/null | awk '/^Address/ {print $NF} /has .*address/ {print $NF}' | grep_wrapper -v '#' | sort -u | head -n 1)
  elif command -v host >/dev/null 2>&1; then
    answer=$(host -t A whoami.akamai.net "$server" 2>/dev/null | awk '/has .*address/ {print $NF}' | sort -u | head -n 1)
  fi
  echo "$answer"
}

# PTR name the SYSTEM resolver returns for the IPv4 address; empty when
# none exists or no tool is available. Field order differs between tools:
# match the field that is not the queried address.
system_ptr_answer() {
  local ip="$1"
  local answer=""
  if command -v getent >/dev/null 2>&1; then
    answer=$(getent hosts "$ip" 2>/dev/null | awk -v addr="$ip" '$1 == addr {print $2; exit} $2 == addr {print $1; exit}')
  elif command -v nslookup >/dev/null 2>&1; then
    answer=$(nslookup "$ip" 2>/dev/null | awk '/name =|pointer/ {print $NF}' | head -n 1)
  elif command -v host >/dev/null 2>&1; then
    answer=$(host "$ip" 2>/dev/null | awk '/pointer/ {print $NF}' | head -n 1)
  fi
  echo "$answer"
}

# True for addresses public services must never serve: this-network,
# loopback, RFC1918, CGNAT, link-local, benchmarking ranges.
is_nonpublic_ipv4() {
  local ip="$1"
  local o1 o2
  [[ "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || return 1
  o1="${ip%%.*}"
  o2="${ip#*.}"
  o2="${o2%%.*}"
  case "$o1" in
  0 | 10 | 127) return 0 ;;
  169) [[ "$o2" == 254 ]] && return 0 ;;
  172) ((o2 >= 16 && o2 <= 31)) && return 0 ;;
  100) ((o2 >= 64 && o2 <= 127)) && return 0 ;;
  192) [[ "$o2" == 168 ]] && return 0 ;;
  198) ((o2 == 18 || o2 == 19)) && return 0 ;;
  esac
  return 1
}

# The TTL the SYSTEM resolver served for the host's first A record;
# empty when the tool cannot report TTLs or the lookup failed. nslookup
# reports "ttl = N" in debug mode; host -a embeds the TTL in the RR line.
system_dns_ttl() {
  local host="$1"
  local answer=""
  if command -v nslookup >/dev/null 2>&1; then
    answer=$(nslookup -debug -type=A "$host" 2>/dev/null | awk 'tolower($1) == "ttl" {print $3; exit}')
  elif command -v host >/dev/null 2>&1; then
    answer=$(host -a "$host" 2>/dev/null | awk 'tolower($2) == "in" && toupper($3) == "A" {print $2; exit}')
  fi
  echo "$answer"
}

# The TTL the Cloudflare DoH reference reports for the name (first
# answer); prints nothing when there is no answer, returns 1 on
# transport failure.
doh_dns_ttl() {
  local host="$1"
  local ip_version="$2"
  local response
  response=$(curl_wrapper GET "https://cloudflare-dns.com/dns-query?name=${host}&type=A" \
    --header "Accept: application/dns-json" \
    --ip-version "$ip_version")
  if [[ -z "$response" ]] || [[ -z "$(process_json "$response" '.Status // empty' 2>/dev/null)" ]]; then
    return 1
  fi
  process_json "$response" '.Answer[0].TTL // empty' 2>/dev/null
}

# Answers an explicitly addressed resolver returned for the host, one
# per line; empty when it did not answer or no tool supports server
# selection. Output format handling mirrors system_dns_answers.
server_dns_answers() {
  local host="$1"
  local server="$2"
  local -a answers=()
  if command -v nslookup >/dev/null 2>&1; then
    mapfile -t answers < <(nslookup -type=A "$host" "$server" 2>/dev/null | awk '/^Address/ {print $NF} /has .*address/ {print $NF}' | grep_wrapper -v '#' | sort -u)
  elif command -v host >/dev/null 2>&1; then
    mapfile -t answers < <(host -t A "$host" "$server" 2>/dev/null | awk '/has .*address/ {print $NF}' | sort -u)
  fi
  printf '%s\n' "${answers[@]+"${answers[@]}"}"
}

# Decimal seconds to integer milliseconds (integer math: bash arithmetic
# has no floats).
seconds_to_ms() {
  local t="$1"
  local int_part frac_part
  if [[ "$t" != *.* ]]; then
    echo $((10#$t * 1000))
    return
  fi
  int_part="${t%%.*}"
  frac_part="${t#*.}"
  while ((${#frac_part} < 6)); do
    frac_part="${frac_part}0"
  done
  echo $((10#$int_part * 1000 + 10#$frac_part / 1000))
}

# Resolution time in milliseconds for one system-resolver A lookup,
# including tool startup; empty when the platform cannot measure
# (EPOCHREALTIME needs bash >= 5) or the lookup failed.
system_dns_latency_ms() {
  local host="$1"
  local start end answers
  [[ -n "${EPOCHREALTIME:-}" ]] || {
    echo ""
    return
  }
  start="$EPOCHREALTIME"
  answers=$(system_dns_answers "$host" "A")
  end="$EPOCHREALTIME"
  [[ -z "$answers" ]] && {
    echo ""
    return
  }
  awk -v s="$start" -v e="$end" 'BEGIN { printf "%d", (e - s) * 1000 }'
}

# Resolution time in milliseconds for one DoH-JSON lookup through the
# reference, measured the same way as system_dns_latency_ms so both
# sides compare like for like.
doh_dns_latency_ms() {
  local host="$1"
  local ip_version="$2"
  local start end answers
  [[ -n "${EPOCHREALTIME:-}" ]] || {
    echo ""
    return
  }
  start="$EPOCHREALTIME"
  answers=$(doh_dns_answers "$host" "A" "$ip_version")
  end="$EPOCHREALTIME"
  [[ -z "$answers" ]] && {
    echo ""
    return
  }
  awk -v s="$start" -v e="$end" 'BEGIN { printf "%d", (e - s) * 1000 }'
}

# Spread (max - min) of exactly three integers.
spread3() {
  local a=$1 b=$2 c=$3
  local min=$a max=$a
  ((b < min)) && min=$b
  ((b > max)) && max=$b
  ((c < min)) && min=$c
  ((c > max)) && max=$c
  echo $((max - min))
}

# Median of exactly three integers.
median3() {
  local a=$1 b=$2 c=$3
  local min=$a mid=$b max=$c t
  ((min > mid)) && {
    t=$min
    min=$mid
    mid=$t
  }
  ((mid > max)) && {
    t=$mid
    mid=$max
    max=$t
  }
  ((min > mid)) && {
    t=$min
    min=$mid
    mid=$t
  }
  echo "$mid"
}

# Resolution time in milliseconds for one direct query to an explicitly
# addressed resolver, measured like the other latency helpers.
server_dns_latency_ms() {
  local host="$1"
  local server="$2"
  local start end answers
  [[ -n "${EPOCHREALTIME:-}" ]] || {
    echo ""
    return
  }
  start="$EPOCHREALTIME"
  answers=$(server_dns_answers "$host" "$server")
  end="$EPOCHREALTIME"
  [[ -z "$answers" ]] && {
    echo ""
    return
  }
  awk -v s="$start" -v e="$end" 'BEGIN { printf "%d", (e - s) * 1000 }'
}

# DNS-integrity diagnostic: a resolver that invents records for names that
# cannot exist, or that rewrites answers for fixed public records compared
# against a TLS-protected DoH reference, is spoofing DNS. A records and
# AAAA records are both compared: an empty system AAAA while the reference
# has one is ISP AAAA-nulling. Yes = answers clean, No = spoofing,
# filtering or nulling detected.
lookup_dns_integrity() {
  local ip_version="$1"
  local -a canaries=("dns.google" "one.one.one.one")
  local -a record_types=("A" "AAAA")
  local canary record_type probe_domain="nx-$(date +%s)-$RANDOM.vladon.sh"
  local local_answers doh_answers answer

  # The zone has no wildcard: an answer for a random label means the
  # resolver invents records.
  if [[ -n "$(system_dns_answers "$probe_domain" "A")" ]]; then
    print_value_or_colored "No" "HEART"
    return
  fi

  for canary in "${canaries[@]}"; do
    for record_type in "${record_types[@]}"; do
      doh_answers=$(doh_dns_answers "$canary" "$record_type" "$ip_version") || {
        # No TLS-protected reference reachable: honesty over guessing.
        echo "$STATUS_NA"
        return
      }
      if [[ -z "$doh_answers" ]]; then
        # The reference legitimately has no records of this type: nothing
        # to compare against.
        continue
      fi
      local_answers=$(system_dns_answers "$canary" "$record_type")
      if [[ -z "$local_answers" ]]; then
        # The reference resolves, the system resolver stays silent: the
        # answer is filtered or nulled (the AAAA case is the common ISP
        # practice of forcing IPv4).
        print_value_or_colored "No" "HEART"
        return
      fi
      while IFS= read -r answer; do
        if ! grep_wrapper -qxF "$answer" <<<"$doh_answers"; then
          print_value_or_colored "No" "HEART"
          return
        fi
      done <<<"$local_answers"
    done
  done
  print_value_or_colored "Yes" "SERVICE"
}

# Port-53 interception diagnostic: whoami.akamai.net echoes the egress
# address of the resolver that actually fetched the answer. Two
# independent public resolvers asked directly must echo different
# egresses (Google and Cloudflare never share one); identical echoes mean
# one invisible resolver answered both - transparent port-53
# interception. Yes = clean, No = intercepted, N/A = cannot verify.
lookup_dns_intercept() {
  local ip_version="$1"
  local google_echo cloudflare_echo

  google_echo=$(resolver_echo_answer "8.8.8.8")
  cloudflare_echo=$(resolver_echo_answer "1.1.1.1")
  if [[ -z "$google_echo" || -z "$cloudflare_echo" ]]; then
    # Direct port-53 queries failed (blocked or no resolver tool):
    # honesty over guessing.
    echo "$STATUS_NA"
    return
  fi
  if [[ "$google_echo" == "$cloudflare_echo" ]]; then
    print_value_or_colored "No" "HEART"
    return
  fi
  print_value_or_colored "Yes" "SERVICE"
}

# Reverse-DNS integrity diagnostic: the PTR names for two stable public
# addresses (dns.google, one.one.one.one) observed from the DoH-JSON
# reference over TLS must match what the system resolver returns. A
# different name is ISP PTR substitution, a silent answer while the
# reference has one is filtering. Yes = clean, No = substituted or
# filtered, N/A = cannot verify.
lookup_dns_ptr() {
  local ip_version="$1"
  local -a reverse_targets=("8.8.8.8" "1.1.1.1")
  local ip local_ptr doh_raw doh_ptr

  for ip in "${reverse_targets[@]}"; do
    doh_raw=$(doh_dns_answers "${ip}.in-addr.arpa" "PTR" "$ip_version") || {
      # No TLS-protected reference reachable: honesty over guessing.
      echo "$STATUS_NA"
      return
    }
    doh_ptr=$(awk '{sub(/\.$/, ""); print tolower($0)}' <<<"$doh_raw")
    if [[ -z "$doh_ptr" ]]; then
      # No authoritative PTR published for the target: nothing to compare.
      continue
    fi
    local_ptr=$(system_ptr_answer "$ip")
    if [[ -z "$local_ptr" ]]; then
      # The reference has a PTR, the system resolver stays silent: the
      # reverse answer is filtered.
      print_value_or_colored "No" "HEART"
      return
    fi
    local_ptr="${local_ptr%.}"
    local_ptr="${local_ptr,,}"
    if ! grep_wrapper -qxF "$local_ptr" <<<"$doh_ptr"; then
      print_value_or_colored "No" "HEART"
      return
    fi
  done
  print_value_or_colored "Yes" "SERVICE"
}

# DNSSEC validation diagnostic: dnssec-failed.org carries deliberately
# broken signatures, so a validating resolver must fail the lookup
# (SERVFAIL) while a non-validating one happily serves records. The
# DoH-JSON reference (Cloudflare, then Google - both validating) confirms
# the canary is still broken before anything is concluded. Yes = the
# system resolver validates, No = it serves records for a
# broken-signature domain, N/A = reference unreachable or the canary no
# longer broken.
lookup_dnssec_validation() {
  local ip_version="$1"
  local canary="dnssec-failed.org"
  local doh_answer system_answer

  doh_answer=$(doh_dns_answers "$canary" "A" "$ip_version") || {
    echo "$STATUS_NA"
    return
  }
  if [[ -n "$doh_answer" ]]; then
    # The TLS reference resolves the canary: its signatures are no longer
    # broken - nothing to verify against.
    echo "$STATUS_NA"
    return
  fi
  system_answer=$(system_dns_answers "$canary" "A")
  if [[ -n "$system_answer" ]]; then
    # Records served for a domain with broken signatures: the resolver
    # does not validate DNSSEC.
    print_value_or_colored "No" "HEART"
    return
  fi
  # Resolution failed while the reference confirms the breakage: the
  # resolver validates signatures.
  print_value_or_colored "Yes" "SERVICE"
}

# Private-DNS leak diagnostic: the major public services must never
# resolve into private address space (RFC1918, loopback, CGNAT,
# link-local). Any private answer from the system resolver for one of
# them is an injection - a captive portal, corporate middleware or
# malware DNS steering clients into internal space. No DoH reference is
# needed: these names are public by construction. Yes = public answers
# everywhere, No = private injection detected, N/A = nothing resolved.
lookup_public_answers() {
  local ip_version="$1"
  local -a probe_domains=(
    "google.com"
    "youtube.com"
    "facebook.com"
    "github.com"
    "cloudflare.com"
    "wikipedia.org"
    "apple.com"
    "microsoft.com"
  )
  local domain answers answer answered=0

  for domain in "${probe_domains[@]}"; do
    answers=$(system_dns_answers "$domain" "A")
    while IFS= read -r answer; do
      [[ -z "$answer" ]] && continue
      answered=1
      if is_nonpublic_ipv4 "$answer"; then
        print_value_or_colored "No" "HEART"
        return
      fi
    done <<<"$answers"
  done
  if [[ "$answered" != 1 ]]; then
    # Not a single public name resolved: there is nothing to judge.
    echo "$STATUS_NA"
    return
  fi
  print_value_or_colored "Yes" "SERVICE"
}

# TTL honesty diagnostic: a caching resolver serves answers with
# DECREMENTING TTLs. The system resolver's TTL for a stable canary is
# sampled twice; the DoH reference must age its own answer over the same
# gap, otherwise the verdict is inconclusive. Yes = TTLs decrement
# (cached, honest), No = a constant TTL is served - the client-visible
# signature of TTL substitution (clamped or rewritten) or of a
# non-caching forwarder, N/A = TTLs unreadable or inconclusive
# reference.
lookup_dns_ttl() {
  local ip_version="$1"
  local canary="dns.google"
  local ttl_gap="${DNS_TTL_GAP:-15}"
  local first second doh_first doh_second

  first=$(system_dns_ttl "$canary")
  if [[ -z "$first" ]]; then
    echo "$STATUS_NA"
    return
  fi
  doh_first=$(doh_dns_ttl "$canary" "$ip_version")
  if [[ -z "$doh_first" ]]; then
    echo "$STATUS_NA"
    return
  fi
  sleep "$ttl_gap"
  second=$(system_dns_ttl "$canary")
  doh_second=$(doh_dns_ttl "$canary" "$ip_version")
  if [[ -z "$second" || -z "$doh_second" ]]; then
    echo "$STATUS_NA"
    return
  fi
  if ((second < first)); then
    # The system resolver aged its own answer: honest caching, whatever
    # the reference did mid-gap.
    print_value_or_colored "Yes" "SERVICE"
    return
  fi
  if ((doh_second < doh_first)); then
    # The reference aged, the system resolver served a constant TTL:
    # rewritten, clamped, or a non-caching forwarder.
    print_value_or_colored "No" "HEART"
    return
  fi
  # The reference refreshed its answer mid-gap and the system resolver
  # served a constant: ambiguous, report rather than guess.
  echo "$STATUS_NA"
}

# Multi-resolver consensus diagnostic: two fixed canaries (dns.google,
# one.one.one.one) asked directly at three independent public resolvers
# (Google, Cloudflare, Quad9) must all return answers from the DoH
# reference set. An answer outside it is divergence - some resolver in
# the path serves something else than the authoritative chain. Fewer
# than two reachable resolvers cannot form a consensus: N/A. Yes = all
# reachable resolvers agree, No = divergence detected.
lookup_resolver_consensus() {
  local ip_version="$1"
  local -a resolvers=("8.8.8.8" "1.1.1.1" "9.9.9.9")
  local -a canaries=("dns.google" "one.one.one.one")
  local resolver canary reachable=0 resolver_ok
  local -a refs=()
  local reference answers answer

  for canary in "${canaries[@]}"; do
    reference=$(doh_dns_answers "$canary" "A" "$ip_version") || {
      echo "$STATUS_NA"
      return
    }
    refs+=("$reference")
  done

  for resolver in "${resolvers[@]}"; do
    resolver_ok=0
    for canary in "${canaries[@]}"; do
      answers=$(server_dns_answers "$canary" "$resolver")
      [[ -z "$answers" ]] && continue
      resolver_ok=1
      if [[ "$canary" == "dns.google" ]]; then
        reference="${refs[0]}"
      else
        reference="${refs[1]}"
      fi
      while IFS= read -r answer; do
        [[ -z "$answer" ]] && continue
        if ! grep_wrapper -qxF "$answer" <<<"$reference"; then
          print_value_or_colored "No" "HEART"
          return
        fi
      done <<<"$answers"
    done
    [[ "$resolver_ok" == 1 ]] && reachable=$((reachable + 1))
  done
  if ((reachable < 2)); then
    echo "$STATUS_NA"
    return
  fi
  print_value_or_colored "Yes" "SERVICE"
}

# DNS latency diagnostic: reports the system resolver's round-trip for a
# stable canary next to the same lookup through the DoH reference
# ("local/doh" milliseconds). Both sides include tool startup, so the
# numbers compare like for like. N/A when the platform cannot measure
# (bash < 5) or either lookup fails.
lookup_dns_latency() {
  local ip_version="$1"
  local canary="dns.google"
  local local_ms doh_ms

  local_ms=$(system_dns_latency_ms "$canary")
  doh_ms=$(doh_dns_latency_ms "$canary" "$ip_version")
  if [[ -z "$local_ms" || -z "$doh_ms" ]]; then
    echo "$STATUS_NA"
    return
  fi
  # --metrics integration: the IPv4 pass reports the system-resolver
  # time, the IPv6 pass the DoH reference time.
  if [[ -n "${CURL_META_FILE:-}" ]]; then
    if [[ "$ip_version" == "6" ]]; then
      printf 'http_code=200;latency_ms=%d;transport_ip_version=%s;error_type=none\n' "$doh_ms" "$ip_version" >"$CURL_META_FILE"
    else
      printf 'http_code=200;latency_ms=%d;transport_ip_version=%s;error_type=none\n' "$local_ms" "$ip_version" >"$CURL_META_FILE"
    fi
  fi
  printf '%d/%d ms' "$local_ms" "$doh_ms"
}

# DNS jitter diagnostic: three timed system-resolver lookups for a
# stable canary; the spread (max - min) shows whether the resolver
# answers with consistent latency or fluctuates. Verdict "±N ms";
# N/A when the platform cannot measure (bash < 5) or a lookup fails.
lookup_dns_jitter() {
  local ip_version="$1"
  local canary="dns.google"
  local gap="${DNS_JITTER_GAP:-1}"
  local -a sys=() doh=()
  local i s d j_l j_d median
  for i in 1 2 3; do
    s=$(system_dns_latency_ms "$canary")
    d=$(doh_dns_latency_ms "$canary" "$ip_version")
    [[ -z "$s" || -z "$d" ]] && {
      echo "$STATUS_NA"
      return
    }
    sys+=("$s")
    doh+=("$d")
    [[ "$i" -lt 3 ]] && sleep "$gap"
  done
  j_l=$(spread3 "${sys[0]}" "${sys[1]}" "${sys[2]}")
  j_d=$(spread3 "${doh[0]}" "${doh[1]}" "${doh[2]}")
  # --metrics integration: the IPv4 pass reports the median system
  # sample, the IPv6 pass the median DoH sample.
  if [[ -n "${CURL_META_FILE:-}" ]]; then
    if [[ "$ip_version" == "6" ]]; then
      median=$(median3 "${doh[0]}" "${doh[1]}" "${doh[2]}")
    else
      median=$(median3 "${sys[0]}" "${sys[1]}" "${sys[2]}")
    fi
    printf 'http_code=200;latency_ms=%d;transport_ip_version=%s;error_type=none\n' "$median" "$ip_version" >"$CURL_META_FILE"
  fi
  printf '±%d/±%d ms' "$j_l" "$j_d"
}

# DNS rebinding diagnostic through the public 1u.ms canary: the first
# query for a fresh canary name resolves to a public IP and every query
# within the following five seconds resolves to 127.0.0.1 (TTL 0, so
# honest resolvers re-fetch each time). A resolver that serves the
# loopback answer is vulnerable to rebinding; one that keeps serving the
# public answer (clamped caching or filtering) is protected. N/A when
# the canary never answers (service down or blocked upstream).
lookup_rebind_protection() {
  local ip_version="$1"
  local canary="ipregion-$$-$RANDOM-make-93-184-216-34-rebind-127-0-0-1-rr.1u.ms"
  local answers answer saw_public=0 saw_private=0 sample

  for sample in 1 2 3 4; do
    answers=$(system_dns_answers "$canary" "A")
    while IFS= read -r answer; do
      [[ -z "$answer" ]] && continue
      if is_nonpublic_ipv4 "$answer"; then
        saw_private=1
      else
        saw_public=1
      fi
    done <<<"$answers"
    [[ "$saw_private" == 1 ]] && break
    [[ "$sample" -lt 4 ]] && sleep 1
  done
  if [[ "$saw_private" != 1 && "$saw_public" != 1 ]]; then
    # Not a single answer for a fresh canary name: service down or
    # blocked upstream.
    echo "$STATUS_NA"
    return
  fi
  if [[ "$saw_private" == 1 ]]; then
    print_value_or_colored "No" "HEART"
    return
  fi
  print_value_or_colored "Yes" "SERVICE"
}

# Proxy egress diagnostic: with a proxy configured (--proxy or the
# standard proxy env vars), reports the country the proxy exits from
# (the same geo the proxied checks see). No = the proxy did not answer
# (dead, blocked, or unauthenticated) - the row is most useful in
# --watch, where a flip from a country to No means the proxy just died.
# N/A = no proxy configured, nothing to check.
lookup_proxy_egress() {
  if [[ -z "$PROXY_ADDR" && -z "${ALL_PROXY:-}" && -z "${HTTPS_PROXY:-}" && -z "${https_proxy:-}" && -z "${HTTP_PROXY:-}" && -z "${http_proxy:-}" ]]; then
    echo "$STATUS_NA"
    return
  fi
  local response country
  response=$(curl_wrapper GET "https://api.country.is/" --header "Accept: application/json")
  [[ -z "$response" ]] && {
    print_value_or_colored "No" "HEART"
    return
  }
  country=$(process_json "$response" '.country // empty' 2>/dev/null)
  if [[ -z "$country" ]]; then
    print_value_or_colored "No" "HEART"
    return
  fi
  printf '%s' "$country"
}

# Resolver latency diagnostic: round-trip of one direct dns.google query
# to each of the three independent public resolvers (Google, Cloudflare,
# Quad9), reported as "G/C/Q ms". A resolver that does not answer is
# shown as "-"; N/A only when none of the three answered or the platform
# cannot measure. Informational verdict, no failure semantics.
lookup_resolver_latency() {
  local ip_version="$1"
  local -a resolvers=("8.8.8.8" "1.1.1.1" "9.9.9.9")
  local resolver ms out="" any=0 total=0 answered=0
  local -a ms_values=()

  for resolver in "${resolvers[@]}"; do
    ms=$(server_dns_latency_ms "dns.google" "$resolver")
    if [[ -z "$ms" ]]; then
      out+="-/"
      ms_values+=(0)
    else
      out+="$ms/"
      ms_values+=("$ms")
      total=$((total + ms))
      answered=$((answered + 1))
      any=1
    fi
  done
  out="${out%/} ms"
  if [[ "$any" != 1 ]]; then
    echo "$STATUS_NA"
    return
  fi
  # --metrics integration: the average round-trip across the resolvers
  # that answered.
  if [[ -n "${CURL_META_FILE:-}" && "$answered" -gt 0 ]]; then
    printf 'http_code=200;latency_ms=%d;transport_ip_version=%s;error_type=none\n' "$((total / answered))" "$ip_version" >"$CURL_META_FILE"
  fi
  printf '%s' "$out"
}

# Resolver jitter diagnostic: each of the three independent public
# resolvers is sampled twice with a direct dns.google query; the worst
# per-resolver spread (|first - second|) is reported as "±N ms". A
# tight spread means the resolver answers consistently; a wide spread
# means it fluctuates. N/A when fewer than two resolvers answer or the
# platform cannot measure.
lookup_resolver_jitter() {
  local -a resolvers=("8.8.8.8" "1.1.1.1" "9.9.9.9")
  local resolver worst=0 pairs=0 j s1 s2
  for resolver in "${resolvers[@]}"; do
    s1=$(server_dns_latency_ms "dns.google" "$resolver")
    s2=$(server_dns_latency_ms "dns.google" "$resolver")
    [[ -z "$s1" || -z "$s2" ]] && continue
    pairs=$((pairs + 1))
    j=$(((s1 > s2) ? s1 - s2 : s2 - s1))
    ((j > worst)) && worst=$j
  done
  if ((pairs < 2)); then
    echo "$STATUS_NA"
    return
  fi
  printf '±%d ms' "$worst"
}

# DoH availability through the configured proxy (--proxy or the standard
# proxy env vars): both reference DoH JSON endpoints (Google, Cloudflare)
# must answer a valid DNS query through the proxy. Yes = DoH works
# through it; No = an endpoint failed or returned garbage through it;
# N/A = no proxy configured (direct DoH is covered by DNS Integrity's
# reference lookups).
lookup_doh_via_proxy() {
  if [[ -z "$PROXY_ADDR" && -z "${ALL_PROXY:-}" && -z "${HTTPS_PROXY:-}" && -z "${https_proxy:-}" && -z "${HTTP_PROXY:-}" && -z "${http_proxy:-}" ]]; then
    echo "$STATUS_NA"
    return
  fi
  local -a endpoints=(
    "https://dns.google/resolve?name=dns.google&type=A"
    "https://cloudflare-dns.com/dns-query?name=dns.google&type=A"
  )
  local endpoint response
  for endpoint in "${endpoints[@]}"; do
    response=$(curl_wrapper GET "$endpoint" --header "Accept: application/dns-json")
    [[ -z "$response" ]] && {
      print_value_or_colored "No" "HEART"
      return
    }
    [[ "$(process_json "$response" '.Status // empty' 2>/dev/null)" == "0" ]] || {
      print_value_or_colored "No" "HEART"
      return
    }
  done
  print_value_or_colored "Yes" "SERVICE"
}

lookup_site_access() {
  local url="$1"
  local marker="$2"
  local ip_version="$3"
  local response error_type

  if ! host_resolves "$(url_host "$url")"; then
    # Nothing resolved at the resolver: report the DNS-poisoning signature
    # instead of an indistinguishable transport failure.
    print_value_or_colored "DNS block" "WARN"
    return
  fi

  response=$(curl_wrapper GET "$url" \
    --user-agent "$USER_AGENT" \
    --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
    --header "Accept-Language: en-US,en;q=0.9" \
    --header "Sec-Fetch-Dest: document" \
    --header "Sec-Fetch-Mode: navigate" \
    --header "Sec-Fetch-Site: none" \
    --header "Sec-Fetch-User: ?1" \
    --header "Upgrade-Insecure-Requests: 1" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    # A transport-level failure (connection reset or timeout) is the typical
    # blocking signature for a site in restricted networks.
    error_type=$(read_curl_metric_field "$CURL_META_FILE" "error_type")
    if [[ "$error_type" == "curl_error" ]]; then
      print_value_or_colored "No" "HEART"
      return
    fi
    echo ""
    return
  fi

  if is_status_string "$response"; then
    echo "$response"
    return
  fi

  if grep_wrapper -qi "$marker" <<<"$response"; then
    print_value_or_colored "Yes" "SERVICE"
  else
    print_value_or_colored "No" "HEART"
  fi
}

# Availability via a region-gated landing page: the gate marker (e.g.
# "Unavailable In Your Region") means No; the brand marker means Yes.
lookup_region_gate_access() {
  local url="$1"
  local gate_marker="$2"
  local brand_marker="$3"
  local ip_version="$4"
  local response error_type

  if ! host_resolves "$(url_host "$url")"; then
    print_value_or_colored "DNS block" "WARN"
    return
  fi

  response=$(curl_wrapper GET "$url" \
    --user-agent "$USER_AGENT" \
    --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
    --header "Accept-Language: en-US,en;q=0.9" \
    --header "Sec-Fetch-Dest: document" \
    --header "Sec-Fetch-Mode: navigate" \
    --header "Sec-Fetch-Site: none" \
    --header "Sec-Fetch-User: ?1" \
    --header "Upgrade-Insecure-Requests: 1" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    error_type=$(read_curl_metric_field "$CURL_META_FILE" "error_type")
    if [[ "$error_type" == "curl_error" ]]; then
      print_value_or_colored "No" "HEART"
      return
    fi
    echo ""
    return
  fi

  if is_status_string "$response"; then
    echo "$response"
    return
  fi

  if grep_wrapper -qi "$gate_marker" <<<"$response"; then
    print_value_or_colored "No" "HEART"
  elif grep_wrapper -qi "$brand_marker" <<<"$response"; then
    print_value_or_colored "Yes" "SERVICE"
  else
    print_value_or_colored "No" "HEART"
  fi
}

lookup_instagram() {
  lookup_site_access "https://www.instagram.com/" "instagram" "$1"
}

lookup_tiktok_access() {
  lookup_site_access "https://www.tiktok.com/" "tiktok" "$1"
}

lookup_whatsapp() {
  lookup_site_access "https://www.whatsapp.com/" "whatsapp" "$1"
}

lookup_telegram_access() {
  lookup_site_access "https://web.telegram.org/k/" "telegram" "$1"
}

# Yes when any target in the named array accepts a TCP connection; "DNS block"
# when every failing target also failed to resolve.
lookup_tcp_targets() {
  local -n probe_targets="$1"
  local target
  local dns_blocked=false

  for target in "${probe_targets[@]}"; do
    if ! host_resolves "${target%%:*}"; then
      dns_blocked=true
      continue
    fi
    if tcp_probe "${target%%:*}" "${target##*:}" 3; then
      print_value_or_colored "Yes" "SERVICE"
      return
    fi
  done

  if [[ "$dns_blocked" == true ]]; then
    print_value_or_colored "DNS block" "WARN"
  else
    print_value_or_colored "No" "HEART"
  fi
}

lookup_telegram_dc() {
  lookup_tcp_targets TELEGRAM_DC_PROBE_TARGETS
}

lookup_whatsapp_dc() {
  lookup_tcp_targets WHATSAPP_PROBE_TARGETS
}

lookup_discord_gateway() {
  lookup_tcp_targets DISCORD_PROBE_TARGETS
}

lookup_discord_access() {
  lookup_site_access "https://discord.com/" "discord" "$1"
}

lookup_twitter() {
  lookup_site_access "https://x.com/" "x.com" "$1"
}

lookup_linkedin_access() {
  lookup_site_access "https://www.linkedin.com/" "linkedin" "$1"
}

lookup_facebook_access() {
  lookup_site_access "https://www.facebook.com/" "facebook" "$1"
}

lookup_messenger_access() {
  lookup_site_access "https://www.messenger.com/" "messenger" "$1"
}

lookup_threads_access() {
  lookup_site_access "https://www.threads.com/" "threads" "$1"
}

lookup_signal_access() {
  lookup_site_access "https://signal.org/" "signal" "$1"
}

lookup_douyin_cn() {
  dns_unresolved "www.douyin.com" && return
  local ip_version="$1"
  local response error_type

  response=$(curl_wrapper GET "https://www.douyin.com/" \
    --user-agent "$USER_AGENT" \
    --header "Accept-Language: en-US,en;q=0.9" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    error_type=$(read_curl_metric_field "$CURL_META_FILE" "error_type")
    if [[ "$error_type" == "curl_error" ]]; then
      print_value_or_colored "No" "HEART"
      return
    fi
    echo ""
    return
  fi

  if is_status_string "$response"; then
    echo "$response"
    return
  fi

  # CN egress gets the SSR page with douyin content; any other egress gets an
  # obfuscated bot-shell without a single douyin marker (region gate).
  if grep_wrapper -qiE "抖音|douyin" <<<"$response"; then
    print_value_or_colored "Yes" "SERVICE"
  else
    print_value_or_colored "No" "HEART"
  fi
}

lookup_vk() {
  lookup_site_access "https://vk.com/" "vk.com" "$1"
}

lookup_ok_ru() {
  lookup_site_access "https://ok.ru/" "ok.ru" "$1"
}

lookup_grok() {
  lookup_site_access "https://grok.com/" "grok" "$1"
}

lookup_deepseek() {
  lookup_site_access "https://chat.deepseek.com/" "deepseek" "$1"
}

lookup_perplexity() {
  lookup_site_access "https://www.perplexity.ai/" "perplexity" "$1"
}

lookup_copilot() {
  lookup_site_access "https://copilot.microsoft.com/" "copilot" "$1"
}

lookup_mistral() {
  lookup_site_access "https://mistral.ai/" "mistral" "$1"
}

lookup_qwen_web() {
  lookup_site_access "https://chat.qwen.ai/" "qwen" "$1"
}

lookup_peacock_access() {
  lookup_region_gate_access "https://www.peacocktv.com/" "Unavailable In Your Region" "peacock" "$1"
}

# Streaming family: Hulu is a redirect gate (non-covered regions land on a
# Disney+ "not available in your region" page); the rest are reachability
# pages. Viki reports No from regions where Rakuten suspended service.
lookup_hulu() {
  lookup_region_gate_access "https://www.hulu.com/" "not available in your region" "hulu" "$1"
}

lookup_paramount_plus() {
  lookup_site_access "https://www.paramountplus.com/" "paramount" "$1"
}

lookup_apple_tv_plus() {
  lookup_site_access "https://tv.apple.com/" "apple tv" "$1"
}

lookup_pluto_tv() {
  lookup_site_access "https://pluto.tv/" "pluto" "$1"
}

lookup_discovery_plus() {
  lookup_site_access "https://www.discoveryplus.com/" "discovery" "$1"
}

lookup_tubi() {
  lookup_site_access "https://tubitv.com/" "tubi" "$1"
}

lookup_mubi() {
  lookup_site_access "https://mubi.com/" "mubi" "$1"
}

lookup_viki() {
  lookup_site_access "https://www.viki.com/" "rakuten viki" "$1"
}

lookup_iqiyi() {
  lookup_site_access "https://www.iq.com/" "iqiyi" "$1"
}

lookup_plex() {
  lookup_site_access "https://watch.plex.tv/" "plex" "$1"
}

lookup_kick() {
  lookup_site_access "https://kick.com/" "kick" "$1"
}

lookup_bluesky() {
  lookup_site_access "https://bsky.app/" "bluesky" "$1"
}

lookup_snapchat() {
  lookup_site_access "https://snapchat.com/" "snapchat" "$1"
}

lookup_pinterest() {
  lookup_site_access "https://pinterest.com/" "pinterest" "$1"
}

lookup_truth_social() {
  lookup_site_access "https://truthsocial.com/" "truthsocial" "$1"
}

lookup_weibo() {
  lookup_site_access "https://weibo.com/" "weibo" "$1"
}

lookup_bilibili() {
  lookup_site_access "https://bilibili.com/" "bilibili" "$1"
}

lookup_netease_music() {
  lookup_site_access "https://music.163.com/" "163" "$1"
}

lookup_twitch_site() {
  lookup_site_access "https://twitch.tv/" "twitch" "$1"
}

lookup_yandex() {
  lookup_site_access "https://yandex.ru/" "yandex" "$1"
}

lookup_mail_ru() {
  lookup_site_access "https://mail.ru/" "mail.ru" "$1"
}

lookup_github() {
  lookup_site_access "https://github.com/" "github" "$1"
}

lookup_bing() {
  lookup_site_access "https://bing.com/" "bing" "$1"
}

lookup_duckduckgo() {
  lookup_site_access "https://duckduckgo.com/" "duckduckgo" "$1"
}

lookup_brave_search() {
  lookup_site_access "https://search.brave.com/" "brave" "$1"
}

lookup_wechat() {
  lookup_site_access "https://weixin.qq.com/" "weixin" "$1"
}

lookup_baidu() {
  lookup_site_access "https://www.baidu.com/" "baidu" "$1"
}

lookup_alipay() {
  lookup_site_access "https://www.alipay.com/" "alipay" "$1"
}

lookup_notion() {
  lookup_site_access "https://www.notion.so/" "notion" "$1"
}

lookup_figma() {
  lookup_site_access "https://www.figma.com/" "figma" "$1"
}

lookup_miro() {
  lookup_site_access "https://miro.com/" "miro" "$1"
}

lookup_canva() {
  lookup_site_access "https://www.canva.com/" "canva" "$1"
}

lookup_trello() {
  lookup_site_access "https://trello.com/" "trello" "$1"
}

lookup_medium() {
  lookup_site_access "https://medium.com/" "medium" "$1"
}

lookup_wikipedia() {
  lookup_site_access "https://www.wikipedia.org/" "wikipedia" "$1"
}

lookup_stack_overflow() {
  lookup_site_access "https://stackoverflow.com/" "stackoverflow" "$1"
}

lookup_habr() {
  lookup_site_access "https://habr.com/" "habr" "$1"
}

lookup_deepl() {
  lookup_region_gate_access "https://www.deepl.com/" "Unavailable in your region" "deepl" "$1"
}

lookup_character_ai() {
  lookup_site_access "https://character.ai/" "character" "$1"
}

lookup_poe() {
  lookup_site_access "https://poe.com/" "poe" "$1"
}

lookup_google_translate() {
  lookup_site_access "https://translate.google.com/" "translate" "$1"
}

lookup_instagram_api() {
  lookup_tcp_targets INSTAGRAM_API_PROBE_TARGETS
}

lookup_threads_api() {
  lookup_tcp_targets THREADS_PROBE_TARGETS
}

lookup_signal_service() {
  lookup_tcp_targets SIGNAL_PROBE_TARGETS
}

lookup_vk_api() {
  lookup_tcp_targets VK_PROBE_TARGETS
}

lookup_openai_api() {
  lookup_tcp_targets OPENAI_API_PROBE_TARGETS
}

lookup_anthropic_api() {
  lookup_tcp_targets ANTHROPIC_API_PROBE_TARGETS
}

lookup_xai_api() {
  lookup_tcp_targets XAI_API_PROBE_TARGETS
}

lookup_deepseek_api() {
  lookup_tcp_targets DEEPSEEK_API_PROBE_TARGETS
}

lookup_perplexity_api() {
  lookup_tcp_targets PERPLEXITY_API_PROBE_TARGETS
}

lookup_mistral_api() {
  lookup_tcp_targets MISTRAL_API_PROBE_TARGETS
}

lookup_reddit_api() {
  lookup_tcp_targets REDDIT_API_PROBE_TARGETS
}

lookup_ok_api() {
  lookup_tcp_targets OK_API_PROBE_TARGETS
}

lookup_linkedin_api() {
  lookup_tcp_targets LINKEDIN_API_PROBE_TARGETS
}

lookup_x_api() {
  lookup_tcp_targets X_API_PROBE_TARGETS
}

lookup_twitter_legacy_api() {
  lookup_tcp_targets TWITTER_LEGACY_API_PROBE_TARGETS
}

lookup_youtube_api() {
  lookup_tcp_targets YOUTUBE_API_PROBE_TARGETS
}

lookup_github_raw() {
  lookup_tcp_targets GITHUB_RAW_PROBE_TARGETS
}

lookup_github_codeload() {
  lookup_tcp_targets GITHUB_CODELOAD_PROBE_TARGETS
}

lookup_npm_registry() {
  lookup_tcp_targets NPM_REGISTRY_PROBE_TARGETS
}

lookup_pypi() {
  lookup_tcp_targets PYPI_PROBE_TARGETS
}

lookup_docker_hub() {
  lookup_tcp_targets DOCKER_HUB_PROBE_TARGETS
}

lookup_hugging_face() {
  lookup_tcp_targets HUGGING_FACE_PROBE_TARGETS
}

lookup_twitch_api() {
  lookup_tcp_targets TWITCH_API_PROBE_TARGETS
}

lookup_twitch_chat() {
  lookup_tcp_targets TWITCH_CHAT_PROBE_TARGETS
}

lookup_facebook_cdn() {
  lookup_tcp_targets FACEBOOK_CDN_PROBE_TARGETS
}

lookup_groq_api() {
  lookup_tcp_targets GROQ_API_PROBE_TARGETS
}

lookup_openrouter() {
  lookup_tcp_targets OPENROUTER_PROBE_TARGETS
}

lookup_cohere_api() {
  lookup_tcp_targets COHERE_API_PROBE_TARGETS
}

lookup_elevenlabs_api() {
  lookup_tcp_targets ELEVENLABS_API_PROBE_TARGETS
}

lookup_teams() {
  lookup_tcp_targets TEAMS_PROBE_TARGETS
}

lookup_outlook() {
  lookup_tcp_targets OUTLOOK_PROBE_TARGETS
}

lookup_azure_portal() {
  lookup_tcp_targets AZURE_PORTAL_PROBE_TARGETS
}

lookup_viber() {
  lookup_tcp_targets VIBER_PROBE_TARGETS
}

lookup_slack() {
  lookup_tcp_targets SLACK_PROBE_TARGETS
}

lookup_zoom() {
  lookup_tcp_targets ZOOM_PROBE_TARGETS
}

lookup_line() {
  lookup_tcp_targets LINE_PROBE_TARGETS
}

lookup_doh_google() {
  lookup_tcp_targets DOH_GOOGLE_PROBE_TARGETS
}

lookup_doh_cloudflare() {
  lookup_tcp_targets DOH_CLOUDFLARE_PROBE_TARGETS
}

lookup_dot_google() {
  lookup_tcp_targets DOT_GOOGLE_PROBE_TARGETS
}

lookup_dot_cloudflare() {
  lookup_tcp_targets DOT_CLOUDFLARE_PROBE_TARGETS
}

lookup_gmail() {
  lookup_tcp_targets GMAIL_PROBE_TARGETS
}

lookup_proton() {
  lookup_tcp_targets PROTON_PROBE_TARGETS
}

lookup_google_drive() {
  lookup_tcp_targets GOOGLE_DRIVE_PROBE_TARGETS
}

lookup_dropbox() {
  lookup_tcp_targets DROPBOX_PROBE_TARGETS
}

lookup_onedrive() {
  lookup_tcp_targets ONEDRIVE_PROBE_TARGETS
}

lookup_mega() {
  lookup_tcp_targets MEGA_PROBE_TARGETS
}

lookup_epic_games() {
  lookup_tcp_targets EPIC_GAMES_PROBE_TARGETS
}

lookup_battle_net() {
  lookup_tcp_targets BATTLE_NET_PROBE_TARGETS
}

lookup_roblox() {
  lookup_tcp_targets ROBLOX_PROBE_TARGETS
}

lookup_riot() {
  lookup_tcp_targets RIOT_PROBE_TARGETS
}

lookup_xbox() {
  lookup_tcp_targets XBOX_PROBE_TARGETS
}

lookup_app_store() {
  lookup_tcp_targets APP_STORE_PROBE_TARGETS
}

lookup_play_store() {
  lookup_tcp_targets PLAY_STORE_PROBE_TARGETS
}

lookup_aws() {
  lookup_tcp_targets AWS_PROBE_TARGETS
}

lookup_gcp_console() {
  lookup_tcp_targets GCP_CONSOLE_PROBE_TARGETS
}

lookup_oracle_cloud() {
  lookup_tcp_targets ORACLE_CLOUD_PROBE_TARGETS
}

lookup_stripe_api() {
  lookup_tcp_targets STRIPE_API_PROBE_TARGETS
}

lookup_paypal() {
  lookup_tcp_targets PAYPAL_PROBE_TARGETS
}

lookup_wise() {
  lookup_tcp_targets WISE_PROBE_TARGETS
}

lookup_gemini_api() {
  lookup_tcp_targets GEMINI_API_PROBE_TARGETS
}

lookup_ai_studio() {
  lookup_tcp_targets AI_STUDIO_PROBE_TARGETS
}

lookup_google_meet() {
  lookup_tcp_targets GOOGLE_MEET_PROBE_TARGETS
}

lookup_google_photos() {
  lookup_tcp_targets GOOGLE_PHOTOS_PROBE_TARGETS
}

lookup_google_calendar() {
  lookup_tcp_targets GOOGLE_CALENDAR_PROBE_TARGETS
}

lookup_youtube_music() {
  lookup_tcp_targets YOUTUBE_MUSIC_PROBE_TARGETS
}

lookup_apple_music() {
  lookup_tcp_targets APPLE_MUSIC_PROBE_TARGETS
}

lookup_soundcloud() {
  lookup_tcp_targets SOUNDCLOUD_PROBE_TARGETS
}

lookup_deezer() {
  lookup_tcp_targets DEEZER_PROBE_TARGETS
}

lookup_discord_cdn() {
  lookup_tcp_targets DISCORD_CDN_PROBE_TARGETS
}

lookup_minecraft_session() {
  lookup_tcp_targets MINECRAFT_SESSION_PROBE_TARGETS
}

lookup_roblox_api() {
  lookup_tcp_targets ROBLOX_API_PROBE_TARGETS
}

lookup_wechat_api() {
  lookup_tcp_targets WECHAT_API_PROBE_TARGETS
}

lookup_kakaotalk() {
  lookup_tcp_targets KAKAOTALK_PROBE_TARGETS
}

lookup_threema() {
  lookup_tcp_targets THREEMA_PROBE_TARGETS
}

lookup_docker_hub_api() {
  lookup_tcp_targets DOCKER_HUB_API_PROBE_TARGETS
}

lookup_go_modules() {
  lookup_tcp_targets GO_MODULES_PROBE_TARGETS
}

lookup_crates_io() {
  lookup_tcp_targets CRATES_IO_PROBE_TARGETS
}

lookup_maven_central() {
  lookup_tcp_targets MAVEN_CENTRAL_PROBE_TARGETS
}

lookup_hetzner() {
  lookup_tcp_targets HETZNER_PROBE_TARGETS
}

lookup_digitalocean() {
  lookup_tcp_targets DIGITALOCEAN_PROBE_TARGETS
}

lookup_vultr() {
  lookup_tcp_targets VULTR_PROBE_TARGETS
}

lookup_matrix() {
  lookup_tcp_targets MATRIX_PROBE_TARGETS
}

lookup_ntfy() {
  lookup_tcp_targets NTFY_PROBE_TARGETS
}

lookup_telegram_bot_api() {
  lookup_tcp_targets TELEGRAM_BOT_API_PROBE_TARGETS
}

lookup_workers_dev() {
  lookup_tcp_targets WORKERS_DEV_PROBE_TARGETS
}

lookup_github_pages() {
  lookup_tcp_targets GITHUB_PAGES_PROBE_TARGETS
}

lookup_gitlab_pages() {
  lookup_tcp_targets GITLAB_PAGES_PROBE_TARGETS
}

lookup_vercel_app() {
  lookup_tcp_targets VERCEL_APP_PROBE_TARGETS
}

lookup_netlify_app() {
  lookup_tcp_targets NETLIFY_APP_PROBE_TARGETS
}

lookup_pages_dev() {
  lookup_tcp_targets PAGES_DEV_PROBE_TARGETS
}

lookup_heroku_app() {
  lookup_tcp_targets HEROKU_APP_PROBE_TARGETS
}

# Days remaining until the TLS certificate of a host expires (integer,
# floor; negative when already expired); empty when openssl is missing,
# the host is unreachable, or the dates cannot be parsed. The target is
# CERT_EXPIRY_HOST (default: this project's site) - point it at your own
# domain to monitor your certificates.
# Certificate notAfter line, with the TLS session bounded to ~10 s. A
# TCP-accepting endpoint that never completes the handshake (tarpit,
# middlebox) otherwise blocks openssl s_client forever - it honors no
# proxy env and has no built-in timeout.
tls_notafter() {
  local host="$1"
  local port="$2"
  local cert_tmp cert_pid waited=0
  command -v openssl >/dev/null 2>&1 || return 1
  cert_tmp=$(mktemp)
  (
    echo | openssl s_client -servername "$host" -connect "$host:$port" >"$cert_tmp" 2>/dev/null &
    child=$!
    trap 'kill -TERM "$child" 2>/dev/null' TERM
    wait "$child"
  ) &
  cert_pid=$!
  while kill -0 "$cert_pid" 2>/dev/null && ((waited < 100)); do
    sleep 0.1
    waited=$((waited + 1))
  done
  if kill -0 "$cert_pid" 2>/dev/null; then
    kill -TERM "$cert_pid" 2>/dev/null
    wait "$cert_pid" 2>/dev/null
    rm -f "$cert_tmp"
    return 1
  fi
  wait "$cert_pid" 2>/dev/null
  openssl x509 -noout -enddate 2>/dev/null <"$cert_tmp"
  rm -f "$cert_tmp"
}

cert_days_remaining() {
  local host="$1"
  local end_line end_date end_s now days
  command -v openssl >/dev/null 2>&1 || {
    echo ""
    return
  }
  end_line=$(tls_notafter "$host" 443)
  end_date="${end_line#notAfter=}"
  [[ -z "$end_date" || "$end_date" == "$end_line" ]] && {
    echo ""
    return
  }
  # notAfter is "Mmm D HH:MM:SS YYYY GMT"; parse it as UTC. macOS BSD
  # date needs -j -u and rejects %Z, GNU date takes -d directly.
  end_s=$(date -ju -f "%b %e %T %Y" "${end_date% GMT}" "+%s" 2>/dev/null)
  [[ -z "$end_s" ]] && end_s=$(date -ud "$end_date" "+%s" 2>/dev/null)
  [[ -z "$end_s" ]] && {
    echo ""
    return
  }
  now=$(date -u "+%s")
  echo $(((end_s - now) / 86400))
}

# TLS certificate expiry for CERT_EXPIRY_HOST (env-configurable target,
# default: this project's site - point CERT_EXPIRY_HOST at your own
# domain to monitor it). Verdict thresholds: Expired / <=14 days (red),
# <=30 days (yellow), otherwise green days remaining. N/A when openssl
# is missing, the host is unreachable, or the dates cannot be parsed.
lookup_cert_expiry() {
  local host="${CERT_EXPIRY_HOST:-ipregion.top}"
  local days

  tcp_probe "$host" 443 || {
    echo "$STATUS_NA"
    return
  }
  days=$(cert_days_remaining "$host")
  if [[ -z "$days" ]]; then
    echo "$STATUS_NA"
    return
  fi
  if ((days < 0)); then
    print_value_or_colored "Expired" "HEART"
    return
  fi
  if ((days <= 14)); then
    print_value_or_colored "$days days" "HEART"
    return
  fi
  if ((days <= 30)); then
    print_value_or_colored "$days days" "WARN"
    return
  fi
  print_value_or_colored "$days days" "SERVICE"
}

lookup_github_api() {
  lookup_tcp_targets GITHUB_API_PROBE_TARGETS
}

lookup_gitlab() {
  lookup_tcp_targets GITLAB_PROBE_TARGETS
}

lookup_gitlab_api() {
  lookup_tcp_targets GITLAB_API_PROBE_TARGETS
}

lookup_steam_api() {
  lookup_tcp_targets STEAM_API_PROBE_TARGETS
}

lookup_discord_api() {
  lookup_tcp_targets DISCORD_API_PROBE_TARGETS
}

lookup_facebook_api() {
  lookup_tcp_targets FACEBOOK_PROBE_TARGETS
}

lookup_messenger_mqtt() {
  lookup_tcp_targets MESSENGER_PROBE_TARGETS
}

lookup_tiktok_transport() {
  lookup_tcp_targets TIKTOK_PROBE_TARGETS
}

lookup_google_transport() {
  lookup_tcp_targets GOOGLE_PROBE_TARGETS
}

# Redirect-chain sanity for two stable public names (both serve 200
# directly, zero redirects, verified from both vantages): a followed
# redirect on either is an unexpected chain - captive portal, ISP
# injection, or a hijacked upstream. Non-200 codes are not judged here
# (availability is a different family). Yes = no redirects, No = an
# unexpected redirect chain, N/A = nothing reachable.
lookup_redirect_chain() {
  local -a canaries=("https://www.google.com/" "https://www.cloudflare.com/")
  local url meta code redirects any=0

  for url in "${canaries[@]}"; do
    meta=$(curl_wrapper GET "$url" -o /dev/null \
      -w '%{http_code}|%{redirect_url}|%{num_redirects}')
    [[ -z "$meta" ]] && continue
    any=1
    code="${meta%%|*}"
    redirects="${meta##*|}"
    if [[ "$code" == "200" && "$redirects" != "0" ]]; then
      print_value_or_colored "No" "HEART"
      return
    fi
  done
  if [[ "$any" != 1 ]]; then
    echo "$STATUS_NA"
    return
  fi
  print_value_or_colored "Yes" "SERVICE"
}

# HTTP/2 support detection for two stable public names: the ALPN-
# negotiated protocol version curl reports for each lookup. Both must
# negotiate HTTP/2; any fallback to HTTP/1 is a downgraded path (legacy
# proxy, middlebox, or hijacked upstream). Yes-like "h2" when both
# negotiate HTTP/2; "no h2" on any fallback; N/A when neither is
# measurable.
lookup_http2_support() {
  local -a canaries=("https://www.google.com" "https://www.cloudflare.com")
  local url versions="" version any=0

  for url in "${canaries[@]}"; do
    version=$(curl_wrapper GET "$url" -o /dev/null -w '%{http_version}')
    [[ -z "$version" ]] && continue
    any=1
    versions+="${version}/"
  done
  versions="${versions%/}"
  if [[ "$any" != 1 ]]; then
    echo "$STATUS_NA"
    return
  fi
  if grep_wrapper -q "1\." <<<"$versions"; then
    print_value_or_colored "no h2" "TABLE_VALUE"
    return
  fi
  print_value_or_colored "h2" "SERVICE"
}

lookup_youtube_transport() {
  lookup_tcp_targets YOUTUBE_PROBE_TARGETS
}

lookup_instagram_transport() {
  lookup_tcp_targets INSTAGRAM_PROBE_TARGETS
}

lookup_threads_transport() {
  lookup_tcp_targets THREADS_PROBE_TARGETS
}

lookup_steam_transport() {
  lookup_tcp_targets STEAM_PROBE_TARGETS
}

lookup_netflix_transport() {
  lookup_tcp_targets NETFLIX_PROBE_TARGETS
}

lookup_apple_transport() {
  lookup_tcp_targets APPLE_PROBE_TARGETS
}

lookup_microsoft_transport() {
  lookup_tcp_targets MICROSOFT_PROBE_TARGETS
}

lookup_rutube_transport() {
  lookup_tcp_targets RUTUBE_PROBE_TARGETS
}

lookup_ozon_transport() {
  lookup_tcp_targets OZON_PROBE_TARGETS
}

lookup_claude() {
  dns_unresolved "claude.ai" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper GET "https://claude.ai/api/bootstrap" \
    --user-agent "Claude com.anthropic.claude/1.261023.20 (Android 30) Claude/1.261023.20" \
    --header "Anthropic-Client-Platform: android" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    echo ""
    return
  fi

  process_json "$response" ".statsig.user.country"
}

lookup_reddit() {
  dns_unresolved "www.reddit.com" && return
  local ip_version="$1"
  local response

  response=$(curl_wrapper GET "https://www.reddit.com/api/v1/not-found" \
    --user-agent "$USER_AGENT" \
    --ip-version "$ip_version")

  if [[ -z "$response" ]]; then
    echo ""
    return
  fi

  if is_status_string "$response"; then
    echo "$response"
    return
  fi

  sed_capture 'country code: ([A-Z]{2})' <<<"$response"
}

lookup_ai_cn_reachable() {
  local url="$1"
  local ip_version="$2"
  local response http_code

  dns_unresolved "$(url_host "$url")" && return
  response=$(curl_wrapper GET "$url" --ip-version "$ip_version")
  http_code=$(read_curl_metric_field "$CURL_META_FILE" "http_code")

  if [[ "$http_code" == "401" ]]; then
    print_value_or_colored "Yes" "SERVICE"
  elif [[ -n "$response" ]]; then
    echo "$response"
  else
    echo ""
  fi
}

lookup_qwen_cn() {
  lookup_ai_cn_reachable "https://dashscope.aliyuncs.com/compatible-mode/v1/models" "$1"
}

lookup_kimi_cn() {
  lookup_ai_cn_reachable "https://api.moonshot.cn/v1/models" "$1"
}

lookup_glm_cn() {
  lookup_ai_cn_reachable "https://open.bigmodel.cn/api/paas/v4/models" "$1"
}

lookup_minimax_cn() {
  lookup_ai_cn_reachable "https://api.minimaxi.com/v1/models" "$1"
}

lookup_youtube_no_ads() {
  dns_unresolved "www.youtube.com" && return
  local ip_version="$1"
  local cookie_jar response

  cookie_jar=$(mktemp "${TMPDIR:-/tmp}/ipregion_youtube_cookies_XXXXXX")

  response=$(curl_wrapper GET "https://www.youtube.com/watch?v=dQw4w9WgXcQ" \
    --user-agent "$USER_AGENT" \
    --header "Cookie: SOCS=CAI; PREF=hl=$YOUTUBE_LANG" \
    --header "Accept-Language: $YOUTUBE_LANG" \
    --cookie-jar "$cookie_jar" \
    --ip-version "$ip_version")

  if [[ -n "$response" ]]; then
    response=$(curl_wrapper GET "https://www.youtube.com/watch?v=dQw4w9WgXcQ" \
      --user-agent "$USER_AGENT" \
      --header "Cookie: SOCS=CAI; PREF=hl=$YOUTUBE_LANG" \
      --header "Accept-Language: $YOUTUBE_LANG" \
      --cookie "$cookie_jar" \
      --ip-version "$ip_version")
  fi

  rm -f "$cookie_jar"

  if [[ -z "$response" ]]; then
    echo ""
    return
  fi

  if is_status_string "$response"; then
    echo "$response"
    return
  fi

  if ! grep_wrapper -q "ytInitialPlayerResponse" <<<"$response"; then
    echo ""
    return
  fi

  if grep_wrapper -q "SLOT_TYPE_PLAYER_BYTES" <<<"$response"; then
    print_value_or_colored "No" "HEART"
  else
    print_value_or_colored "Yes" "SERVICE"
  fi
}

# Runs the checks for the groups selected via --group: resets per-run
# accumulators, publishes the planned total, dispatches all groups.
run_selected_groups() {
  ARR_PRIMARY=()
  ARR_CUSTOM=()
  ARR_CDN=()
  ARR_DNS=()
  ARR_DEVINFRA=()
  [[ -n "${CHECKS_DONE_FILE:-}" ]] && : >"$CHECKS_DONE_FILE"

  if [[ "$JSON_OUTPUT" != "true" && "$PROGRESS_LOG" != true ]]; then
    local selected_groups total_group
    case "$GROUPS_TO_SHOW" in
    primary) selected_groups=(primary) ;;
    custom) selected_groups=(custom) ;;
    cdn) selected_groups=(cdn) ;;
    dns) selected_groups=(dns) ;;
    devinfra) selected_groups=(devinfra) ;;
    default) selected_groups=(default) ;;
    *) selected_groups=(primary custom cdn devinfra dns) ;;
    esac
    CHECKS_TOTAL=0
    for total_group in "${selected_groups[@]}"; do
      CHECKS_TOTAL=$((CHECKS_TOTAL + $(count_group_checks "$total_group")))
    done
    [[ -n "${CHECKS_TOTAL_FILE:-}" ]] && printf '%s' "$CHECKS_TOTAL" >"$CHECKS_TOTAL_FILE"
  fi

  case "$GROUPS_TO_SHOW" in
  primary)
    if ((PARALLEL_JOBS > 1)); then
      run_service_group_parallel "primary"
    else
      run_service_group "primary"
    fi
    ;;
  default)
    if ((PARALLEL_JOBS > 1)); then
      run_service_group_parallel "default"
    else
      run_service_group "default"
    fi
    ;;
  custom)
    if ((PARALLEL_JOBS > 1)); then
      run_service_group_parallel "custom"
    else
      run_service_group "custom"
    fi
    ;;
  cdn)
    if ((PARALLEL_JOBS > 1)); then
      run_service_group_parallel "cdn"
    else
      run_service_group "cdn"
    fi
    ;;
  dns)
    if ((PARALLEL_JOBS > 1)); then
      run_service_group_parallel "dns"
    else
      run_service_group "dns"
    fi
    ;;
  devinfra)
    if ((PARALLEL_JOBS > 1)); then
      run_service_group_parallel "devinfra"
    else
      run_service_group "devinfra"
    fi
    ;;
  *)
    if ((PARALLEL_JOBS > 1)); then
      run_service_group_parallel "primary"
      run_service_group_parallel "custom"
      run_service_group_parallel "cdn"
      run_service_group_parallel "devinfra"
    else
      run_service_group "primary"
      run_service_group "custom"
      run_service_group "cdn"
      run_service_group "devinfra"
    fi
    ;;
  esac

  if ((${#FAIL_ON_BLOCK_KEYS[@]} > 0)); then
    finalize_json
    fail_on_block_check || return 1
  fi
}

# Prints the full check registry: group, check key, display name -
# machine-readable (tab-separated), one line per check. Primary
# registry entries carry "display|domain|url" - display is field one.
print_check_registry() {
  local group key display
  for group in primary custom cdn devinfra dns; do
    local -a keys=()
    case "$group" in
    primary) keys=("${PRIMARY_SERVICES_ORDER[@]}") ;;
    custom) keys=("${CUSTOM_SERVICES_ORDER[@]}") ;;
    cdn) keys=("${CDN_SERVICES_ORDER[@]}") ;;
    devinfra) keys=("${DEVINFRA_SERVICES_ORDER[@]}") ;;
    dns) keys=("${DNS_DIAG_SERVICES_ORDER[@]}") ;;
    esac
    for key in "${keys[@]}"; do
      case "$group" in
      primary) display="${PRIMARY_SERVICES[$key]%%|*}" ;;
      custom) display="${CUSTOM_SERVICES[$key]:-}" ;;
      cdn) display="${CDN_SERVICES[$key]:-}" ;;
      devinfra) display="${DEVINFRA_SERVICES[$key]:-}" ;;
      dns) display="${DNS_DIAG_SERVICES[$key]:-}" ;;
      esac
      printf '%s\t%s\t%s\n' "$group" "$key" "$display"
    done
  done
}

# --fail-on-block: exit nonzero when any of the listed checks is not Yes
# in the finalized result JSON. Absent results count as blocked.
# Registry keys resolve to display names first: add_result stores the
# display name in the results.
fail_on_block_display() {
  local key="$1"
  if [[ -n "${CUSTOM_SERVICES[$key]:-}" ]]; then
    printf '%s' "${CUSTOM_SERVICES[$key]}"
  elif [[ -n "${CDN_SERVICES[$key]:-}" ]]; then
    printf '%s' "${CDN_SERVICES[$key]}"
  elif [[ -n "${DEVINFRA_SERVICES[$key]:-}" ]]; then
    printf '%s' "${DEVINFRA_SERVICES[$key]}"
  elif [[ -n "${DNS_DIAG_SERVICES[$key]:-}" ]]; then
    printf '%s' "${DNS_DIAG_SERVICES[$key]}"
  elif [[ -n "${PRIMARY_SERVICES[$key]:-}" ]]; then
    printf '%s' "${PRIMARY_SERVICES[$key]%%|*}"
  fi
}

fail_on_block_check() {
  local key verdict failed_list=""
  local -a wanted_displays=()
  for key in "${FAIL_ON_BLOCK_KEYS[@]}"; do
    wanted_displays+=("$(fail_on_block_display "$key")")
  done
  local wanted_json
  wanted_json=$(printf '%s\n' "${wanted_displays[@]}" | jq -R . | jq -s .)

  for key in "${FAIL_ON_BLOCK_KEYS[@]}"; do
    verdict=$(jq -r --arg k "$(fail_on_block_display "$key")" \
      --arg no "No" \
      --arg denied "$STATUS_DENIED" \
      --arg server "$STATUS_SERVER_ERROR" \
      --arg rate "$STATUS_RATE_LIMIT" \
      --arg region "$STATUS_REGION_BLOCKED" \
      --arg expired "Expired" \
      --arg ipblock "IP block" '
      [ .results.primary[], .results.custom[], .results.cdn[], .results.devinfra[], .results.dns[]? ]
      | map(select(.service == $k))
      | if length == 0 then "absent"
        elif any(.[]; .ipv4 == $no or .ipv4 == $denied or .ipv4 == $server or .ipv4 == $rate or .ipv4 == $region or .ipv4 == $expired or .ipv4 == $ipblock or .ipv6 == $no or .ipv6 == $denied or .ipv6 == $server or .ipv6 == $rate or .ipv6 == $region or .ipv6 == $expired or .ipv6 == $ipblock) then "failed"
        else "ok"
        end
    ' <<<"$RESULT_JSON" 2>/dev/null)
    if [[ "$verdict" == "failed" || "$verdict" == "absent" ]]; then
      failed_list+="$key "
    fi
  done

  if [[ -n "$failed_list" ]]; then
    printf "%s %s\n" \
      "$(color HEART 'FAIL: blocked checks:')" \
      "${failed_list% }" >&2
    return 1
  fi
  return 0
}

# One "service=v4/v6" line per check from a result JSON
collect_verdict_lines() {
  local json="$1"

  jq -r '
    [ .results.primary[], .results.custom[], .results.cdn[], .results.devinfra[], .results.dns[]? ]
    | .[]
    | .service + "=" + ((.ipv4 // "-") + "/" + (.ipv6 // "-"))
  ' <<<"$json"
}

# Short token for a DNS-family check, used by the --dns-summary line.
dns_summary_token() {
  case "$1" in
  DNS_INTEGRITY) echo "integrity" ;;
  DNS_INTERCEPT) echo "intercept" ;;
  DNS_PTR) echo "ptr" ;;
  DNSSEC_VALIDATION) echo "dnssec" ;;
  DOT_GOOGLE) echo "dot-g" ;;
  DOT_CLOUDFLARE) echo "dot-cf" ;;
  PUBLIC_ANSWERS) echo "public" ;;
  DNS_TTL) echo "ttl" ;;
  RESOLVER_CONSENSUS) echo "consensus" ;;
  DNS_LATENCY) echo "latency" ;;
  RESOLVER_LATENCY) echo "rlatency" ;;
  DNS_JITTER) echo "jitter" ;;
  RESOLVER_JITTER) echo "rjitter" ;;
  DOH_PROXY) echo "dohvia" ;;
  REBIND_PROTECTION) echo "rebind" ;;
  *) echo "$1" ;;
  esac
}

# One-line DNS-family verdict summary for --watch cycles:
#   DNS integrity=Yes intercept=Yes ... latency=12/180 ms rebind=Yes
dns_summary_line() {
  local key token verdict out="DNS"
  for key in "${DNS_DIAG_SERVICES_ORDER[@]}"; do
    token=$(dns_summary_token "$key")
    verdict=$(jq -r --arg k "${DNS_DIAG_SERVICES[$key]}" \
      '[.results.dns[]?] | map(select(.service == $k))[0].ipv4 // "n/a"' \
      <<<"${RESULT_JSON:-}" 2>/dev/null)
    out+=" $token=$verdict"
  done
  printf '%s\n' "$out" >&2
}

# Human-readable diff of verdict lines between two runs
compute_verdict_changes() {
  local prev="$1"
  local cur="$2"
  local -a removed added
  mapfile -t removed < <(printf '%s\n' "$prev" | sort)
  mapfile -t added < <(printf '%s\n' "$cur" | sort)

  local out="" r a svc found known
  for r in "${removed[@]}"; do
    [[ -z "$r" ]] && continue
    svc="${r%%=*}"
    found=""
    for a in "${added[@]}"; do
      [[ "$a" == "$svc="* ]] && {
        found="$a"
        break
      }
    done
    if [[ -n "$found" && "$found" != "$r" ]]; then
      out+="~ ${svc}: ${r#*=} → ${found#*=}"$'\n'
    elif [[ -z "$found" ]]; then
      out+="- ${svc}: ${r#*=}"$'\n'
    fi
  done
  for a in "${added[@]}"; do
    [[ -z "$a" ]] && continue
    svc="${a%%=*}"
    known=false
    for r in "${removed[@]}"; do
      [[ "$r" == "$svc="* ]] && {
        known=true
        break
      }
    done
    [[ "$known" == true ]] || out+="+ ${svc}: ${a#*=}"$'\n'
  done
  printf '%s' "$out"
}

telegram_send_message() {
  local text="$1"

  [[ -n "${IPREGION_TG_BOT_TOKEN:-}" && -n "${IPREGION_TG_CHAT_ID:-}" ]] || return 0
  curl_wrapper POST "https://api.telegram.org/bot${IPREGION_TG_BOT_TOKEN}/sendMessage" \
    --data "chat_id=${IPREGION_TG_CHAT_ID}" \
    --data-urlencode "text=${text}" >/dev/null 2>&1 || true
}

run_compare() {
  local old_file="$1"
  local new_file="$2"

  [[ -f "$old_file" ]] || error_exit "Compare: file not found: $old_file"
  [[ -f "$new_file" ]] || error_exit "Compare: file not found: $new_file"

  local changes
  changes=$(compute_verdict_changes \
    "$(collect_verdict_lines "$(cat "$old_file")")" \
    "$(collect_verdict_lines "$(cat "$new_file")")")

  if [[ -z "$changes" ]]; then
    echo "No verdict changes."
  else
    printf '%s\n' "$changes"
  fi
}

# --watch N: re-run the selected groups every N seconds and report
# verdict changes between cycles (optionally pushing them to Telegram
# via IPREGION_TG_BOT_TOKEN / IPREGION_TG_CHAT_ID).
run_monitor_loop() {
  local prev_verdicts next_verdicts changes
  finalize_json
  prev_verdicts=$(collect_verdict_lines "$RESULT_JSON")

  while true; do
    sleep "$WATCH_INTERVAL"
    run_selected_groups || exit 1
    finalize_json

    next_verdicts=$(collect_verdict_lines "$RESULT_JSON")
    changes=$(compute_verdict_changes "$prev_verdicts" "$next_verdicts")
    if [[ -n "$changes" ]]; then
      printf '%s\n' "$changes" >&2
      telegram_send_message "$changes"
    fi
    if [[ "$DNS_SUMMARY" == true && ("$GROUPS_TO_SHOW" == "dns" || "$GROUPS_TO_SHOW" == "all") ]]; then
      dns_summary_line
    fi
    prev_verdicts="$next_verdicts"
  done
}

main() {
  parse_arguments "$@"

  # The curated default profile only filters when actually selected;
  # tests and golden runs source the script and call the runners directly.
  if [[ "$GROUPS_TO_SHOW" == "default" ]]; then
    DEFAULT_PROFILE=true
  fi

  if [[ "$LIST_ONLY" == true ]]; then
    print_check_registry
    exit 0
  fi

  if [[ -n "$COMPARE_OLD" ]]; then
    run_compare "$COMPARE_OLD" "$COMPARE_NEW"
    exit 0
  fi

  ignore_ip_version_with_proxy
  detect_main_interface

  # Handle cache management flags early
  if [[ "$CACHE_SHOWN" == true ]]; then
    show_ip_cache
    exit 0
  fi

  if [[ "$CACHE_CLEARED" == true ]]; then
    clear_ip_cache
    exit 0
  fi

  setup_debug

  if [[ "$ONLY_CHANGES" == true && "$WATCH_INTERVAL" == 0 ]]; then
    error_exit "--only-changes requires --watch N"
  fi

  if [[ "$DNS_SUMMARY" == true && ("$GROUPS_TO_SHOW" == "dns" || "$GROUPS_TO_SHOW" == "all") ]]; then
    # The summary line replaces all other DNS-family output: quiet run.
    ONLY_CHANGES=true
  fi

  trap cleanup_on_exit EXIT
  trap cleanup_on_interrupt INT TERM HUP

  # Best-effort sweep of temp files from earlier crashed runs
  cleanup_stale_temp_files

  if ((PARALLEL_JOBS <= 0)); then
    PARALLEL_JOBS=$(detect_parallel_jobs)
  fi

  print_startup_message

  if [[ "$JSON_OUTPUT" != true ]]; then
    printf "%s %s\n" \
      "$(color INFO '[INFO]')" \
      "Checking dependencies..." >&2
  fi

  detect_distro
  install_dependencies

  if [[ "$JSON_OUTPUT" != "true" && "$VERBOSE" != "true" && "$PROGRESS_LOG" != true && "$ONLY_CHANGES" != true ]]; then
    spinner_start
  fi

  if ipv4_enabled; then
    check_ip_support 4
    IPV4_SUPPORTED=$?
  fi

  if ipv6_enabled; then
    check_ip_support 6
    IPV6_SUPPORTED=$?
  fi

  if [[ "$IPV6_ONLY" == true && "$IPV6_SUPPORTED" -ne 0 ]]; then
    error_exit "IPv6 is not supported on this system"
  fi

  discover_external_ips
  load_registered_countries
  get_asn

  run_selected_groups || exit 1

  if [[ "$PROGRESS_LOG" == true && "$JSON_OUTPUT" != "true" ]]; then
    printf "%s %s\n" \
      "$(color INFO '[INFO]')" \
      "Rendering results..." >&2
  fi

  if [[ "$JSON_OUTPUT" != "true" && "$VERBOSE" != "true" && "$PROGRESS_LOG" != true && "$ONLY_CHANGES" != true ]]; then
    spinner_stop
  fi

  if [[ "$ONLY_CHANGES" != true ]]; then
    print_results
  fi

  if [[ "$DNS_SUMMARY" == true && ("$GROUPS_TO_SHOW" == "dns" || "$GROUPS_TO_SHOW" == "all") ]]; then
    dns_summary_line
  fi

  if ((WATCH_INTERVAL > 0)); then
    run_monitor_loop
  fi

  cleanup_debug

  trap - EXIT INT TERM
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
