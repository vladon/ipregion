# ipregion

[![Deploy to FTPS](https://github.com/vladon/ipregion/actions/workflows/deploy.yml/badge.svg)](https://github.com/vladon/ipregion/actions/workflows/deploy.yml)

## Usage

### Download and run locally

```bash
wget -O ipregion.sh https://ipregion.vladon.sh
chmod +x ipregion.sh
```

### Run directly from GitHub

```bash
bash <(wget -qO- https://ipregion.vladon.sh)
```

Opening <https://ipregion.vladon.sh> in a browser shows the project page; curl/wget always receive the raw script. The script is also served verbatim at <https://ipregion.vladon.sh/ipregion.sh>.

### Run a pinned release

```bash
wget -qO ipregion.sh https://github.com/vladon/ipregion/releases/latest/download/ipregion.sh
bash ipregion.sh
```

All releases: https://github.com/vladon/ipregion/releases

### Shell completions

```bash
source completions/ipregion.bash                                    # bash
# zsh: copy to a fpath dir as _ipregion, e.g.
mkdir -p ~/.zfunc && cp completions/ipregion.zsh ~/.zfunc/_ipregion
```

### Monitoring mode

Re-run checks on an interval and print only verdict changes:

```bash
ipregion.sh --watch 300
```

Optionally push changes to a Telegram bot via environment variables:

```bash
IPREGION_TG_BOT_TOKEN=123:ABC IPREGION_TG_CHAT_ID=42 ipregion.sh --watch 300
```

Compare two saved result files without running checks:

```bash
ipregion.sh --compare yesterday.json today.json
```

## Features

- 211 checks in four groups: GeoIP sources (19), popular services (175), dev infra (14) and CDN nodes (3)
- Availability checks for messengers, social networks, AI services and streaming platforms with Yes/No verdicts
- Transport probes distinguish a working service from an open landing page: Telegram MTProto datacenters, WhatsApp edges, Discord gateway (raw TCP connect)
- Region-gate detection: pages that serve a "not available in your region" stub to foreign egress (e.g. Douyin, Peacock) report No instead of a false Yes
- Multiple GeoIP APIs and web services (YouTube, Google, etc.)
- IPv4/IPv6 support with SOCKS5 proxy and custom network interface
- JSON output and color-coded tables
- Parallel checks by default (auto-detected)
- Per-service HTTP/latency metrics and consensus country detection
- Result export to JSON/CSV and service include/exclude filters
- Runs on Linux and macOS (Homebrew bash; missing dependencies are offered via brew)

## Dependencies

- bash 4+ (on macOS install via Homebrew; system bash 3.2 is not supported)
- curl
- jq
- column (util-linux/bsdmainutils; preinstalled on macOS)

Missing commands are detected on start and can be installed automatically (apt/pacman/dnf/yum/zypper/apk/brew).

## Key Options

```bash
./ipregion.sh --help # Show all options
./ipregion.sh --group primary # GeoIP services only
./ipregion.sh --group custom # Popular websites only
./ipregion.sh --group cdn # CDN node checks only
./ipregion.sh --group devinfra # Developer infrastructure only
./ipregion.sh --ipv4 # IPv4 only
./ipregion.sh --ipv6 # IPv6 only
./ipregion.sh --proxy 127.0.0.1:1080 # Use SOCKS5 proxy
./ipregion.sh --json # JSON output
./ipregion.sh --debug # Debug mode
./ipregion.sh --parallel 6 # Run checks in parallel
./ipregion.sh --progress-log # Progress lines instead of spinner
./ipregion.sh --metrics # Show per-service metrics table
./ipregion.sh --youtube-lang en # Viewer language for the YouTube No Ads check
./ipregion.sh --include-service MAXMIND --include-service GOOGLE
./ipregion.sh --exclude-service YOUTUBE
./ipregion.sh --output result.json # Save output
./ipregion.sh --output result.csv # Save output as CSV
```

> [!NOTE]
> Debug mode writes a local log file and may include sensitive data. If you choose to upload it, the script uses a redacted copy, but review the file before sharing.

All options can be combined.

## Checks

### GeoIP (primary)

MaxMind, RIPE, IPinfo, Cloudflare, ipapi.co, ifconfig.co, ip2location.io, iplocation.com, country.is, geojs.io, ipapi.is, ipbase.com, ipquery.io, ipwhois.io, ipwho.is, ip-api.com, ipregistry.co, Detector404, Geoapify — consensus country, ASN and registered country are derived from these.

### Availability (Yes/No per network)

- **Messengers**: WhatsApp (site + transport probe), Telegram (site + MTProto datacenter probe), Discord (site + gateway + CDN probe), Signal, Messenger, Viber, Slack, Zoom, Line, WeChat (+ API), KakaoTalk, Threema
- **Encrypted DNS**: dns.google, cloudflare-dns.com (DoH transport probes)
- **Search**: Bing, DuckDuckGo, Brave Search
- **Social**: Instagram, Facebook (Access + API + CDN), Threads, TikTok (region + access), Twitter (X), LinkedIn, VK, OK, Reddit (region + guest access), Bluesky, Snapchat, Pinterest, Truth Social, Weibo, Bilibili, NetEase Music, Twitch (Site + API + Chat), Yandex, Mail.ru, GitHub
- **AI**: ChatGPT, Claude, Gemini Notebook / NotebookLM (3-attempt region gate), Gemini API, AI Studio, Grok, DeepSeek, Perplexity, Copilot, Mistral, Qwen Web, DeepL (451 region gate), Character.AI, Poe, Google Translate + API transport probes (OpenAI, Anthropic, xAI, DeepSeek, Perplexity, Mistral, Reddit, OK, LinkedIn, X, Twitter Legacy, GitHub, GitLab, GitLab API, Steam API, Discord API, YouTube API, Groq API, OpenRouter, Cohere API, ElevenLabs API)
- **Google services**: Meet, Photos, Calendar, Drive (transport probes — Google gates services individually)
- **Music**: YouTube Music, Apple Music, SoundCloud, Deezer (transport probes)
- **Productivity**: Notion, Figma, Miro, Canva, Trello, Medium
- **Knowledge**: Wikipedia, Stack Overflow, Habr
- **Streaming**: YouTube (region, Premium via API, Premium via web page, No Ads), Netflix (region), Spotify (region + signup), Disney+ (region + access), Peacock
- **Region gates**: Douyin (CN egress detector), Peacock
- **Enterprise**: Microsoft Teams, Outlook, Azure Portal, OneDrive (transport probes)
- **Mail & storage**: Gmail, Proton, Google Drive, Dropbox, MEGA (transport probes)
- **Gaming**: Epic Games, Battle.net, Roblox (+ API), Riot Games, Xbox, Minecraft session (transport probes)
- **Stores & clouds**: App Store, Play Store, AWS, GCP Console, Oracle Cloud (transport probes)
- **CN platforms**: WeChat, WeChat API, Baidu, Alipay
- **Finance**: Stripe API, PayPal, Wise (transport probes)
- **Dev infra** (`--group devinfra`): GitHub (site + API + Codeload + Raw), GitLab (site + API), npm Registry, PyPI, Docker Hub (+ API), Go Modules, Crates.io, Maven Central, Hugging Face
- **Static hosting**: Workers.dev, GitHub Pages, GitLab Pages, Vercel, Netlify, Cloudflare Pages, Heroku (transport probes — this infrastructure is often blocked wholesale)
- **Hosting**: Hetzner, DigitalOcean, Vultr (transport probes)
- **Push & chat infra**: Matrix, ntfy, Telegram Bot API (transport probes)

<!-- ipregion:checks-start -->

| Group | Check | Key |
|---|---|---|
| primary | maxmind.com | `MAXMIND` |
| primary | rdap.db.ripe.net | `RIPE` |
| primary | ipinfo.io | `IPINFO_IO` |
| primary | cloudflare.com | `CLOUDFLARE` |
| primary | ipapi.co | `IPAPI_CO` |
| primary | ifconfig.co | `IFCONFIG_CO` |
| primary | ip2location.io | `IP2LOCATION_IO` |
| primary | iplocation.com | `IPLOCATION_COM` |
| primary | country.is | `COUNTRY_IS` |
| primary | geojs.io | `GEOJS_IO` |
| primary | ipapi.is | `IPAPI_IS` |
| primary | ipbase.com | `IPBASE_COM` |
| primary | ipquery.io | `IPQUERY_IO` |
| primary | ipwhois.io | `IPWHOIS_IO` |
| primary | ipwho.is | `IPWHO_IS` |
| primary | ip-api.com | `IPAPI_COM` |
| primary | Detector404 | `DETECTOR404` |
| primary | ipregistry.co | `IPREGISTRY` |
| primary | geoapify.com | `GEOAPIFY_COM` |
| custom | Google | `GOOGLE` |
| custom | YouTube | `YOUTUBE` |
| custom | YouTube Premium | `YOUTUBE_PREMIUM` |
| custom | YouTube Premium (Web) | `YOUTUBE_PREMIUM_WEB` |
| custom | YouTube API | `YOUTUBE_API` |
| custom | YouTube Transport | `YOUTUBE_TRANSPORT` |
| custom | YouTube Music | `YOUTUBE_MUSIC` |
| custom | Google Search Captcha | `GOOGLE_SEARCH_CAPTCHA` |
| custom | Google Transport | `GOOGLE_TRANSPORT` |
| custom | Bing | `BING` |
| custom | DuckDuckGo | `DUCKDUCKGO` |
| custom | Brave Search | `BRAVE_SEARCH` |
| custom | DoH Google | `DOH_GOOGLE` |
| custom | DoH Cloudflare | `DOH_CLOUDFLARE` |
| custom | Gmail | `GMAIL` |
| custom | Google Drive | `GOOGLE_DRIVE` |
| custom | Google Meet | `GOOGLE_MEET` |
| custom | Google Photos | `GOOGLE_PHOTOS` |
| custom | Google Calendar | `GOOGLE_CALENDAR` |
| custom | Play Store | `PLAY_STORE` |
| custom | AWS | `AWS` |
| custom | GCP Console | `GCP_CONSOLE` |
| custom | Oracle Cloud | `ORACLE_CLOUD` |
| custom | Hetzner | `HETZNER` |
| custom | DigitalOcean | `DIGITALOCEAN` |
| custom | Vultr | `VULTR` |
| custom | Google Gemini | `GEMINI` |
| custom | Gemini Notebook | `GEMINI_NOTEBOOK` |
| custom | Gemini API | `GEMINI_API` |
| custom | AI Studio | `AI_STUDIO` |
| custom | Apple | `APPLE` |
| custom | Apple Transport | `APPLE_TRANSPORT` |
| custom | App Store | `APP_STORE` |
| custom | Apple Music | `APPLE_MUSIC` |
| custom | Steam | `STEAM` |
| custom | Steam API | `STEAM_API` |
| custom | Steam Transport | `STEAM_TRANSPORT` |
| custom | Tiktok | `TIKTOK` |
| custom | Ookla Speedtest | `OOKLA_SPEEDTEST` |
| custom | JetBrains | `JETBRAINS` |
| custom | PlayStation | `PLAYSTATION` |
| custom | Microsoft | `MICROSOFT` |
| custom | Microsoft Transport | `MICROSOFT_TRANSPORT` |
| custom | Microsoft Teams | `TEAMS` |
| custom | Outlook | `OUTLOOK` |
| custom | Azure Portal | `AZURE_PORTAL` |
| custom | OneDrive | `ONEDRIVE` |
| custom | Twitch | `TWITCH` |
| custom | ChatGPT | `CHATGPT` |
| custom | OpenAI API | `OPENAI_API` |
| custom | Disney+ | `DISNEY_PLUS` |
| custom | Disney+ Access | `DISNEY_PLUS_ACCESS` |
| custom | Reddit Guest Access | `REDDIT_GUEST_ACCESS` |
| custom | Reddit API | `REDDIT_API` |
| custom | Claude | `CLAUDE` |
| custom | Anthropic API | `ANTHROPIC_API` |
| custom | Reddit | `REDDIT` |
| custom | Qwen CN API | `QWEN_CN` |
| custom | Kimi CN API | `KIMI_CN` |
| custom | GLM CN API | `GLM_CN` |
| custom | MiniMax CN API | `MINIMAX_CN` |
| custom | YouTube No Ads | `YOUTUBE_NO_ADS` |
| custom | Netflix | `NETFLIX` |
| custom | Netflix Transport | `NETFLIX_TRANSPORT` |
| custom | Spotify | `SPOTIFY` |
| custom | Spotify Signup | `SPOTIFY_SIGNUP` |
| custom | Instagram | `INSTAGRAM` |
| custom | Instagram API | `INSTAGRAM_API` |
| custom | Instagram Transport | `INSTAGRAM_TRANSPORT` |
| custom | TikTok Access | `TIKTOK_ACCESS` |
| custom | TikTok Transport | `TIKTOK_TRANSPORT` |
| custom | WhatsApp | `WHATSAPP` |
| custom | WhatsApp DC | `WHATSAPP_DC` |
| custom | Telegram Access | `TELEGRAM_ACCESS` |
| custom | Telegram DC | `TELEGRAM_DC` |
| custom | Discord Access | `DISCORD_ACCESS` |
| custom | Discord API | `DISCORD_API` |
| custom | Discord Gateway | `DISCORD_GATEWAY` |
| custom | Discord CDN | `DISCORD_CDN` |
| custom | Twitter (X) | `TWITTER` |
| custom | X API | `X_API` |
| custom | Twitter Legacy API | `TWITTER_LEGACY_API` |
| custom | LinkedIn Access | `LINKEDIN_ACCESS` |
| custom | LinkedIn API | `LINKEDIN_API` |
| custom | Facebook Access | `FACEBOOK_ACCESS` |
| custom | Facebook API | `FACEBOOK_API` |
| custom | Facebook CDN | `FACEBOOK_CDN` |
| custom | Messenger Access | `MESSENGER_ACCESS` |
| custom | Messenger MQTT | `MESSENGER_MQTT` |
| custom | Viber | `VIBER` |
| custom | Slack | `SLACK` |
| custom | Zoom | `ZOOM` |
| custom | Line | `LINE` |
| custom | KakaoTalk | `KAKAOTALK` |
| custom | Threema | `THREEMA` |
| custom | Matrix | `MATRIX` |
| custom | ntfy | `NTFY` |
| custom | Telegram Bot API | `TELEGRAM_BOT_API` |
| custom | Workers.dev | `WORKERS_DEV` |
| custom | GitHub Pages | `GITHUB_PAGES` |
| custom | GitLab Pages | `GITLAB_PAGES` |
| custom | Vercel | `VERCEL_APP` |
| custom | Netlify | `NETLIFY_APP` |
| custom | Cloudflare Pages | `PAGES_DEV` |
| custom | Heroku | `HEROKU_APP` |
| custom | Threads Access | `THREADS_ACCESS` |
| custom | Threads API | `THREADS_API` |
| custom | Threads Transport | `THREADS_TRANSPORT` |
| custom | Signal Access | `SIGNAL_ACCESS` |
| custom | Signal Service | `SIGNAL_SERVICE` |
| custom | Douyin (CN) | `DOUYIN_CN` |
| custom | WeChat | `WECHAT` |
| custom | WeChat API | `WECHAT_API` |
| custom | Baidu | `BAIDU` |
| custom | Alipay | `ALIPAY` |
| custom | VK | `VK` |
| custom | VK API | `VK_API` |
| custom | OK | `OK_RU` |
| custom | OK API | `OK_API` |
| custom | RUTUBE Transport | `RUTUBE_TRANSPORT` |
| custom | Ozon Transport | `OZON_TRANSPORT` |
| custom | Grok | `GROK` |
| custom | xAI API | `XAI_API` |
| custom | DeepSeek | `DEEPSEEK` |
| custom | DeepSeek API | `DEEPSEEK_API` |
| custom | Perplexity | `PERPLEXITY` |
| custom | Perplexity API | `PERPLEXITY_API` |
| custom | Copilot | `COPILOT` |
| custom | Mistral | `MISTRAL` |
| custom | Mistral API | `MISTRAL_API` |
| custom | Groq API | `GROQ_API` |
| custom | OpenRouter | `OPENROUTER` |
| custom | Cohere API | `COHERE_API` |
| custom | ElevenLabs API | `ELEVENLABS_API` |
| custom | Qwen Web | `QWEN_WEB` |
| custom | DeepL | `DEEPL` |
| custom | Character.AI | `CHARACTER_AI` |
| custom | Poe | `POE` |
| custom | Google Translate | `GOOGLE_TRANSLATE` |
| custom | Peacock Access | `PEACOCK_ACCESS` |
| custom | Bluesky | `BLUESKY` |
| custom | Snapchat | `SNAPCHAT` |
| custom | Pinterest | `PINTEREST` |
| custom | Truth Social | `TRUTH_SOCIAL` |
| custom | Weibo | `WEIBO` |
| custom | Bilibili | `BILIBILI` |
| custom | NetEase Music | `NETEASE_MUSIC` |
| custom | Twitch Site | `TWITCH_SITE` |
| custom | Twitch API | `TWITCH_API` |
| custom | Twitch Chat | `TWITCH_CHAT` |
| custom | Yandex | `YANDEX` |
| custom | Mail.ru | `MAIL_RU` |
| custom | Proton | `PROTON` |
| custom | Dropbox | `DROPBOX` |
| custom | MEGA | `MEGA` |
| custom | Epic Games | `EPIC_GAMES` |
| custom | Battle.net | `BATTLE_NET` |
| custom | Minecraft Session | `MINECRAFT_SESSION` |
| custom | Roblox | `ROBLOX` |
| custom | Roblox API | `ROBLOX_API` |
| custom | Riot Games | `RIOT` |
| custom | Xbox | `XBOX` |
| custom | Stripe API | `STRIPE_API` |
| custom | PayPal | `PAYPAL` |
| custom | Wise | `WISE` |
| custom | Notion | `NOTION` |
| custom | Figma | `FIGMA` |
| custom | Miro | `MIRO` |
| custom | Canva | `CANVA` |
| custom | Trello | `TRELLO` |
| custom | Medium | `MEDIUM` |
| custom | Wikipedia | `WIKIPEDIA` |
| custom | Stack Overflow | `STACK_OVERFLOW` |
| custom | Habr | `HABR` |
| custom | SoundCloud | `SOUNDCLOUD` |
| custom | Deezer | `DEEZER` |
| cdn | YouTube CDN | `YOUTUBE_CDN` |
| cdn | Cloudflare CDN | `CLOUDFLARE_CDN` |
| cdn | Netflix CDN | `NETFLIX_CDN` |
| devinfra | GitHub | `GITHUB` |
| devinfra | GitHub API | `GITHUB_API` |
| devinfra | GitHub Codeload | `GITHUB_CODELOAD` |
| devinfra | GitHub Raw | `GITHUB_RAW` |
| devinfra | GitLab | `GITLAB` |
| devinfra | GitLab API | `GITLAB_API` |
| devinfra | npm Registry | `NPM_REGISTRY` |
| devinfra | PyPI | `PYPI` |
| devinfra | Docker Hub | `DOCKER_HUB` |
| devinfra | Docker Hub API | `DOCKER_HUB_API` |
| devinfra | Go Modules | `GO_MODULES` |
| devinfra | Crates.io | `CRATES_IO` |
| devinfra | Maven Central | `MAVEN_CENTRAL` |
| devinfra | Hugging Face | `HUGGING_FACE` |
| dns | DNS Integrity | `DNS_INTEGRITY` |
| dns | DNS Intercept | `DNS_INTERCEPT` |
| dns | PTR Match | `DNS_PTR` |
| dns | DNSSEC Validation | `DNSSEC_VALIDATION` |
| dns | DoT Google | `DOT_GOOGLE` |
| dns | DoT Cloudflare | `DOT_CLOUDFLARE` |
| dns | Public Answers | `PUBLIC_ANSWERS` |
| dns | TTL Honesty | `DNS_TTL` |
| dns | Resolver Consensus | `RESOLVER_CONSENSUS` |
| dns | DNS Latency | `DNS_LATENCY` |
| dns | Rebind Protection | `REBIND_PROTECTION` |

Total: 223 checks.
<!-- ipregion:checks-end -->

### DNS diagnostics (group dns)

The whole family runs with `--group dns` and is reference-based and token-free: every verdict is derived from public canaries or a TLS-protected DoH reference, never from the author's infrastructure.

| Check | Detects | Verdict |
|---|---|---|
| DNS Integrity | Fabricated records (random-label NXDOMAIN canary) and rewritten, clamped or filtered A/AAAA answers for `dns.google` / `one.one.one.one` vs the DoH reference | **Yes** = clean; **No** = spoofing or filtering; **N/A** = reference unreachable |
| DNS Intercept | Transparent port-53 interception: `whoami.akamai.net` echoes the same egress address for two independent public resolvers | **Yes** = clean; **No** = intercepted; **N/A** = probes fail |
| PTR Match | Reverse answers for 8.8.8.8 / 1.1.1.1 vs the DoH reference | **Yes** = match; **No** = substituted or filtered; **N/A** = reference unreachable or no published PTR |
| DNSSEC Validation | `dnssec-failed.org` (permanently broken signatures) must SERVFAIL | **Yes** = resolver validates; **No** = serves broken-signature records; **N/A** = canary no longer broken or reference unreachable |
| DoT Google / DoT Cloudflare | DNS-over-TLS reachability (`dns.google:853`, `one.one.one.one:853`) | **Yes/No** per transport |
| Public Answers | Private-address answers (RFC1918, loopback, CGNAT) for eight major public names | **Yes** = all public; **No** = private injection; **N/A** = nothing resolved |
| TTL Honesty | Cache behavior: the served TTL must decrement between samples | **Yes** = decrementing (honest cache); **No** = constant (substituted or non-caching forwarder); **N/A** = ambiguous |
| Resolver Consensus | `dns.google` and `one.one.one.one` asked directly at 8.8.8.8 / 1.1.1.1 / 9.9.9.9 must all match the DoH reference | **Yes** = consensus; **No** = divergence; **N/A** = fewer than two reachable |
| Rebind Protection | Public 1u.ms rebinding canary: a fresh name resolves to a public IP first and to 127.0.0.1 on follow-up queries (TTL 0) | **Yes** = protected (loopback never served); **No** = vulnerable (serves the flip); **N/A** = canary unreachable |
| DNS Latency | Informational: system-resolver vs DoH-JSON resolution time ("local/doh ms") for a stable canary | milliseconds; **N/A** = bash < 5 or lookup failure |

### CDN nodes (group cdn)

YouTube CDN, Cloudflare CDN, Netflix CDN — Google/Cloudflare/Netflix edge node detection (`--group cdn`).

A green Yes means the service answers from your network; a red No usually means a transport-level block (connection reset or timeout) or a region-gate stub; Denied / Rate-limit / N/A are HTTP-level outcomes. A yellow **DNS block** means the hostname did not resolve at all (typical of DNS poisoning); every check — transport probes, site availability and the bespoke custom handlers — resolves its target before connecting. **DNS Latency** is informational: it shows the system resolver's resolution time next to the DoH-JSON reference ("local/doh ms") for a stable canary.

## Country codes

The script outputs country codes in ISO 3166-1 alpha-2 format (e.g., RU, US, DE).

You can look up the meaning of any country code at the official ISO website: [https://www.iso.org/obp/ui/#search/code/](https://www.iso.org/obp/ui/#search/code/)

Just enter the code in the search box to get the full country name.

## Contributing

Contributions are welcome! Feel free to submit pull requests to add new services or improve the script’s functionality.

## Original repository

Forked from the original repository and heavily rewritten, with key improvements:
- Availability checks for messengers, social networks, AI services and streaming platforms, including per-protocol transport probes
- Parallel checks by default with auto-detected worker count
- Per-service HTTP/latency metrics, JSON/CSV export and service include/exclude filters
- macOS support (brew dependency install, BSD-compatible tools)
- Robust debug-log redaction with consent-gated uploads and paste-service fallbacks
- Safer legacy fallback for parallel waiting on older bash

Original: https://github.com/vernette/ipregion

## Credits

Original author: Nikita Skryabin  
Maintainer and rewrites: Vlad Yaroslavlev

![Star History Chart](https://api.star-history.com/svg?repos=vladon/ipregion&type=Date)
