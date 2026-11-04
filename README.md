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

## Features

- 100 checks in three groups: GeoIP sources (19), popular services (78) and CDN nodes (3)
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
./ipregion.sh --ipv4 # IPv4 only
./ipregion.sh --ipv6 # IPv6 only
./ipregion.sh --proxy 127.0.0.1:1080 # Use SOCKS5 proxy
./ipregion.sh --json # JSON output
./ipregion.sh --debug # Debug mode
./ipregion.sh --parallel 6 # Run checks in parallel
./ipregion.sh --force-spinner # Force spinner even in parallel mode
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

- **Messengers**: WhatsApp (site + transport probe), Telegram (site + MTProto datacenter probe), Discord (site + gateway probe), Signal, Messenger
- **Social**: Instagram, Facebook, Threads, TikTok (region + access), Twitter (X), LinkedIn, VK, OK, Reddit (region + guest access), Bluesky, Snapchat, Pinterest, Truth Social, Weibo, Bilibili, NetEase Music, Twitch Site, Yandex, Mail.ru, GitHub
- **AI**: ChatGPT, Claude, Grok, DeepSeek, Perplexity, Copilot, Mistral, Qwen Web + API transport probes (OpenAI, Anthropic, xAI, DeepSeek, Perplexity, Mistral, Reddit, OK, LinkedIn, X, GitHub, GitLab, GitLab API, Steam API, Discord API)
- **Streaming**: YouTube (region, Premium via API, Premium via web page, No Ads), Netflix (region), Spotify (region + signup), Disney+ (region + access), Peacock
- **Region gates**: Douyin (CN egress detector), Peacock

### CDN nodes (group cdn)

YouTube CDN, Cloudflare CDN, Netflix CDN — Google/Cloudflare/Netflix edge node detection (`--group cdn`).

A green Yes means the service answers from your network; a red No usually means a transport-level block (connection reset or timeout) or a region-gate stub; Denied / Rate-limit / N/A are HTTP-level outcomes.

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
