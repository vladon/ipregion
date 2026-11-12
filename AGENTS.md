# Repository Guidelines

## Project Overview

**ipregion** is a single-file Bash CLI (`ipregion.sh`, ~3700 lines) that reports IP geolocation and region availability. It queries GeoIP APIs (group `primary`) and popular-website region checks (group `custom`: Google, YouTube, Gemini, Steam, TikTok, Apple, …) in parallel over IPv4/IPv6, with optional SOCKS5 proxy or network interface binding. Output: color-coded table, JSON, or CSV. MIT-licensed fork of [vernette/ipregion](https://github.com/vernette/ipregion), heavily rewritten. CI deploys the script and the project page to `https://ipregion.top`: the hosting serves the raw script to curl/wget and `index.html` to browsers; that routing is server-side (Caddy on the deploy host) and not part of this repository.

## Architecture & Data Flow

- **Monolith, no build step.** All logic lives in `ipregion.sh`. Entry guard at EOF (~3677): `if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi` — tests safely `source` the file.
- **Configuration = associative arrays** (~lines 84–233), pipe-delimited entries:
  ```bash
  [SERVICE_NAME]="display_name|domain|url_template|response_format"
  ```
  `{ip}` in `url_template` is replaced with the target IP; `response_format` defaults to JSON, use `plain` for text responses.
- **Groups**: `SERVICE_GROUPS` maps `primary` → `PRIMARY_SERVICES_ORDER`, `custom` → `CUSTOM_SERVICES_ORDER`. `main` runs groups via `run_service_group` (sequential) or `run_service_group_parallel`.
- **Result pipeline**: `add_result` → `finalize_json` (builds `RESULT_JSON` via jq: per-service results, metrics, consensus country, ip/asn header data) → `print_results` / `write_output_file`.
- **Dispatch**: `process_service` → `service_build_request` → `curl_wrapper` → `process_response` (case statement with one jq filter per primary service) or `process_with_custom_handler` for entries in `PRIMARY_SERVICES_CUSTOM_HANDLERS`. Custom services call their handler from `CUSTOM_SERVICES_HANDLERS`; `run_all_services` discovers all `lookup_*` functions by name.
- **HTTP status mapping** (`status_from_http_code`, ~1296): 403 → `Denied`, 429 → `Rate-limit`, 5xx → `Server error`, other 4xx → `N/A`.
- **Parallelism**: `PARALLEL_JOBS=0` auto-detects workers (`detect_parallel_jobs`). Each job is an isolated subshell writing to a `mktemp` file; `wait_for_parallel_slot` uses `wait -n` when `supports_wait_n` (bash ≥ 4.3), else a legacy polling loop. Spinner is suppressed in parallel mode (`--force-spinner` to override; `--progress-log` prints lines instead).
- **IP cache**: `${XDG_CACHE_HOME:-$HOME/.cache}/ipregion/ip_cache.json`, TTL `CACHE_TTL=3600` (`--cache-ttl`, `--no-cache`, `--clear-cache`, `--show-cache`); cleared automatically when proxy or interface changes (`load_ip_cache`/`save_ip_cache`, ~1496–1605).
- **External IP discovery**: `IDENTITY_SERVICES` shuffled + retried (`fetch_external_ip`), fallback to cached values on total failure.
- **Debug mode**: temp files under `umask 077`; `redact_debug_log()` strips sensitive data before any upload; upload only on explicit consent.

## Key Directories

Flat repository, no source tree:

| Path | Purpose |
|---|---|
| `ipregion.sh` | Entire application |
| `tests/run.sh` | Unit tests (sources `ipregion.sh`, never runs `main`) |
| `index.html` | Project page (install commands, copy button); shown to browsers by server-side routing |
| `.github/workflows/deploy.yml` | CI: tests, lint, version injection, rsync deploy |
| `.cursor/rules/trunk-based-pr-workflow.mdc` | Git workflow rules (see below) |
| `plans/` | Design docs (`ip-cache-fallback-architecture.md`, `versioning-fix.md`) |
| `README.md` | User-facing usage; update when CLI changes |

## Development Commands

```bash
bash tests/run.sh                            # unit tests (needs jq, bash ≥ 4.3)
bash tests/golden.sh                         # golden tests for the availability family (needs jq, column)
shellcheck -S error ipregion.sh tests/run.sh tests/golden.sh # lint gate
shfmt -i 2 -d ipregion.sh tests/run.sh tests/golden.sh       # format gate (2-space indent)
./ipregion.sh -g primary                     # manual check: GeoIP group
./ipregion.sh -g custom                      # manual check: website group
```

- Runtime deps: `bash`, `curl`, `jq`, `column` (util-linux/bsdmainutils); optional `nslookup`. The script detects distro/package manager and offers to install missing commands.
- **macOS caveat**: system `/bin/bash` is 3.2 (no associative arrays) — install Homebrew bash. On macOS the script runs fully with Homebrew bash (BSD grep/sed/date are supported; `curl --json` is emulated for older system curl).
- Golden tests (`tests/golden.sh`) render the availability family against stubbed `curl_wrapper`/`tcp_probe` responses and diff the full table plus a sorted `RESULT_JSON` against `tests/golden/expected/`. Regenerate after intentional output changes with `GOLDEN_UPDATE=1 bash tests/golden.sh`; the suite self-skips when `column` is absent (CI installs `util-linux-misc`).

## Code Conventions & Common Patterns

- **Formatting/lint**: shfmt 2-space indent, `shellcheck -S error` clean in CI. Never remove directives: SC1003 (literal backslash in spinner `spinstr`, ~1911) and SC1091 (variable-path source, `tests/run.sh:12`).
- **Naming**: `snake_case` functions; handlers named `lookup_<service>`; `UPPERCASE` globals at file top.
- **Adding a primary GeoIP service**: add to `PRIMARY_SERVICES` **and** `PRIMARY_SERVICES_ORDER`; jq filter in the `process_response` case; `SERVICE_HEADERS` for special headers; `PRIMARY_SERVICES_CUSTOM_HANDLERS` if non-JSON/HTML; `IPV6_OVER_IPV4_SERVICES` if the service lacks IPv6 transport.
- **Adding a custom service**: add to `CUSTOM_SERVICES`, `CUSTOM_SERVICES_ORDER`, `CUSTOM_SERVICES_HANDLERS`; implement `lookup_<name>()` returning a country code or status string.
- **Service filtering**: `should_skip_service` — `INCLUDED_SERVICES` (CLI `--include-service`) wins, then default `EXCLUDED_SERVICES` (contains `GOOGLE_SEARCH_CAPTCHA`), then `EXCLUDED_SERVICES_CLI`. CLI names normalize via `normalize_service_name` (case-insensitive, `-` → `_`).
- **Errors/logs**: `error_exit "msg" [code]`; user-facing output via `log LEVEL "msg"` + `color()`; data results only through `add_result`.
- **Parallel-safe state**: jobs cannot share variables — results cross only via temp files; the parent parses them in `add_result_line`.
- **Versioning**: `SCRIPT_VERSION_METADATA` (line 10, format `VERSION_TYPE|VERSION_VALUE|BUILD_DATE|COMMIT_HASH`) is injected by CI via `sed` — never hand-edit.

## Important Files

- `ipregion.sh` — key sections: config arrays (84–233), `parse_arguments` (1138), `status_from_http_code` (1296), cache functions (1496–1675), `curl_wrapper` (1982), `process_response` (2193), `finalize_json` (2572), `add_result` (2686), output/format detection (3007–3123), custom handlers `lookup_*` (3125+), `main` (3564), entry guard (3677).
- `tests/run.sh`, `index.html`, `.github/workflows/deploy.yml`, `README.md` — see table above.

## Runtime/Tooling Preferences

- **Bash ≥ 4.3** for `wait -n` (associative arrays need ≥ 4.0); the legacy fallback keeps *execution* working on older bash, but tests require 4.3+. CI validates on both bash 4.4 and 5.2.
- **jq** is a hard dependency for both the script and tests.
- No local package manager, bundler, or build system — anything "release" happens exclusively in GitHub Actions.

## Testing & QA

- Run `bash tests/run.sh`. It sources `ipregion.sh` and exercises pure/offline functions only — no network.
- Covered: IP/proxy/interface validation helpers, `process_json`, `status_from_http_code`, Gemini parsers (`parse_gemini_user_status_code`, `gemini_batch_needs_stream_probe`, `gemini_stream_generate_has_reply`), service filters (`should_skip_service` against all three filter arrays), `finalize_json` `RESULT_JSON` structure (`.ip.*`, `.asn`, `.consensus`, `.results.*.metrics`), `detect_output_format`.
- Style: flat script — assertion helpers `assert_eq` / `assert_true` / `assert_false` / `assert_empty` / `assert_contains`, global `failures` counter, `exit 1` on any failure. Add new assertions at the bottom; set state variables directly before the call (see the `add_result`/`finalize_json` block).
- Expectations: run tests before finishing any `ipregion.sh` behavior change; for network/service changes also do one manual `./ipregion.sh -g primary` or `-g custom`.

## Git Workflow

Trunk-based, **never commit directly to `master`**:

1. `git checkout -b <type>/<short-description>` from up-to-date `master`
2. Focused changes; `bash tests/run.sh` when `ipregion.sh` changes
3. One clear commit per logical change
4. `git push -u origin HEAD` → `gh pr create --base master` (body: summary bullets + test-plan checklist)
5. Review the diff before merging — no skipping review, even for docs
6. `gh pr merge --merge --delete-branch` (CI green first)
7. `git checkout master && git pull --ff-only`
