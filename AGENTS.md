# Repository Guidelines

## Project Overview

**ipregion** is a single-file Bash CLI (`ipregion.sh`, ~9000 lines) that reports IP geolocation and ~240 website/transport availability checks in parallel over IPv4/IPv6, with optional SOCKS5 proxy or interface binding. Output: color-coded card report, JSON, or CSV; plus monitoring (`--watch`), diffing (`--compare`), and verdict gating (`--fail-on-block`). MIT-licensed fork of [vernette/ipregion](https://github.com/vernette/ipregion), heavily rewritten. CI deploys the script and the project page to `https://ipregion.top`: browsers get `index.html`, curl/wget get the raw script — that user-agent routing is Caddy on the deploy host, not in this repo.

## Architecture & Data Flow

- **Monolith, no build step.** All logic lives in `ipregion.sh`. Entry guard at EOF (8976–8978): `if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi` — tests safely `source` the file.
- **Configuration = associative arrays**, pipe-delimited entries (~lines 368–1298):
  ```bash
  [MAXMIND]="maxmind.com|geoip.maxmind.com|/geoip/v2.1/city/me"   # display|domain|url_template[|plain]
  [GOOGLE]="Google"                                               # key → display name
  [GOOGLE]="lookup_google"                                        # key → handler function
  ```
  `{ip}` in `url_template` is replaced with the target IP; `plain` marks non-JSON responses.
- **Groups**: `SERVICE_GROUPS` (1266) maps `primary` (19 GeoIP providers), `custom` (messengers, AI, streaming…), `cdn`, `dns` (integrity/resolver diagnostics), `devinfra`, plus a curated `default` profile. `--include-service` selections dispatch as a pseudo-group regardless of `-g`.
- **Dispatch pipeline**: `main` (8823) → `parse_arguments` (2488) → `run_selected_groups` (8522) → `run_service_group` (4264) / `run_service_group_parallel` (4292) → `process_service` (4165) → `service_build_request` (3879) → `curl_wrapper` (3680) → `process_response` (3934, one jq filter per primary service) or `process_with_custom_handler` for `PRIMARY_SERVICES_CUSTOM_HANDLERS`. All non-primary checks call their `lookup_*` handler from `CUSTOM_SERVICES_HANDLERS` (1037) — handlers take `(ip_version|proxy)`.
- **Result pipeline**: `add_result` (4522) appends rows `service|||v4|||v6|||m4|||m6` to `ARR_*` arrays and result files → `finalize_json` (4378) builds `RESULT_JSON` via jq (`$schema`, per-group results, metrics, consensus country, ip/asn header; contract: `schema/ipregion-v1.schema.json`, draft 2020-12) → `print_results` / `write_output_file`.
- **Report rendering (card UI)**: `print_report` (5568) renders header block (masked IPs + ASN + pooled verdict + `N/M checks passed` bar), Attention card (abnormal cells via `collect_attention_rows`/`is_abnormal_cell`), paired side-by-side group cards, legend. Cells classified by `classify_cell_value` (4734); widths via `visible_length` (4656, ANSI/emoji-aware — emoji count as 2 cells, `WIDE_EMOJI_PATTERN` at 313). Card rows travel through `read_group_rows` (4887) with **`\x1f` unit separators** (tab is IFS-collapsible — do not switch back to tabs). Colors gated per stream (`USE_COLOR_STDOUT`/`USE_COLOR_STDERR` from `-t 1`/`-t 2`, `NO_COLOR` honored) via `color()`/`COLOR_TARGET`; report + `--json` go to **stdout**, everything operational (logs, spinner, per-check live lines, progress) to **stderr**.
- **Parallelism**: `PARALLEL_JOBS=0` auto-detects via `nproc` (`-P` to override). Each check is an isolated subshell; **all cross-subshell state moves through mktemp files** (result files, spinner sentinels `SPINNER_SERVICE_FILE`/`CHECKS_DONE_FILE`, `CURL_META_FILE` metrics side-channel) — the parent replays rows via `add_result_line`. `wait_for_parallel_slot` + `reap_expired_parallel_workers` enforce `PARALLEL_WORKER_TIMEOUT` (default 120s, floor 30): wedged workers get subtree TERM→KILL and an N/A row (`error_type=worker_timeout`), so one hung check cannot stall the run (bash 5.3 has a subshell spin in `set_pipestatus_array`). `spinner_stop` is a no-op outside the main shell (`BASHPID == $$` guard).
- **IP cache**: `${XDG_CACHE_HOME:-$HOME/.cache}/ipregion/ip_cache.json`, TTL `CACHE_TTL=3600` (`--cache-ttl`, `--no-cache`, `--clear-cache`, `--show-cache`). Cache is **fallback-only**: `fetch_external_ip` (3299) shuffles `IDENTITY_SERVICES` (11 services) with exponential backoff and reads the cache only after all fail; disabled entirely without jq.
- **Debug mode**: temp files under `umask 077`; `redact_debug_log()` strips sensitive data before any upload; upload only on explicit consent.

## Key Directories

Flat repository, no source tree:

|Path|Purpose|
|---|---|
|`ipregion.sh`|Entire application|
|`tests/run.sh`|Unit tests (sources `ipregion.sh`, never runs `main`)|
|`tests/golden.sh`, `tests/golden/expected/`|Golden tests for report rendering; diff target for table + sorted JSON|
|`index.html`|Project page (install tabs, copy button) shown to browsers by server-side routing|
|`schema/ipregion-v1.schema.json`|JSON Schema (draft 2020-12) for `--json` output; `RESULT_JSON` carries `$schema` pointing here|
|`scripts/generate-readme-checks.sh`|Regenerates the auto-generated check-registry table in README between `<!-- ipregion:checks-start/end -->` markers|
|`completions/ipregion.bash`, `completions/ipregion.zsh`|Shell completions (tested by `tests/run.sh`; not shipped in release assets)|
|`fonts/`|Medeo Sans/Medeo Mono variable webfonts (SIL OFL 1.1) used by `index.html` only|
|`.github/workflows/deploy.yml`|CI: tests (bash 4.4 + 5.2 matrix), lint, rsync deploy to `ipregion.top`, release-asset upload (stamped `ipregion.sh`/`.ps1`/`.cmd`)|
|`.github/workflows/live.yml`|Cron (every 3 days) + manual: real network run, `--json` validated with check-jsonschema, group-answer smoke|
|`.github/workflows/docker.yml`|Build + push `ghcr.io/vladon/ipregion` (`latest`, short SHA, semver tags)|
|`.github/workflows/homebrew-tap.yml`|Release-triggered: sha256 + bump `vladon/homebrew-ipregion` formula (secret `TAP_TOKEN`)|
|`.github/workflows/scoop-bump.yml`|Release-triggered + manual: waits for ps1 asset, bumps `vladon/scoop-bucket` manifest (secret `SCOOP_TOKEN`)|
|`ipregion.ps1` / `ipregion.cmd`|Windows launchers: locate a bash env (Git Bash/MSYS2/Cygwin/WSL), fetch the script to `%LOCALAPPDATA%\ipregion`, pass args through; `-Update` re-downloads|
|`.shellcheckrc`|Shared shellcheck config: `source-path=SCRIPTDIR`, extra optional checks (warnings only — the CI gate is `shellcheck -S error`)|
|`.cursor/rules/trunk-based-pr-workflow.mdc`|Git workflow rules (see below)|
|`plans/`|Design docs (`versioning-fix.md`, `ip-cache-fallback-architecture.md`) — both implemented|

## Development Commands

```bash
bash tests/run.sh                            # unit tests (needs jq, bash ≥ 4.3)
bash tests/golden.sh                         # golden tests for report rendering (needs jq)
GOLDEN_UPDATE=1 bash tests/golden.sh         # regenerate golden expected files after intentional output changes
shellcheck -S error ipregion.sh tests/run.sh tests/golden.sh   # lint gate
shfmt -i 2 -d ipregion.sh tests/run.sh tests/golden.sh         # format gate (2-space indent)
scripts/generate-readme-checks.sh            # refresh README check table after adding/removing checks
./ipregion.sh -g primary                     # manual check: GeoIP group
./ipregion.sh --list                         # print the full check registry (group, key, display)
```

## Code Conventions & Common Patterns

- **Formatting/lint**: shfmt 2-space indent, `shellcheck -S error` clean in CI. Never remove directives: SC1003 (literal backslash in spinner `spinstr`) and SC1091 (variable-path source, `tests/run.sh:12`).
- **Naming**: `snake_case` functions with verb prefixes (`is_*` predicates, `get_*`, `parse_*`, `format_*`, `print_*` stdout rendering, `run_*` orchestration, `process_*` dispatch); handlers named `lookup_<service>` (discovered dynamically via `declare -F | grep '^lookup_'`); `UPPERCASE` globals; `readonly` constants; `ARR_<GROUP>` result arrays accessed via namerefs (`local -n rows_ref="ARR_${group^^}"`).
- **Errors/logs**: `error_exit "msg" [code]` for all CLI validation (stderr + help + exit); `log LEVEL "msg"` prints **only when `VERBOSE=true`**; data results only through `add_result`. Exit codes: 0 for `--help`/`--list`/`--compare`/cache ops, 1 default, 130 on INT/TERM/HUP.
- **HTTP status mapping** (`status_from_http_code`, 2702): 403 → `Denied`, 429 → `Rate-limit`, 451 → `Region blocked`, 5xx → `Server error`, other 4xx → `N/A`. Status strings are valid cell values (`is_status_string` short-circuits parsing).
- **Degraded modes (by design)**: bash is the only hard dependency. Missing jq → card report still renders from `ARR_*`; `--json`/`--output`/`--compare`/IP cache/Telegram push hard-fail with a clear error. Missing curl → the `CURL_FREE_CHECKS` subset (TCP `/dev/tcp` + DNS canaries, ~130 checks) still runs, warning shows skipped count. `nslookup` falls back `dig`→`host`→`getent`; ICMP blocked → TCP `:53` probe. Startup detects missing commands and **offers** install (apt/pacman/dnf/yum/zypper/apk/brew, package map `PACKAGE_MAPPING`); declining continues with reduced capabilities instead of exiting.
- **Adding a primary GeoIP service**: entry in `PRIMARY_SERVICES` **and** `PRIMARY_SERVICES_ORDER`; jq filter case arm in `process_response`; optional `SERVICE_HEADERS`, `CURL_FREE_CHECKS`, `IPV6_OVER_IPV4_SERVICES` (1300). Non-JSON/HTML → handler in `PRIMARY_SERVICES_CUSTOM_HANDLERS` + `lookup_*` taking `(transport ip_version)`.
- **Adding a custom/cdn/dns/devinfra check**: key+display in the group's map **and** its `_ORDER` array, handler `lookup_<key_lowercase>` in `CUSTOM_SERVICES_HANDLERS` (signature `(ip_version|proxy)`), optional `*_PROBE_TARGETS`. Then run `scripts/generate-readme-checks.sh` — the README registry and tests' drift-guard loops must stay in sync.
- **Parallel-safe state**: jobs cannot share variables — results cross only via temp files; never add subshell writes to globals.
- **README/page sync**: update README when the CLI changes; `index.html` duplicates install commands in its `installMethods` JS object — keep in sync when commands change.
- **Versioning**: `SCRIPT_VERSION_METADATA` (line 10, format `VERSION_TYPE|VERSION_VALUE|BUILD_DATE|COMMIT_HASH`) is injected by CI via `sed` — never hand-edit; dev builds print `unknown`. No `--version` flag by design.

## Important Files

- `ipregion.sh` — key sections: constants/probe targets (46–176), `CURL_FREE_CHECKS` (368–493), primary registries (503–556), custom registries (558–942), cdn/dns/devinfra registries (945–1035), handlers map (1037–1263), `SERVICE_GROUPS` (1266), `IDENTITY_SERVICES` (1283), `parse_arguments` (2488), `install_dependencies` (2078), `status_from_http_code` (2702), cache functions (3063–3182), `fetch_external_ip` (3299), `curl_wrapper` (3680), `process_response` (3934), group runners (4264–4355), `finalize_json` (4378), `add_result` (4522), rendering helpers (4656–5140), `print_report` (5568), `lookup_*` handlers (5707+), monitor/compare/Telegram (8600+), `main` (8823), entry guard (8976).
- `tests/run.sh` — assertion helpers at top; new assertions go at the bottom before the final `failures` check; registry drift-guard loops near `:234` must list every new service.
- `.github/workflows/deploy.yml` — quality matrix (bash 4.4/5.2 containers), lint job, version injection, rsync deploy; its `paths:` filter means README-only changes do **not** deploy.

## Runtime/Tooling Preferences

- **Bash ≥ 4.3** (associative arrays); no runtime version check in code — the CI matrix (bash 4.4, 5.2) is the compatibility gate. Tests require 4.3+.
- **macOS caveat**: system `/bin/bash` is 3.2 — Homebrew bash required. BSD portability is by construction: use `sed_capture` (not `grep -P`), no `sed -I`, no GNU-only flags; Darwin is special-cased (brew, no-sudo paths).
- **jq** is required for tests/golden and JSON-family features; **curl** for all HTTP checks (curl-free subset still runs without it). No local package manager, bundler, or build system — anything "release" happens exclusively in GitHub Actions.
- Env knobs: `PARALLEL_WORKER_TIMEOUT`, `IPREGION_TG_BOT_TOKEN`/`IPREGION_TG_CHAT_ID` (Telegram push), `XDG_CACHE_HOME`, `TMPDIR`, `NO_COLOR`.

## Testing & QA

Run `bash tests/run.sh`. It sources `ipregion.sh` into one shared process and exercises pure/offline functions only — no network: `curl_wrapper`, `tcp_probe`, and all DNS resolvers are stubbed; subprocess fixtures shrink `PATH` to test degraded environments.

- **Style**: flat script — helpers `assert_eq` / `assert_true` / `assert_false` / `assert_empty` / `assert_contains`, global `failures` counter, `exit 1` on any failure. Add new assertions at the bottom; set state variables directly before the call. **Stub hygiene is mandatory**: every block must `unset -f` its stubs, `unset` its vars, and restore `JSON_OUTPUT` — the suite is one global process.
- **Covered**: IP/proxy validation, parsers (Gemini, DNS family), service filters/selection (`should_skip_service`, `--fail-on-block` interplay, parallel dispatch fixture), `finalize_json` structure, `status_from_http_code`, rendering (`visible_length`, `classify_cell_value`, card text), monitoring kit (`run_compare`, Telegram), completions, jq-less/curl-less degradation regressions, registry completeness drift guards.
- **Golden tests** (`tests/golden.sh`): render the availability family against a stub map (doc-range IPs `203.0.113.10`/`2001:db8::10`, fixed ASN/timestamps), diff the full table **and** key-sorted `RESULT_JSON` (`jq -S`) against `tests/golden/expected/`. Deterministic across systems; non-TTY runs disable colors. `cdn` group is intentionally omitted. Regenerate after intentional output changes with `GOLDEN_UPDATE=1`.
- **Expectations**: run tests before finishing any `ipregion.sh` behavior change; for network/service changes also do one manual `./ipregion.sh -g primary` or `-g custom`.

## Git Workflow

Trunk-based, **never commit directly to `master`**:

1. `git checkout -b <type>/<short-description>` from up-to-date `master`
2. Focused changes; `bash tests/run.sh` when `ipregion.sh` changes
3. One clear commit per logical change
4. `git push -u origin HEAD` → `gh pr create --base master` (body: summary bullets + test-plan checklist)
5. Review the diff before merging — no skipping review, even for docs
6. `gh pr merge --merge --delete-branch` (CI green first)
7. `git checkout master && git pull --ff-only`
