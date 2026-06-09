# AGENTS.md

Guidance for AI assistants working in this repository.

## Project layout

| Path | Role |
|------|------|
| `ipregion.sh` | Entire application (~3400 lines, single bash script) |
| `tests/run.sh` | Unit tests (sources `ipregion.sh`, does not run `main`) |
| `index.php` | Serves `ipregion.sh` as plain text at `ipregion.vladon.sh` |
| `.github/workflows/deploy.yml` | CI: tests, shellcheck/shfmt, version injection, rsync deploy |

## Architecture

- **Monolith**: all logic lives in `ipregion.sh`; no modules or build step locally.
- **Entry guard**: `main` runs only when `BASH_SOURCE[0] == $0` (line ~3429); tests source functions directly.
- **Service groups**: `primary` (GeoIP APIs) and `custom` (website region checks); `SERVICE_GROUPS` maps group names to `_ORDER` arrays.
- **Result pipeline**: `add_result` → `finalize_json` (builds `RESULT_JSON` via jq) → `print_results` / `write_output_file`.
- **Custom services** use `CUSTOM_SERVICES_HANDLERS` (`lookup_*` functions); primary non-JSON services use `PRIMARY_SERVICES_CUSTOM_HANDLERS`.

## Testing

```bash
bash tests/run.sh
```

Requires `jq`. Tests cover validation helpers, HTTP status mapping, service filters, `finalize_json`, and output format detection.

For behavior changes in `ipregion.sh`, always run tests before finishing. For network/service changes, also run a manual check such as `./ipregion.sh -g primary` or `./ipregion.sh -g custom`.

## CI / deploy

On push to `master` (when `ipregion.sh`, `index.php`, `tests/run.sh`, or the workflow changes):

1. **quality** — `tests/run.sh` in Docker with `bash:4.4` and `bash:5.2`
2. **lint** — `shellcheck ipregion.sh tests/run.sh` and `shfmt -d` on the same files
3. **deploy** — injects `SCRIPT_VERSION_METADATA` via `sed`, rsyncs to `ipregion.vladon.sh`

Do not hand-edit `SCRIPT_VERSION_METADATA` for releases; CI sets `VERSION_TYPE|VERSION_VALUE|BUILD_DATE|COMMIT_HASH`.

## Critical gotchas

### Bash version requirements
- **Bash 4.3+** required for `wait -n` (parallel processing)
- **Bash 4.0+** required for associative arrays
- Falls back to legacy loop for older Bash (see `supports_wait_n()`)

### ShellCheck directives (do not remove)
- Line ~1908 in `ipregion.sh`: SC1003 (literal backslash in spinner `spinstr`)
- Line 12 in `tests/run.sh`: SC1091 (sourcing with variable path)

### Service configuration format

Primary services use pipe-delimited entries in associative arrays:

```bash
[SERVICE_NAME]="display_name|domain|url_template|response_format"
```

- `{ip}` in `url_template` is replaced with the target IP
- `response_format` is optional (defaults to JSON); use `plain` for text responses (e.g. `IFCONFIG_CO`)
- Add new services to **both** the associative array **and** the `_ORDER` array
- Non-JSON primary services: add handler to `PRIMARY_SERVICES_CUSTOM_HANDLERS`
- Custom (website) services: add to `CUSTOM_SERVICES`, `CUSTOM_SERVICES_ORDER`, and `CUSTOM_SERVICES_HANDLERS`

### Default service exclusions
`GOOGLE_SEARCH_CAPTCHA` is in `EXCLUDED_SERVICES` by default. CLI `--exclude-service` / `--include-service` override via `EXCLUDED_SERVICES_CLI` and `INCLUDED_SERVICES`.

### IPv6-over-IPv4 services
Listed in `IPV6_OVER_IPV4_SERVICES` — when IPv6 transport is requested, these services automatically use IPv4 instead.

### HTTP status mapping
- HTTP 403 → `STATUS_DENIED`
- HTTP 429 → `STATUS_RATE_LIMIT`
- HTTP 5xx → `STATUS_SERVER_ERROR`
- Other 4xx → `STATUS_NA`

### Parallel processing
- Each job runs in an isolated subshell; results written to temp files via `mktemp`
- `PARALLEL_JOBS=0` (default) auto-detects worker count via `detect_parallel_jobs`
- Spinner disabled by default in parallel mode (`--force-spinner` to override)

### Debug mode security
- Temp files use `umask 077`
- Upload uses `redact_debug_log()` to strip sensitive data
- Debug log path shown at end of execution

### IP cache
- Location: `${XDG_CACHE_HOME:-$HOME/.cache}/ipregion/ip_cache.json`
- Default TTL: 3600 seconds
- Cleared automatically when proxy/interface changes

## Adding a new primary GeoIP service

1. Add to `PRIMARY_SERVICES` and `PRIMARY_SERVICES_ORDER`
2. Add jq filter in `process_response()` case statement (or `plain` format in array entry)
3. If special headers needed: add to `SERVICE_HEADERS`
4. If non-JSON/HTML: add handler to `PRIMARY_SERVICES_CUSTOM_HANDLERS`
5. If IPv6 transport unsupported: add to `IPV6_OVER_IPV4_SERVICES`

## Adding a new custom (website) service

1. Add to `CUSTOM_SERVICES`, `CUSTOM_SERVICES_ORDER`, and `CUSTOM_SERVICES_HANDLERS`
2. Implement `lookup_<name>()` returning country code or status string

## Git workflow

Trunk-based development: **never commit directly to `master`**. Branch → commit → PR → code review → merge → sync `master`. See `.cursor/rules/trunk-based-pr-workflow.mdc`.

## Boot sequence (/init)

1. Read this file and scan `README.md` for user-facing behavior.
2. Run `git status --short` before making edits.
3. Use `rg` for code discovery; keep edits minimal and style-consistent.
4. Run `bash tests/run.sh` after behavior changes in `ipregion.sh`.
5. Land changes via PR to `master` (review before merge).
6. Do not revert unrelated local changes; only touch files required for the task.
