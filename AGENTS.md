# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Testing

```bash
bash tests/run.sh
```

Tests source `ipregion.sh` directly and call validation functions. Requires `jq`.

## Critical Gotchas

### Bash Version Requirements
- **Bash 4.3+** required for `wait -n` (parallel processing)
- **Bash 4.0+** required for associative arrays
- Falls back to legacy loop for older Bash (see `supports_wait_n()`)

### ShellCheck Directives (Do Not Remove)
- Line 1003 in ipregion.sh: SC1003 (literal backslash in spin character)
- Line 12 in tests/run.sh: SC1091 (sourcing with variable path)

## Service Configuration Format

Primary services use pipe-delimited format in associative arrays:
```bash
[SERVICE_NAME]="display_name|domain|url_template|response_format"
```

- `{ip}` in `url_template` gets replaced with actual IP
- Add new services to BOTH the associative array AND the `_ORDER` array
- Non-JSON services need entry in `PRIMARY_SERVICES_CUSTOM_HANDLERS`

## Non-Obvious Patterns

### IPv6-over-IPv4 Services
Some services don't support IPv6 transport. Listed in `IPV6_OVER_IPV4_SERVICES` array - automatically switch to IPv4 transport when IPv6 is requested.

### HTTP Status Mapping
- HTTP 403 → `STATUS_DENIED`
- HTTP 429 → `STATUS_RATE_LIMIT`  
- HTTP 5xx → `STATUS_SERVER_ERROR`
- Other 4xx → `STATUS_NA`

### Parallel Processing
- Each job runs in isolated subshell
- Results written to temp files via `mktemp`
- Spinner disabled by default in parallel mode (use `--force-spinner` to override)

### Debug Mode Security
- Temp files use `umask 077`
- Upload uses `redact_debug_log()` function to strip sensitive data
- Debug log path shown at end of execution

### IP Cache
- Cache location: `${XDG_CACHE_HOME:-$HOME/.cache}/ipregion/ip_cache.json`
- Default TTL: 3600 seconds
- Cleared automatically when proxy/interface changes

## Adding New Services

1. Add to `PRIMARY_SERVICES` (or `CUSTOM_SERVICES`) associative array
2. Add to corresponding `_ORDER` array
3. Add jq filter in `process_response()` case statement
4. If special headers needed: add to `SERVICE_HEADERS`
5. If non-JSON: add handler to `PRIMARY_SERVICES_CUSTOM_HANDLERS`
