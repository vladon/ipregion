# Graph Report - ipregion  (2026-11-19)

## Corpus Check
- 19 files · ~55,672 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 10 file(s) not represented in the graph (top: (none) 5, .woff2 2, .mdc 1)

## Summary
- 769 nodes · 1530 edges · 40 communities (29 shown, 11 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 17 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `ac83731f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- AI & Service Lookup Handlers
- HTTP & DNS Primitives
- Card Layout Constants
- log
- Site Availability Handlers
- Result & Cell Rendering
- Report & Architecture Concepts
- Deploy Workflow
- Docker Workflow
- Scoop Bump Workflow
- print_results
- Unit Test Suite
- Live Cron Workflow
- Monitoring & Test Assertions
- Golden Test Harness
- Homebrew Tap Workflow
- Debug & Cleanup Lifecycle
- DNS Latency & Jitter
- check_ip_connectivity
- Resolver Latency Checks
- Route Printing Helpers
- TCP Probe Stubs
- DNS Integrity Stubs
- DoH Latency Stubs
- System DNS Stubs
- README Check Generator
- Cert Days Stub
- Consensus Stub
- DoH Integrity Stub
- DoH TTL Stub
- PTR Stub
- Resolver Echo Stub
- Resolver Jitter Stub
- System TTL Stub
- main
- is_command_available
- error_exit
- GEMINI.md
- has_route_flag

## God Nodes (most connected - your core abstractions)
1. `lookup_tcp_targets()` - 116 edges
2. `lookup_site_access()` - 65 edges
3. `curl_wrapper()` - 49 edges
4. `dns_unresolved()` - 34 edges
5. `run.sh script` - 33 edges
6. `main()` - 32 edges
7. `log()` - 29 edges
8. `print_value_or_colored()` - 29 edges
9. `process_json()` - 26 edges
10. `curl_wrapper()` - 23 edges

## Surprising Connections (you probably didn't know these)
- `Golden report fixture` --semantically_similar_to--> `ipregion Terminal Report Screenshot`  [INFERRED] [semantically similar]
  tests/golden/expected/table.txt → .github/assets/ipregion-report.png
- `GeoIP consensus verdict` --references--> `ipregion Terminal Report Screenshot`  [INFERRED]
  README.md → .github/assets/ipregion-report.png
- `Identity services pool` --semantically_similar_to--> `Service rotation with exponential backoff`  [INFERRED] [semantically similar]
  README.md → plans/ip-cache-fallback-architecture.md
- `Golden report fixture` --semantically_similar_to--> `Card-based report`  [INFERRED] [semantically similar]
  tests/golden/expected/table.txt → README.md
- `Card-based report` --references--> `ipregion Terminal Report Screenshot`  [EXTRACTED]
  README.md → .github/assets/ipregion-report.png

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **External IP resilience** — readme_identity_services, plans_ip_cache_mechanism, plans_service_rotation_backoff, plans_cache_functions [EXTRACTED 1.00]
- **Card report family** — readme_card_report, agents_card_rendering, tests_golden_expected_table, _github_assets_ipregion_report_report [INFERRED 0.85]
- **Deterministic release versioning** — plans_hybrid_versioning, plans_script_version_metadata, plans_get_script_version, agents_repo_guidelines [INFERRED 0.85]
- **Unified multi-service network verdict layout** — _github_assets_ipregion_report_geoip_services_check, _github_assets_ipregion_report_popular_services_check, _github_assets_ipregion_report_dns_diagnostics, _github_assets_ipregion_report_check_score [INFERRED]

## Communities (40 total, 11 thin omitted)

### Community 0 - "AI & Service Lookup Handlers"
Cohesion: 0.02
Nodes (98): lookup_ai_studio(), lookup_anthropic_api(), lookup_app_store(), lookup_apple_music(), lookup_apple_transport(), lookup_aws(), lookup_azure_portal(), lookup_battle_net() (+90 more)

### Community 1 - "HTTP & DNS Primitives"
Cohesion: 0.06
Nodes (76): curl_wrapper(), dns_unresolved(), doh_dns_answers(), doh_dns_ttl(), gemini_batch_needs_stream_probe(), gemini_build_stream_generate_freq(), gemini_stream_generate_has_reply(), get_iata_location() (+68 more)

### Community 2 - "Card Layout Constants"
Cohesion: 0.03
Nodes (52): ALL_GROUPS, ANSI_SEQUENCE, CARD_BOTTOM_LEFT, CARD_BOTTOM_RIGHT, CARD_CONTENT_INDENT, CARD_GAP, CARD_HORIZONTAL, CARD_SIDE (+44 more)

### Community 3 - "log"
Cohesion: 0.16
Nodes (20): check_ip_default_route(), check_ip_support(), clear_ip_cache(), fetch_external_ip(), fetch_ip_from_service_with_retry(), get_asn(), get_timestamp(), has_default_route() (+12 more)

### Community 4 - "Site Availability Handlers"
Cohesion: 0.03
Nodes (59): lookup_alipay(), lookup_apple_tv_plus(), lookup_baidu(), lookup_bilibili(), lookup_bing(), lookup_bluesky(), lookup_brave_search(), lookup_canva() (+51 more)

### Community 5 - "Result & Cell Rendering"
Cohesion: 0.05
Nodes (60): add_result(), attention_issue_text(), attention_value_text(), bar_prefix(), bold(), build_service_metric(), can_use_ipv4(), can_use_ipv6() (+52 more)

### Community 6 - "Report & Architecture Concepts"
Cohesion: 0.06
Nodes (41): Attention Panel (Blocked Services and Rate-limits), Check Score Progress (23/27 Checks Passed), DNS Diagnostics Panel (Integrity, Intercept, Latency), GeoIP Services Consensus Panel, Masked IPv4 with ASN and Registration Country Header, Popular Messaging Services Accessibility Panel, ipregion Terminal Report Screenshot, Status Symbols Legend (works / no-blocked / IP blocked / no answer) (+33 more)

### Community 7 - "Deploy Workflow"
Cohesion: 0.06
Nodes (40): concurrency, cancel-in-progress, group, if, needs, permissions, runs-on, steps (+32 more)

### Community 8 - "Docker Workflow"
Cohesion: 0.05
Nodes (38): runs-on, steps, concurrency, cancel-in-progress, group, env, DOCKER_METADATA_ANNOTATIONS_LEVELS, IMAGE_NAME (+30 more)

### Community 9 - "Scoop Bump Workflow"
Cohesion: 0.07
Nodes (29): runs-on, steps, concurrency, cancel-in-progress, group, DISPATCH_TAG, HASH, PS1_URL (+21 more)

### Community 10 - "print_results"
Cohesion: 0.15
Nodes (19): count_group_checks(), detect_output_format(), fail_on_block_check(), fail_on_block_display(), finalize_json(), group_has_results(), has_explicit_selection(), have_jq() (+11 more)

### Community 11 - "Unit Test Suite"
Cohesion: 0.12
Nodes (24): ai_stub_wrapper(), curl_wrapper(), deepl_stub_wrapper(), discord_stub_wrapper(), doh_proxy_curl_stub(), douyin_stub_wrapper(), http2_curl_stub(), instagram_stub_wrapper() (+16 more)

### Community 12 - "Live Cron Workflow"
Cohesion: 0.10
Nodes (20): concurrency, cancel-in-progress, group, jobs, live, runs-on, steps, name (+12 more)

### Community 13 - "Monitoring & Test Assertions"
Cohesion: 0.13
Nodes (20): collect_verdict_lines(), collect_verdict_lines_json(), compute_verdict_changes(), dns_summary_line(), dns_summary_token(), run_compare(), run_monitor_loop(), telegram_send_message() (+12 more)

### Community 14 - "Golden Test Harness"
Cohesion: 0.09
Nodes (8): ipregion.bash script, compare_golden(), curl_wrapper(), DNS_TTL_GAP, doh_dns_answers(), original_curl_stub(), stub_body(), system_dns_answers()

### Community 15 - "Homebrew Tap Workflow"
Cohesion: 0.11
Nodes (18): runs-on, steps, concurrency, cancel-in-progress, group, TAP_TOKEN, jobs, bump-formula (+10 more)

### Community 16 - "Debug & Cleanup Lifecycle"
Cohesion: 0.12
Nodes (18): add_result_line(), append_worker_timeout_result(), cleanup_debug(), cleanup_on_exit(), cleanup_on_interrupt(), debug_paste_upload(), freeze_worker_subtree(), kill_worker_subtree() (+10 more)

### Community 17 - "DNS Latency & Jitter"
Cohesion: 0.40
Nodes (6): doh_dns_latency_ms(), lookup_dns_jitter(), lookup_dns_latency(), median3(), spread3(), system_dns_latency_ms()

### Community 18 - "check_ip_connectivity"
Cohesion: 0.33
Nodes (6): cert_days_remaining(), check_ip_connectivity(), get_ping_command(), lookup_cert_expiry(), tcp_probe(), tls_notafter()

### Community 19 - "Resolver Latency Checks"
Cohesion: 0.50
Nodes (4): lookup_resolver_jitter(), lookup_resolver_latency(), server_dns_answers(), server_dns_latency_ms()

### Community 21 - "Route Printing Helpers"
Cohesion: 0.67
Nodes (3): print_default_routes(), print_ipv4_default_routes(), print_ipv6_default_routes()

### Community 22 - "TCP Probe Stubs"
Cohesion: 0.67
Nodes (3): cert_tcp_stub(), dc_probe_stub(), tcp_probe()

### Community 23 - "DNS Integrity Stubs"
Cohesion: 0.67
Nodes (3): dns_integrity_system_stub(), rebind_dns_stub(), system_dns_answers()

### Community 24 - "DoH Latency Stubs"
Cohesion: 0.67
Nodes (3): doh_dns_latency_ms(), jitter_doh_stub(), latency_doh_stub()

### Community 25 - "System DNS Stubs"
Cohesion: 0.67
Nodes (3): jitter_dns_stub(), latency_dns_stub(), system_dns_latency_ms()

### Community 36 - "main"
Cohesion: 0.22
Nodes (11): cleanup_stale_temp_files(), detect_distro(), discover_external_ips(), ignore_ip_version_with_proxy(), ipv4_enabled(), ipv6_enabled(), main(), print_check_registry() (+3 more)

### Community 37 - "is_command_available"
Cohesion: 0.17
Nodes (12): check_ip_dns(), check_ip_interfaces(), detect_package_manager(), detect_parallel_jobs(), get_missing_commands(), get_package_name(), install_dependencies(), install_packages() (+4 more)

### Community 38 - "error_exit"
Cohesion: 0.29
Nodes (8): display_help(), error_exit(), is_valid_interface_name(), is_valid_port(), is_valid_proxy_addr(), normalize_service_name(), parse_arguments(), validate_known_service()

### Community 40 - "has_route_flag"
Cohesion: 0.67
Nodes (3): detect_main_interface(), has_route_flag(), print_gateway_interface()

## Knowledge Gaps
- **55 isolated node(s):** `ANSI_SEQUENCE`, `WIDE_EMOJI_PATTERN`, `CARD_GAP`, `CARD_SIDES_WIDTH`, `CARD_CONTENT_INDENT` (+50 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 181 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **11 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `golden.sh script` connect `print_results` to `Golden Test Harness`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._
- **What connects `ANSI_SEQUENCE`, `WIDE_EMOJI_PATTERN`, `CARD_GAP` to the rest of the system?**
  _55 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `AI & Service Lookup Handlers` be split into smaller, more focused modules?**
  _Cohesion score 0.02040816326530612 - nodes in this community are weakly interconnected._
- **Why does `lookup_tcp_targets()` connect `AI & Service Lookup Handlers` to `HTTP & DNS Primitives`, `Card Layout Constants`, `check_ip_connectivity`?**
  _High betweenness centrality (0.011) - this node is a cross-community bridge._
- **Should `HTTP & DNS Primitives` be split into smaller, more focused modules?**
  _Cohesion score 0.06315789473684211 - nodes in this community are weakly interconnected._
- **Why does `print_results()` connect `print_results` to `Card Layout Constants`, `main`, `Result & Cell Rendering`, `error_exit`, `Debug & Cleanup Lifecycle`?**
  _High betweenness centrality (0.010) - this node is a cross-community bridge._
- **Should `Card Layout Constants` be split into smaller, more focused modules?**
  _Cohesion score 0.03076923076923077 - nodes in this community are weakly interconnected._