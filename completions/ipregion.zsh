#compdef ipregion ipregion.sh
# zsh completion for ipregion
_ipregion() {
  local -a args
  args=(
    '(-h --help)'{-h,--help}'[Show help]'
    '(-v --verbose)'{-v,--verbose}'[Verbose logging]'
    '(-d --debug)'{-d,--debug}'[Debug trace]'
    '(-j --json)'{-j,--json}'[JSON output]'
    '(-g --group)'{-g,--group}'[Run one group]:group:(primary custom cdn devinfra dns all)'
    '--dns-summary[With --watch: one-line DNS-family summary per cycle]'
    '(-t --timeout)'{-t,--timeout}'[Curl timeout seconds]:seconds:'
    '(-P --parallel)'{-P,--parallel}'[Parallel jobs]:jobs:'
    '--watch[Monitoring mode interval seconds]:seconds:'
    '--only-changes[With --watch: print only verdict changes]'
    '--compare[Compare two result JSON files]:old:_files -g "*.json":new:_files -g "*.json"'
    '--list[Print the check registry]'
    '--progress-log[Progress lines instead of spinner]'
    '(-4 --ipv4)'{-4,--ipv4}'[IPv4 only]'
    '(-6 --ipv6)'{-6,--ipv6}'[IPv6 only]'
    '(-p --proxy)'{-p,--proxy}'[SOCKS5 proxy]:proxy:'
    '(-i --interface)'{-i,--interface}'[Network interface]:interface:'
    '--no-cache[Disable IP cache]'
    '--cache-ttl[Cache TTL seconds]:seconds:'
    '--clear-cache[Clear IP cache]'
    '--show-cache[Show cached IPs]'
    '--include-service[Include check]:service:->services'
    '--exclude-service[Exclude check]:service:->services'
    '--fail-on-block[Exit 1 if the check is not Yes]:service:->services'
    '--metrics[Show per-service metrics]'
    '--youtube-lang[YouTube language]:lang:(ru en)'
    '(-o --output)'{-o,--output}'[Output file]:file:_files'
  )
  _arguments -S $args

  case $state in
  services)
    local -a names
    names=($(ipregion.sh --list 2>/dev/null | cut -f2 | tr 'A-Z' 'a-z'))
    (( ${#names[@]} == 0 )) && names=($(./ipregion.sh --list 2>/dev/null | cut -f2 | tr 'A-Z' 'a-z'))
    _values -s , $names
    ;;
  esac
}
compdef _ipregion ipregion.sh ipregion 2>/dev/null
