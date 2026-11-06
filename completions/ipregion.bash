# bash completion for ipregion
# Source it (or install to bash-completion/wipo):
#   source completions/ipregion.bash
_ipregion_completions() {
  local cur prev cmd
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmd="${COMP_WORDS[0]}"

  case "$prev" in
  -g | --group)
    COMPREPLY=($(compgen -W "primary custom cdn devinfra all" -- "$cur"))
    return
    ;;
  --include-service | --exclude-service)
    # The command is often invoked as ./ipregion.sh (not on PATH) - fall
    # back to the local file when the PATH lookup produces nothing. The
    # trailing || true keeps set -e from exiting on the 127 lookup miss.
    local service_words
    service_words=$("$cmd" --list 2>/dev/null | cut -f2 | tr 'A-Z' 'a-z' || true)
    if [[ -z "$service_words" && -f "./$cmd" ]]; then
      service_words=$(./"$cmd" --list 2>/dev/null | cut -f2 | tr 'A-Z' 'a-z')
    fi
    COMPREPLY=($(compgen -W "$service_words" -- "$cur"))
    return
    ;;
  -t | --timeout | -P | --parallel | --watch | --cache-ttl | --youtube-lang | -p | --proxy | -i | --interface | -o | --output | --compare)
    return
    ;;
  esac

  if [[ "$cur" == -* ]]; then
    COMPREPLY=($(compgen -W "--help --verbose --debug --json --group --timeout --parallel --watch --only-changes --compare --list --progress-log --ipv4 --ipv6 --proxy --interface --no-cache --cache-ttl --clear-cache --show-cache --include-service --exclude-service --metrics --youtube-lang --output" -- "$cur"))
  fi
}
complete -F _ipregion_completions ipregion.sh ipregion
