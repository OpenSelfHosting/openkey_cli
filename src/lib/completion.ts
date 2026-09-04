/** Shell completion scripts for bash / zsh / fish. */

export type CompletionShell = "bash" | "zsh" | "fish";

const COMMANDS = [
  "config",
  "login",
  "logout",
  "unlock",
  "lock",
  "status",
  "forget",
  "sync",
  "gen",
  "secret",
  "discover",
  "get",
  "copy",
  "search",
  "totp",
  "logins",
  "cards",
  "crypto",
  "doctor",
  "env",
  "run",
  "completion",
] as const;

export function completionScript(shell: CompletionShell): string {
  switch (shell) {
    case "bash":
      return bashCompletion();
    case "zsh":
      return zshCompletion();
    case "fish":
      return fishCompletion();
    default: {
      const _exhaustive: never = shell;
      return _exhaustive;
    }
  }
}

function bashCompletion(): string {
  const cmds = COMMANDS.join(" ");
  return `# openkey bash completion — eval "$(openkey completion bash)"
_openkey_completions() {
  local cur="\${COMP_WORDS[COMP_CWORD]}"
  local prev="\${COMP_WORDS[COMP_CWORD-1]}"
  if [[ \${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "${cmds}" -- "\$cur") )
    return
  fi
  case "\${COMP_WORDS[1]}" in
    secret)
      COMPREPLY=( $(compgen -W "add set list get copy rm update export devices" -- "\$cur") )
      ;;
    config)
      COMPREPLY=( $(compgen -W "set-server show set-lock" -- "\$cur") )
      ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh fish" -- "\$cur") )
      ;;
    gen)
      COMPREPLY=( $(compgen -W "-l --length --no-upper --no-lower --no-digits --no-symbols -a --avoid-ambiguous -c --copy" -- "\$cur") )
      ;;
    discover)
      COMPREPLY=( $(compgen -W "-d --device -p --path --depth --no-ssh --no-env-files --no-env-vars --no-aws --no-gh --no-docker --dry-run -y --yes" -- "\$cur") )
      ;;
    totp)
      COMPREPLY=( $(compgen -W "-c --copy -w --watch --clear --keep" -- "\$cur") )
      ;;
    sync)
      COMPREPLY=( $(compgen -W "--push" -- "\$cur") )
      ;;
    env|run)
      COMPREPLY=( $(compgen -W "-e --export --raw" -- "\$cur") )
      ;;
    *)
      COMPREPLY=( $(compgen -W "--json --help --version" -- "\$cur") )
      ;;
  esac
}
complete -F _openkey_completions openkey
`;
}

function zshCompletion(): string {
  return `# openkey zsh completion — eval "$(openkey completion zsh)"
#compdef openkey
_openkey() {
  local -a commands
  commands=(
    'config:CLI configuration'
    'login:Log in to a self-hosted server'
    'logout:Clear server access tokens'
    'unlock:Unlock and print OPENKEY_SESSION export'
    'lock:Print unset OPENKEY_SESSION'
    'status:Show bridge / session / server status'
    'forget:Wipe local CLI config and cache'
    'sync:Pull ciphertext from the server'
    'gen:Generate a password offline'
    'secret:Manage developer secrets'
    'discover:Scan machine for secrets'
    'get:Get password/secret for best match'
    'copy:Copy password/secret for best match'
    'search:Search secrets, logins, cards, and crypto'
    'totp:Print or copy a TOTP code'
    'logins:List login entries'
    'cards:List payment cards'
    'crypto:List crypto wallets'
    'doctor:Diagnose CLI / bridge / server'
    'env:Export secrets as shell env assignments'
    'run:Run a command with secrets in the environment'
    'completion:Print shell completion script'
  )
  _arguments -C \\
    '--json[Machine-readable JSON output]' \\
    '(-h --help)'{-h,--help}'[Show help]' \\
    '(-V --version)'{-V,--version}'[Show version]' \\
    '1: :->cmd' \\
    '*::arg:->args'
  case \$state in
    cmd) _describe -t commands 'openkey command' commands ;;
    args)
      case \$words[1] in
        secret) _values 'secret command' add set list get copy rm update export devices ;;
        config) _values 'config command' set-server show set-lock ;;
        completion) _values 'shell' bash zsh fish ;;
      esac
      ;;
  esac
}
compdef _openkey openkey
`;
}

function fishCompletion(): string {
  const lines = COMMANDS.map(
    (c) => `complete -c openkey -n "__fish_use_subcommand" -a ${c}`,
  );
  return `# openkey fish completion — openkey completion fish | source
${lines.join("\n")}
complete -c openkey -n "__fish_seen_subcommand_from secret" -a "add set list get copy rm update export devices"
complete -c openkey -n "__fish_seen_subcommand_from config" -a "set-server show set-lock"
complete -c openkey -n "__fish_seen_subcommand_from completion" -a "bash zsh fish"
complete -c openkey -l json -d "Machine-readable JSON output"
`;
}
