# OpenKey CLI

Developer command-line interface for the [OpenKey](https://github.com/OpenSelfHosting/OpenKey) self-hosted, end-to-end encrypted password manager.

Generate passwords offline, manage developer secrets through the unlocked **desktop or Android** app (native bridge), discover SSH / `.env` / API / AWS material into a device-grouped Secrets section, and optionally authenticate to a self-hosted sync server for ciphertext pull and a short-lived `OPENKEY_SESSION`.

Full documentation: [CLI guide](https://openselfhosting.com/guide/cli) (also on the docs site under **Guide → CLI**).

## Requirements

- Node.js **20+**
- For vault commands without a server: OpenKey **desktop** (or Android) app unlocked on this machine
- For server mode: a running [OpenKey_server](https://github.com/OpenSelfHosting/OpenKey_server) instance

## Install

**From npm** (recommended):

```bash
npm install -g openkey-cli
openkey --version
```

**From source** (development):

```bash
cd openkey_cli
npm install
npm run build
npm link          # optional: puts `openkey` on your PATH
```

Without linking:

```bash
npx openkey-cli --help
npx tsx src/cli.ts --help
node dist/cli.js --help
```

## Quick start (desktop bridge)

```bash
# Unlock the OpenKey desktop app first
openkey status
openkey gen -l 24 --no-symbols
openkey discover --dry-run
openkey discover -y
openkey secret add --name "GitHub PAT" --kind apiToken --secret ghp_...
printf '%s' 'ghp_...' | openkey secret add -n "GitHub PAT" --stdin
openkey secret list
openkey secret list -d laptop -k apiToken
openkey secret update "GitHub PAT" --stdin < token.txt
openkey secret export -d laptop -o .env.local
openkey secret devices
openkey secret copy "GitHub"
openkey totp "GitHub" -c
openkey get "GitHub" --field username
openkey search api
eval $(openkey env DATABASE_URL GITHUB_TOKEN)
openkey run -e DATABASE_URL -e GH=GitHub -- npm start
```

Shell completions: `eval "$(openkey completion zsh)"` (also `bash` / `fish`).

## Android (Termux)

Unlock OpenKey → **Settings → Data → Termux / CLI**, then:

```bash
pkg install nodejs
npm install -g openkey-cli
export OPENKEY_NATIVE_PORT=...    # from the sheet
export OPENKEY_NATIVE_TOKEN=...   # from the sheet
openkey status
```

Port and token last only for that unlock. Copy them again after you lock the vault.

## Optional: self-hosted server

```bash
openkey config set-server http://localhost:8000
openkey login --email you@example.com
eval $(openkey unlock)
openkey sync
eval $(openkey lock)
```

Master password: interactive prompt, or `OPENKEY_PASSWORD` for scripts/CI (never a CLI flag). Email can come from `OPENKEY_EMAIL`.

## Commands (summary)

| Command | Vault access? | Description |
|---------|---------------|-------------|
| `gen` | No | Offline password generation (`-l`, `--no-*`, `-a`, `-c`) |
| `discover` | Save: yes\* | Scan SSH / `.env` / env / AWS → device group |
| `secret add\|list\|get\|copy\|rm\|update\|export\|devices\|set` | Yes\* | Typed developer secrets (`--stdin` / `--secret -`) |
| `get` / `copy` / `search` / `totp` / `logins` / `cards` / `crypto` | Yes\* | Secrets + logins + cards + wallets |
| `env` / `run` | Yes\* | Export secrets into the shell or a child process |
| `doctor` | No | Diagnose bridge / session / server / clipboard |
| `completion` | No | Bash / zsh / fish completion scripts |
| `status` / `config` / `forget` | No | Diagnostics and local state |
| `login` / `logout` / `unlock` / `lock` / `sync` | Server path | Optional ciphertext sync + session (`sync --push`) |

\*Desktop or Android app unlocked, **or** `eval $(openkey unlock)` after `login`.

Global: `--json` for machine-readable output.

Clipboard copies auto-clear after **45s** by default (`--keep` to disable; `--clear N` to change).

### Secret kinds

`apiToken` (default), `sshKey`, `envSnippet`, `other` — see the [CLI guide](../openkey_docs/guide/cli.md) for flags (`--file`, `--public-key-file`, `--device`, …).

## Backends

1. **Native bridge** — unlocked desktop (or Android Termux) app (default).
2. **CLI session** — `OPENKEY_SESSION` after `unlock`.

`openkey gen` needs neither.

Config file (mode `600` when supported): macOS `~/Library/Application Support/OpenKey/config.json`, Linux `~/.config/openkey/config.json`, Windows `%APPDATA%\OpenKey\config.json`.

## Development

```bash
npm test
npm run typecheck
npm run build
```

## Security notes

- `list` / `search` mask values; use `get` / `copy` for plaintext
- Do not pass the master password as a CLI flag
- Sessions expire (default 15 minutes; `config set-lock`)
- Bridge is local-only while the vault is unlocked
- Server stores ciphertext only; keys are derived on the client
