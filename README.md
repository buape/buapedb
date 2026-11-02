# buapedb

Database access for Buape.

```sh
brew install buape/tap/buapedb
```

```sh
buapedb list
buapedb orbit
buapedb orbit --write
buapedb kiai --renew <id>
buapedb orbit --end
```

The connection URL is copied to your clipboard; paste in your database tool. The password stays masked unless copying fails. Use `--json` for scripts.

## Development

```sh
bun install --frozen-lockfile
bun run typecheck
bun run lint
bun run build
```

Version tags (`v0.1.0`) build macOS ARM/Intel and Linux Intel binaries and update the Homebrew tap.
