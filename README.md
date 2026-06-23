# postgres

Hardened PostgreSQL access for AI agents — capability-gated, tiered, bounded

## Usage

```bash
just init   # first time: fetch WIT deps
just build  # build wasm component
just test   # run e2e tests
```

## Publishing

Pushing to `main` publishes a signed component to
`actpkg.dev/<owner>/postgres` (owner derived from the git remote;
override the full path with the `OCI_REGISTRY` env var). CI signs the image
keylessly with [cosign](https://docs.sigstore.dev/) via GitHub OIDC.

One-time setup: create a Personal Access Token at
[actpkg.dev](https://actpkg.dev) and add it as a repository secret named
**`ACTPKG_TOKEN`** (Settings → Secrets and variables → Actions).

```bash
just publish   # local publish (unsigned); CI signs on push to main
```

## License

MIT OR Apache-2.0
