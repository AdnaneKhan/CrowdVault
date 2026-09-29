# AGENTS.md

Guidance for AI coding agents (and humans) working in this repo. Read [README.md](README.md) for what CrowdVault is, and [docs/design.md](docs/design.md) for how and why it works.

## Layout

| Path | What | Toolchain |
| --- | --- | --- |
| `contracts/` | `CrowdVault.sol` (the vault) and `CrowdVaultFactory.sol`, Foundry tests in `test/`, `script/Deploy.s.sol` | Foundry, pinned in CI as `FOUNDRY_VERSION` |
| `vault-seal/` | Rust crate: the library (`src/lib.rs`, `src/zk/`) and two binaries | Rust stable |
| `vault-seal/src/bin/vault-seal.rs` | Creator and coordinator CLI: `keygen`, `pubkey`, `seal`, `fingerprint` | |
| `vault-seal/src/bin/vault-open.rs` | Backer CLI: `verify`, `open`, `fingerprint` | |
| `vault-seal/src/bin/common/` | Code both binaries share: process hardening, the wiping allocator, metadata loading | |
| `web/` | The vault page: React + viem, static build. `src/networks.ts` holds the networks and their public RPCs | Node 22 in CI |
| `scripts/e2e.sh` | The whole flow on a local anvil chain, following the guides | Foundry + Rust |
| `scripts/ci/` | CI helpers: cross-platform round trip, macOS signing check | bash (Git Bash on Windows) |
| `.github/workflows/pages.yml` | Publishes `web/` to GitHub Pages on every push to `main` that touches it | |
| `docs/` | User guides (`coordinator.md`, `creators.md`, `deploying.md`) and technical docs (`design.md`, `performance.md`) | |

## Build and test

```bash
cd contracts && forge build && forge test
cd vault-seal && cargo test --release     # always --release: the proof tests are far too slow in debug
cd vault-seal && cargo build --release    # binaries in target/release/
./scripts/e2e.sh                          # needs anvil, forge and cast on PATH
cd web && npm ci && npm run build         # type-checks, then builds
```

On macOS, a freshly built binary prints a hardened-runtime reminder to stderr for commands that handle secrets. That's expected; sign it (`codesign --force --options runtime --sign - <binary>`) to silence it. The binaries call `PT_DENY_ATTACH` on macOS, so you can't attach a debugger to them.

Before finishing a change, run the checks for every part you touched. CI (`.github/workflows/ci.yml`) runs all of them on Linux, macOS and Windows.

## Rules that are easy to break

**Contracts**
- After any change to a contract's interface, run `forge build` in `contracts/` and then `python3 scripts/gen-abi.py`, and commit the regenerated `web/src/abi.ts`. CI fails if it's stale.
- The vault has no owner and no admin functions by design. Don't add any.
- State changes go before ETH transfers, and every external entry point stays `nonReentrant`.
- If gas use changes noticeably, update the tables in `docs/deploying.md`. They were measured from real transaction receipts on a local anvil chain, not from `forge test --gas-report`, which leaves out the per-transaction base cost.

**Cryptography and the CLIs**
- File formats are versioned (`FORMAT` in `lib.rs` and `zk/mod.rs`, and `KEY_CONTEXT`). Any change to how files are encrypted or keys are derived needs a new format version. Old files must be refused, not misread.
- Secrets are wiped after use: use `Zeroizing`/`zeroize` for anything derived from a secret. Both binaries install the `WipeOnFree` global allocator from `common`. A test scans process memory for leftover secrets, so a leak fails the tests on Linux.
- A sealed file is one file: body, then a JSON metadata footer (`src/container.rs`). Never use the file name in the footer as a path; `vault-open open` reduces it to a bare file name. Keep that.
- The last chunk of an ordinary sealed file authenticates the footer's exact bytes, and a proven file's footer fields are in the proof transcript. Keep every footer field bound one of those ways.
- Write outputs to a `.partial` file and rename only on success, so a failure never leaves a half-written file under the real name.
- A command that handles a secret must call `warn_if_not_hardened()` before it touches the secret.
- Print to stdout with the `out!` macro from `common`, not `println!`, so a closed pipe doesn't panic.
- Put creator and coordinator features in `vault-seal`, and backer features in `vault-open`. Shared helpers go in `src/bin/common/`; library logic goes in `src/lib.rs`.

**The web page**
- Without `VITE_CHAIN_ID`, visitors choose Ethereum or Sepolia; with it, the page serves only that chain. Keep both modes working.
- Public RPCs in `src/networks.ts` must answer browsers (CORS) without an API key. Check each one before adding it.
- Demo mode must never touch a wallet or a network. It's only offered where `VITE_DEMO_BUTTON=1` (the Pages build), on the dev server, and in the single-file demo build.
- `docs/assets/seal.svg`, the README image, is rendered from `src/Seal.tsx`. After changing the seal, run `npm run seal-svg` in `web/` and commit the result.

**Scripts and docs**
- `scripts/e2e.sh` runs the commands from `docs/coordinator.md` and `docs/creators.md`. When you change a command or its output, update the guides and the script together.
- Shell scripts must stay LF (see `.gitattributes`) and run under Git Bash on Windows. Scripts use `set -euo pipefail`; don't pipe into `grep -q`, because an early exit can fail the command writing to the pipe. Capture the output in a variable first.
- Write user docs in plain language: short sentences, second person, and the command before the explanation. Technical detail belongs in `docs/design.md`, not the README or the guides.
- Don't put exact test counts in docs; they go stale.

## Security posture

Nothing here has been audited. Don't describe it as production-ready, and don't weaken a check to make a test pass. If a test that guards a security property fails, fix the cause.
