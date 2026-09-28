# Design and security

The technical side of CrowdVault: how files are sealed, what backers can check and how, the optional zero-knowledge proofs, and how the contract handles the risky spots. For how to *use* CrowdVault, see the [README](../README.md) and the guides next to this file.

## How sealing works

For each file the tool picks a random scalar r and publishes `R = r·G` as the sealed key. The file key is derived from `r·X` (plus the file's name and format). After the reveal, anyone derives the same key from `x·R`, because `x·R = r·X`.

The file key is derived with BLAKE3 in key-derivation mode, and the file is encrypted under it in 64 KiB chunks, using the STREAM construction over AES-256-GCM. Files of any size stream through without being held in memory, and truncated, reordered or altered chunks are all detected. The last chunk also authenticates the file's length and BLAKE3 hash, so every metadata field is bound in: edit any of them and the file won't open.

The ephemeral secrets of a seal are wiped from memory as soon as they are used: the random scalar r, the shared secret r·X, the file key and the AES key schedule. A test searches the whole process memory after sealing, opening and proving, and finds none of them.

## What backers can verify

**Before the reveal, with certainty and no trust.** `vault-open verify` checks that the metadata names the vault's campaign key and that the sealed key is a valid curve point in its one canonical encoding. The file key is then a fixed function of `x` and public data. The contract only accepts an `x` with `x·G = X`. So the key the vault reveals is guaranteed to produce exactly this file's key. There is no wrapped key blob that could turn out not to open. `verify` also checks that the encrypted file matches its metadata byte for byte.

**Trusted, unless the file is proven.** Whether the creator encrypted the promised content under that key. After the reveal, `open` checks the content against the creator's committed hash, and a mismatch is reported as the creator's fault. Anyone with the revealed key can reproduce it, so cheating is publicly provable, just not preventable.

### Proven files (optional, small files)

`vault-seal seal --prove` adds a zero-knowledge proof of about 1.5 KB. `verify` checks it automatically, and it shows, with no secret and no trust, that the key the vault reveals will open the file to a plaintext with the fingerprint in its metadata. If that fingerprint was published for a known work, the plaintext is exactly that work; without a published fingerprint, the proof guarantees the file opens and can't be swapped. `verify` refuses proven files over 64 KB by default, so a hostile file can't make checking run for hours. Nothing on-chain changes. Proven files use their own format, `crowdvault-seal/zk1`, alongside the ordinary one.

The design keeps the proof small and the statement cheap:

- **A curve cycle.** Proofs are Bulletproofs over secq256k1, a curve whose group order is exactly secp256k1's field prime. Circuits are therefore over the field where secp256k1 arithmetic is native, so the step that ties the file to the vault's key (`S = r·X`) costs about 2,400 gates rather than emulated big-integer arithmetic. The field has no large power-of-two subgroup, which rules out FFT-based provers but suits Bulletproofs, which need no FFTs and no trusted setup.
- **Proof-friendly sealing.** Proven files use a Poseidon keystream and a Poseidon fingerprint over that same field, about 3.3 gates per byte. Byte-oriented primitives like the BLAKE3 and AES-GCM that ordinary sealing uses would cost hundreds.
- **Only `r` is secret.** Inside the circuit, the plaintext is the public ciphertext minus the keystream, so the prover's only witness is the one random value behind the sealed key.

Measured on a single slow cloud core, with generators cached; proving and verifying use every core available, so a laptop is several times faster (see [performance.md](performance.md)):

| File size | Gates | Proof size | Seal and prove | Verify |
| --- | --- | --- | --- | --- |
| 1 KB | 6,838 | 1,291 bytes | 2.4 s | 0.36 s |
| 16 KB | 57,430 | 1,489 bytes | 16.8 s | 2.4 s |
| 64 KB | 218,998 | 1,621 bytes | 72.9 s | 9.1 s |

Proof size grows with the logarithm of the file size, so it stays under 2 KB at any size you'd prove.

The circuit proves: `R = r·G` and `S = r·X` (fixed-base windows, complete addition formulas); `K = Poseidon(S, R, X, name, length)`; plaintext = ciphertext − `Poseidon(K, block)`; fingerprint = `Poseidon-sponge(length, plaintext)`.

Security rests on the discrete-log assumption in secq256k1 (proof soundness), CDH in secp256k1 and Poseidon as a PRF and hash (confidentiality and binding), and SHA-256 as the Fiat–Shamir random oracle. Everything is implemented from the published constructions in `vault-seal/src/zk/`, including hand-written field arithmetic that is tested against a reference implementation. The tests include a prover holding the wrong key failing to produce a verifying proof, and proofs failing to transfer between files, keys, names or fingerprints.

**Before production:** have the proof system and circuit audited, and run the Poseidon reference script's MDS security checks against this field and parameters (width 9, x^5, 8 full and 64 partial rounds, Cauchy MDS).

For large files, two further routes were explored: spot checks (cheap, but samples must be large because a creator can retry) and general zkVM proofs (thorough but compute-heavy).

One trade-off of deriving the key from the campaign key: an encrypted file belongs to one campaign. Offering the same work in another campaign means sealing it again.

## Releasing the key

The claim reveals the secret directly: the contract checks `x·G == X` using the `ecrecover` precompile trick (one call, about 3k gas), then pays out. Claim and reveal are one transaction, and front-running is harmless because the destination is fixed. An adaptor signature, with the secret extracted from a completed signature, would tie the two together as well, but on the EVM it adds nothing, and it would bring a nonce that must never be reused. The direct check has no nonce to get wrong.

For ordinary files, whether the content is what the creator promised is taken on trust until the reveal, as described above; proven files remove that trust for small files.

## Security notes

The five places where a mistake would be most costly, and how each is handled:

1. **Nonce handling.** Removed by using the direct key check. In the Rust tool, every seal uses a fresh r and so a fresh file key, so the fixed AEAD nonce prefix is never reused under one key.
2. **Reentrancy.** Every state change happens before the ETH transfer, plus a reentrancy guard. Tested with an attacker contract.
3. **Atomic threshold check.** The contribution that reaches the goal sets `lockedAt` in the same transaction. Tested.
4. **Key integrity.** `X` is fixed at deployment and checked to be on the curve, so nobody can substitute a different point. The `ecrecover` key check is fuzz-tested against Foundry's own secp256k1 keys.
5. **Accounting.** Solidity 0.8 checked arithmetic; fuzz-tested that the total always equals the contract balance and the sum of contributions.

Other behaviours to be aware of:

- **Withdrawing as the vault locks.** Transactions in a block run one after another, so a withdrawal and the contribution that reaches the goal can't both land. If the withdrawal is first, the total drops and the vault stays Open. If the contribution is first, the vault locks in that same transaction and the withdrawal fails, costing only gas. The page simulates each transaction before asking for a signature, and warns backers with a stake once the vault is 90% funded.
- **The end of the claim window.** `claim` is accepted up to and including the deadline block, and `withdraw` reopens from the block after it, so the two can never both succeed.
- A recipient that rejects ETH doesn't block the claim. The payout is held and anyone can retry with `releasePayout()`.
- Anyone who knows `x` can call `claim`. Before the reveal that's only the coordinator; after, the money goes to the recipient anyway.
- **Claiming near the deadline is risky for the coordinator.** A claim transaction that lands after the window reverts, but its calldata, including `x`, is still published on-chain. Backers would then get both the goods and their refunds. Claim early in the window.
- The metadata's plaintext hash is public, so if a sealed file is guessable (a known public file), anyone can confirm which file it is.
- `open` writes to a temporary file and only renames it once everything checks out, so a failed open never leaves a partial file behind under the real name.
- The claim window is measured in seconds and capped at 30 days by the contract, so backers' money can never be frozen longer than that, on any chain.
- **Genuine vaults only.** Vaults are created by `CrowdVaultFactory`, which records them; the page refuses any address the factory didn't create, so a lookalike contract with a backdoor can't borrow the page. The page also refuses transactions on any network but its own.
- **The recipient is checked at deployment.** The vault forwards 1 wei to the recipient and refuses to deploy if it can't accept ETH. Payouts send the vault's whole balance, so ETH force-sent to the vault is swept to the recipient too.
- None of this has been audited. Get an audit before holding real funds.

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull request:

- **Contracts:** `forge build --sizes`, which fails if a contract exceeds the deployment size limit; the Foundry tests; and a check that the web app's copy of the ABI still matches the compiled contracts. After changing a contract, run `forge build` in `contracts/`, then `python3 scripts/gen-abi.py`.
- **vault-seal and vault-open on Linux, macOS (Apple silicon) and Windows:** the full test suite, then sealing sample files (empty, one byte, exactly one chunk, 5 MB, and a proven file) and opening them again. On macOS it also checks, for each tool, that an unsigned build reminds you to sign it and that signing silences the reminder; every later step there runs on the signed build.
- **Cross-platform:** each platform verifies and opens the files the other two sealed, byte for byte.
- **End to end:** `scripts/e2e.sh` on a local anvil chain: deploy through the factory, contribute, claim (which reveals the key), then open every file. Every step is checked, and any mismatch fails the run.
- **Web app:** a clean install from the lockfile, the type-checked build, and the single-file demo.

Foundry is pinned to the release everything was last verified with (`FOUNDRY_VERSION` in the workflow), so an upgrade is a deliberate one-line change.
