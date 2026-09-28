# Performance

All measurements are from one slow cloud core (AVX2, SHA-NI) with release builds, taking the fastest of several runs because this machine has occasional 3x slowdowns unrelated to the code. Everything that can run in parallel does, so machines with more cores gain more. Those gains are expected, not measured, because this machine has one core.

## Proven files (`--prove`)

| File | Prove: first version → first pass → now | Verify: first version → first pass → now | Proof |
| --- | --- | --- | --- |
| 1 KB | 5.0 s → 2.4 s → 1.7 s | 0.82 s → 0.36 s → 0.20 s | 1,291 bytes |
| 16 KB | 38.2 s → 16.8 s → 11.0 s | 6.4 s → 2.4 s → 1.0 s | 1,489 bytes |
| 64 KB | 148 s → 72.9 s → 41.0 s | 25.0 s → 9.1 s → 3.7 s | 1,621 bytes |

The proof format has never changed, and proofs made by earlier versions still verify.

### What changed in the second pass

- **Circuit building is precomputed where it can be.** Poseidon's partial rounds are the same linear algebra in every permutation, so their coefficients are worked out once. Each permutation then only combines its own wires. At 16 KB, circuit building went from 935 ms to 118 ms. It had been about 40% of verification time.
- **Multi-scalar multiplication uses batch-affine buckets.** Buckets accumulate with batched affine additions, one inversion per 512 points, at about 6 field multiplications per point instead of 11.
  - Scalars are recoded into signed digits, which halves the buckets. The carry into each window is exactly one bit of the scalar, so every window computes its own digits with no digit array.
  - When a point's bucket is already in the current batch, the point goes into that bucket's overflow sum instead of waiting. An earlier version made it wait, and that turned quadratic when digits are concentrated (a narrow top window, or the 0/1 values in witness commitments). A regression test covers it.
  - Small multiplications with full-size scalars also split each scalar with GLV. That's 20% faster at 2¹⁴ points, but slower for large inputs and for small scalars, so those don't use it.
- **Each fold uses one scalar instead of two.** A factor shared by a whole round is carried in the scalars, not the points: g′ = x⁻¹·(G_lo + x²·G_hi), and likewise for h.
  - Each half-scalar is recoded in width-4 NAF.
  - Each step fuses a doubling and an addition (Eisenträger–Lauter–Montgomery), and squaring has its own routine.
  - Folding works in 1,024-point batches. Above that, a batch's working set leaves L2 cache and folding gets 3x slower (measured).
  - Folding went from 60 µs to 41 µs per point.
- **The generator cache reads only what a proof needs.** The cache holds as many generators as the largest proof ever made needed. Every run used to read and check all of them, so at 1 KB loading took 148 ms. It now reads and checks only the prefix it uses, in 6 ms.
- **The three witness commitments are computed in parallel.**

Tried and dropped, because they measured no better:

- A straight-line field multiplier in place of the loop-based one.
- Merging batch inversions into the surrounding arithmetic passes. I kept the merged form because it allowed deleting dead code, not for speed.
- Width-5 NAF in folds: 3% faster, but its tables sit at the edge of L2 cache.
- GLV for large multi-scalar multiplications.

The multiplier's latency equals its throughput, so reordering independent multiplications can't help either.

### Where the time goes now

At 16 KB (`VAULT_SEAL_PROFILE=1`):

| Step | Time |
| --- | --- |
| Folding | 5.6 s |
| Multi-scalar multiplications | 4.2 s (commitments 2.1 s, inner-product rounds 2.1 s) |
| Self-check | 0.9 s |
| Everything else | 0.3 s |

Folding is within about 30% of its operation count. The field multiply takes 25 ns.

### Next, in order of value

1. **128-bit challenges in the inner-product argument.** With the shared-factor folds, the g folds would use 64-bit GLV halves, which cuts folding by about a quarter (about 12% of proving). This changes the proof format and gives each round of that argument a soundness error of about 2⁻¹²⁰, which is standard practice but a real reduction in margin, so it's a decision rather than an optimization.
2. **A faster field inversion** (Bernstein–Yang safegcd in place of exponentiation): about 3 to 4%.
3. **One proof for a folder of files,** sharing the fixed key-derivation cost and the generators.

An earlier version of this list proposed halving the circuit by replacing the Poseidon fingerprint with a Pedersen commitment taken from the proof's own witness commitment. As sketched it's unsound. The prover chooses the rest of that commitment freely, so it could shift values between the published fingerprint and its own part, and the fingerprint would no longer bind the plaintext. Doing it properly needs committed vector inputs on dedicated generators, which is real protocol work.

## Ordinary sealing

| 256 MB file, one core | First version (ChaCha20-Poly1305, SHA-256) | ring's ChaCha20-Poly1305 | Now (AES-256-GCM, BLAKE3) |
| --- | --- | --- | --- |
| seal | 849 ms | 646 ms | 274 ms |
| open | 699 ms | 437 ms | 205 ms |
| verify | 232 ms | 234 ms | 102 ms |

Sealing writes into a fresh directory. On ext4, sealing over an existing output file takes about 90 ms longer, because ext4 starts writeback early when a file is renamed over another.

The format is `crowdvault-seal/2` (magic `CVENC2`). Files in the earlier format are refused, not opened.

How the new format works:

- **AES-256-GCM from ring** encrypts each chunk (7.6 GB/s on this core, against 1.8 GB/s for ChaCha20-Poly1305). It keeps the same STREAM chunking and nonces, and a test checks every chunk against RustCrypto's reference STREAM encryptor.
- **BLAKE3** hashes the plaintext and the ciphertext (5.75 GB/s on one thread here, against 1.38 GB/s for SHA-256). Unlike SHA-256, it splits across cores. It also derives the file key, in key-derivation mode. The hashes match the official BLAKE3 implementation, so `b3sum` checks them.
- **Batches of 64 chunks (4 MiB).** Each batch is hashed, encrypted and hashed again across all cores when there are several. Reading runs ahead and writing runs behind on their own threads, overlapping the work. With one core, everything runs inline.

With the hashing and encryption this fast, what remains on one core is mostly memory traffic:

| Step | Time |
| --- | --- |
| Hash the plaintext | about 47 ms |
| Encrypt | about 35 ms |
| Hash the ciphertext | about 47 ms |
| Read | about 38 ms |
| Write | about 70 ms |
| Copy each batch into the output buffer | about 20 ms |

With several cores, the three compute steps split across them, and a disk is the limit.

Wiping ephemeral keys costs nothing measurable. It covers the scalar r, the shared secret, the file key and the AES key schedule, and every freed heap block through the wipe-on-free allocator. A 16 KB proof takes 11.0 s with or without it.
