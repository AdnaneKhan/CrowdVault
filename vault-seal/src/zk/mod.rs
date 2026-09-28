//! Optional zero-knowledge proofs for sealed files ("proven files").
//!
//! A proven file comes with a proof of about 1.5 KB that, once the vault
//! reveals its key, the file will open to exactly the plaintext with the
//! fingerprint in its metadata. The proof reveals nothing else, and checking
//! it needs no secret. Nothing on-chain changes.
//!
//! Design, chosen so the proof is small and the statement is cheap:
//!
//! * **Curve cycle.** Proofs are Bulletproofs over secq256k1, whose group
//!   order is secp256k1's field prime. Circuits are therefore over the field
//!   where secp256k1 arithmetic is native, so tying the file to the vault's
//!   key (S = r·X) costs a few thousand gates instead of emulation.
//! * **Proof-friendly sealing.** Proven files use a Poseidon keystream and a
//!   Poseidon fingerprint over that same field: about 3.3 gates per byte,
//!   where SHA-256 alone would cost hundreds.
//! * **Only r is secret.** The plaintext inside the circuit is the public
//!   ciphertext minus the keystream, so the prover's only witness is r.
//!
//! Assumptions: discrete log in secq256k1 (proof soundness), CDH in secp256k1
//! and Poseidon as a PRF and hash (confidentiality and binding), and SHA-256
//! as a random oracle for Fiat–Shamir.

pub mod bp;
pub mod circuit;
pub mod cs;
pub mod field;
pub mod poseidon;
pub mod secq;

use k256::{AffinePoint, ProjectivePoint};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

use crate::{compressed, nonzero_scalar, parse_canonical, CampaignKey, CampaignSecret, Error, Result};
use bp::{Gens, Proof, Transcript};
use circuit::{coords, fingerprint_native, kdf_native, keystream_native, Statement};
use cs::Cs;
use field::Fp;

pub const FORMAT: &str = "crowdvault-seal/zk1";
pub const FILE_MAGIC: &[u8; 8] = b"CVZK1\0\0\0";
pub const PROOF_MAGIC: &[u8; 8] = b"CVPF1\0\0\0";
/// Bytes per field element of plaintext.
pub const CHUNK: usize = 31;
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024;

/// The `.meta.json` of a proven file.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ZkMetadata {
    pub format: String,
    /// X, compressed hex
    pub campaign_key: String,
    /// R = r·G, compressed hex
    pub sealed_key: String,
    pub file_name: String,
    pub plaintext_len: u64,
    /// Proven. Anyone holding the original recomputes it with
    /// `vault-seal fingerprint` or `vault-open fingerprint`.
    pub fingerprint: String,
    pub ciphertext_len: u64,
    pub ciphertext_sha256: String,
}

impl ZkMetadata {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(s: &str) -> Result<Self> {
        let m: Self = serde_json::from_str(s)?;
        if m.format != FORMAT {
            return Err(Error::Format);
        }
        Ok(m)
    }
}

pub fn chunks_for(len: u64) -> u64 {
    len.div_ceil(CHUNK as u64)
}

/// Size of the `.enc` file (None on overflow).
pub fn ciphertext_len_for(len: u64) -> Option<u64> {
    (FILE_MAGIC.len() as u64).checked_add(chunks_for(len).checked_mul(32)?)
}

/// Opt-in timing output for profiling: set VAULT_SEAL_PROFILE=1.
pub(crate) fn profile(label: &str, since: std::time::Instant) {
    if std::env::var_os("VAULT_SEAL_PROFILE").is_some() {
        eprintln!("  [profile] {label}: {:.2?}", since.elapsed());
    }
}

/// 31 bytes per element, big-endian, the last chunk zero-padded at the end.
fn encode(data: &[u8]) -> Vec<Fp> {
    data.chunks(CHUNK)
        .map(|c| {
            let mut b = [0u8; 32];
            b[1..1 + c.len()].copy_from_slice(c);
            Fp::from_canonical(&b).expect("below 2^248")
        })
        .collect()
}

/// Total: every element decodes, to its low 31 bytes, the last cut to the
/// length. The proof constrains the elements, not their byte ranges, so a
/// file that verified must always open. A fingerprint computed from a real
/// file pins every element to that file's valid encoding.
fn decode(elems: &[Fp], len: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len as usize);
    for (i, e) in elems.iter().enumerate() {
        let take = (len as usize - i * CHUNK).min(CHUNK);
        out.extend_from_slice(&e.to_bytes()[1..1 + take]);
    }
    out
}

pub fn name_hash(name: &str) -> Fp {
    poseidon::hash_to_field(b"crowdvault/zk1/file-name", &[name.as_bytes()])
}

/// The fingerprint a proven file commits to.
pub fn fingerprint(data: &[u8]) -> Fp {
    fingerprint_native(&encode(data), data.len() as u64)
}

pub fn fingerprint_hex(data: &[u8]) -> String {
    hex::encode(fingerprint(data).to_bytes())
}

fn keystream(k: Fp, n: usize) -> Vec<Fp> {
    (0..n.div_ceil(8) as u64).flat_map(|b| keystream_native(k, b)).take(n).collect()
}

fn transcript(meta: &ZkMetadata, enc: &[u8], log_n: u32) -> Transcript {
    let mut tr = Transcript::new(b"crowdvault/zk1/sealed-file");
    tr.append(b"format", meta.format.as_bytes());
    tr.append(b"campaign_key", meta.campaign_key.as_bytes());
    tr.append(b"sealed_key", meta.sealed_key.as_bytes());
    tr.append(b"file_name", meta.file_name.as_bytes());
    tr.append(b"plaintext_len", &meta.plaintext_len.to_be_bytes());
    tr.append(b"fingerprint", meta.fingerprint.as_bytes());
    tr.append(b"ciphertext", &Sha256::digest(enc));
    tr.append(b"log_n", &log_n.to_be_bytes());
    tr
}

struct Parsed {
    x: AffinePoint,
    r: AffinePoint,
    ct: Vec<Fp>,
    fp: Fp,
}

fn parse(meta: &ZkMetadata, enc: &[u8]) -> Result<Parsed> {
    if meta.format != FORMAT {
        return Err(Error::Format);
    }
    let x = parse_canonical(&meta.campaign_key)?;
    let r = parse_canonical(&meta.sealed_key)?;
    if Some(meta.ciphertext_len) != ciphertext_len_for(meta.plaintext_len) {
        return Err(Error::Malformed("sizes are inconsistent"));
    }
    if enc.len() as u64 != meta.ciphertext_len || hex::encode(Sha256::digest(enc)) != meta.ciphertext_sha256 {
        return Err(Error::CiphertextMismatch);
    }
    if &enc[..8] != FILE_MAGIC {
        return Err(Error::NotEncrypted);
    }
    let ct = enc[8..]
        .chunks(32)
        .map(|c| Fp::from_canonical(c.try_into().unwrap()))
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::Malformed("ciphertext element out of range"))?;
    let fpb: [u8; 32] = hex::decode(&meta.fingerprint)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(Error::Malformed("fingerprint"))?;
    let fp = Fp::from_canonical(&fpb).ok_or(Error::Malformed("fingerprint"))?;
    Ok(Parsed { x, r, ct, fp })
}

const UNUSABLE_KEY: Error = Error::Malformed("this campaign key can't be used for proofs");

pub struct Sealed {
    pub meta: ZkMetadata,
    pub encrypted: Vec<u8>,
    pub proof: Vec<u8>,
    pub gates: usize,
}

/// Seal `data` as a proven file. Refuses files over `max_bytes`.
pub fn seal_and_prove(campaign: &CampaignKey, file_name: &str, data: &[u8], max_bytes: u64) -> Result<Sealed> {
    let result = seal_and_prove_inner(campaign, file_name, data, max_bytes);
    crate::burn_stacks();
    result
}

fn seal_and_prove_inner(campaign: &CampaignKey, file_name: &str, data: &[u8], max_bytes: u64) -> Result<Sealed> {
    let len = data.len() as u64;
    if len > max_bytes {
        return Err(Error::TooLarge(len, max_bytes));
    }
    let x_pt = campaign.point();
    let r = nonzero_scalar();
    let r_pt = (ProjectivePoint::GENERATOR * *r).to_affine();
    let s_pt = Zeroizing::new((ProjectivePoint::from(x_pt) * *r).to_affine());
    let name_h = name_hash(file_name);

    let elems = encode(data);
    let k = Zeroizing::new(kdf_native(coords(&s_pt), coords(&r_pt), coords(&x_pt), name_h, len));
    let ks: Zeroizing<Vec<Fp>> = Zeroizing::new(keystream(*k, elems.len()).into_iter().collect());
    let ct: Vec<Fp> = elems.iter().zip(ks.iter()).map(|(m, k)| *m + *k).collect();
    let fp = fingerprint_native(&elems, len);

    let mut encrypted = FILE_MAGIC.to_vec();
    for c in &ct {
        encrypted.extend_from_slice(&c.to_bytes());
    }
    let meta = ZkMetadata {
        format: FORMAT.to_string(),
        campaign_key: campaign.compressed_hex(),
        sealed_key: hex::encode(compressed(&r_pt)),
        file_name: file_name.to_string(),
        plaintext_len: len,
        fingerprint: hex::encode(fp.to_bytes()),
        ciphertext_len: encrypted.len() as u64,
        ciphertext_sha256: hex::encode(Sha256::digest(&encrypted)),
    };

    let st = Statement { campaign: x_pt, sealed: r_pt, name_h, len, ct, fingerprint: fp };
    let t = std::time::Instant::now();
    let mut cs = Cs::new(true);
    let bits = Zeroizing::new(circuit::scalar_bits(&r));
    circuit::build(&mut cs, &st, &bits).ok_or(UNUSABLE_KEY)?;
    profile("build circuit and witness", t);
    if !cs.is_satisfied() {
        return Err(Error::Malformed("internal error: the honest witness does not satisfy the circuit"));
    }
    let n = cs.gates().next_power_of_two();
    let t = std::time::Instant::now();
    let gens = Gens::new(n);
    profile("generators", t);
    let t = std::time::Instant::now();
    let pf = bp::prove(&cs, &gens, &mut transcript(&meta, &encrypted, n.trailing_zeros()));
    profile("prove (total)", t);
    let mut proof = PROOF_MAGIC.to_vec();
    proof.extend(pf.to_bytes());

    // Never hand out a proof that doesn't verify.
    let t = std::time::Instant::now();
    verify_with(&meta, campaign, &encrypted, &proof, max_bytes, Some((&gens, &cs.cons)))?;
    profile("self-check verification", t);
    Ok(Sealed { meta, encrypted, proof, gates: cs.gates() })
}

/// Check a proven file before contributing. Needs no secret. Refuses files
/// over `max_bytes`, so a hostile "proven" file can't exhaust the verifier.
///
/// If this passes, the key the vault reveals opens the file to a
/// `plaintext_len`-byte file with the committed fingerprint; if that
/// fingerprint was computed from a known work, it is exactly that work.
pub fn verify(meta: &ZkMetadata, campaign: &CampaignKey, encrypted: &[u8], proof: &[u8], max_bytes: u64) -> Result<()> {
    verify_with(meta, campaign, encrypted, proof, max_bytes, None)
}

/// The self-check after proving can reuse the prover's generators and
/// constraints: the circuit's structure never depends on the witness.
type Reuse<'a> = Option<(&'a Gens, &'a [cs::Lc])>;

fn verify_with(
    meta: &ZkMetadata,
    campaign: &CampaignKey,
    encrypted: &[u8],
    proof: &[u8],
    max_bytes: u64,
    reuse: Reuse<'_>,
) -> Result<()> {
    if meta.plaintext_len > max_bytes {
        return Err(Error::TooLarge(meta.plaintext_len, max_bytes));
    }
    let p = parse(meta, encrypted)?;
    if p.x != campaign.point() {
        return Err(Error::WrongCampaign);
    }
    if proof.len() < 8 || &proof[..8] != PROOF_MAGIC {
        return Err(Error::MalformedProof);
    }
    let pf = Proof::from_bytes(&proof[8..]).ok_or(Error::MalformedProof)?;
    let st = Statement {
        campaign: p.x,
        sealed: p.r,
        name_h: name_hash(&meta.file_name),
        len: meta.plaintext_len,
        ct: p.ct,
        fingerprint: p.fp,
    };
    let (owned_cs, owned_gens);
    let (gens, cons) = match reuse {
        Some((g, c)) => (g, c),
        None => {
            let mut cs = Cs::new(false);
            circuit::build(&mut cs, &st, &[false; 256]).ok_or(UNUSABLE_KEY)?;
            owned_gens = Gens::new(cs.gates().next_power_of_two());
            owned_cs = cs;
            (&owned_gens, &owned_cs.cons[..])
        }
    };
    let n = gens.g.len();
    if pf.ls.len() != n.trailing_zeros() as usize {
        return Err(Error::BadProof);
    }
    if !bp::verify(cons, gens, &mut transcript(meta, encrypted, n.trailing_zeros()), &pf) {
        return Err(Error::BadProof);
    }
    Ok(())
}

/// Decrypt a proven file with the revealed campaign secret.
pub fn open(meta: &ZkMetadata, secret: &CampaignSecret, encrypted: &[u8]) -> Result<Vec<u8>> {
    let result = open_inner(meta, secret, encrypted);
    crate::burn_stacks();
    result
}

fn open_inner(meta: &ZkMetadata, secret: &CampaignSecret, encrypted: &[u8]) -> Result<Vec<u8>> {
    let p = parse(meta, encrypted)?;
    if secret.public().point() != p.x {
        return Err(Error::WrongSecret);
    }
    let s_pt = Zeroizing::new((ProjectivePoint::from(p.r) * *secret.scalar()).to_affine());
    let k = Zeroizing::new(kdf_native(coords(&s_pt), coords(&p.r), coords(&p.x), name_hash(&meta.file_name), meta.plaintext_len));
    let ks: Zeroizing<Vec<Fp>> = Zeroizing::new(keystream(*k, p.ct.len()).into_iter().collect());
    let elems: Vec<Fp> = p.ct.iter().zip(ks.iter()).map(|(c, k)| *c - *k).collect();
    if fingerprint_native(&elems, meta.plaintext_len) != p.fp {
        return Err(Error::FingerprintMismatch);
    }
    Ok(decode(&elems, meta.plaintext_len))
}

#[cfg(test)]
mod tests {
use super::*;

    /// End to end: after proving, neither the file key nor the shared
    /// secret's coordinates (as the prover holds them) remain in memory:
    /// not in the witness, the prover's vectors or any thread's stack.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_key_material_survives_proving() {
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        let data = b"proven and then forgotten".repeat(8);
        let sealed = seal_and_prove(&pk, "note.txt", &data, 64 * 1024).unwrap();
        let [(mk, kmask), (mx, xmask), (my, ymask)] = masked_secrets(&sealed, &sk, "note.txt", data.len() as u64);
        crate::burn_stack();
        assert!(!crate::memory_contains(&mk, &kmask), "file key survived proving");
        assert!(!crate::memory_contains(&mx, &xmask), "shared secret x survived proving");
        assert!(!crate::memory_contains(&my, &ymask), "shared secret y survived proving");
    }

    /// The file key and the shared secret's coordinates, masked. Derived in a
    /// frame of its own, so nothing of them outlives the call on this stack.
    #[cfg(target_os = "linux")]
    #[inline(never)]
    fn masked_secrets(sealed: &Sealed, sk: &CampaignSecret, name: &str, len: u64) -> [(Vec<u8>, Vec<u8>); 3] {
        let r_pt = parse_canonical(&sealed.meta.sealed_key).unwrap();
        let s_pt = Zeroizing::new((ProjectivePoint::from(r_pt) * *sk.scalar()).to_affine());
        let (x, y) = coords(&s_pt);
        let (x, y) = (Zeroizing::new(x), Zeroizing::new(y));
        let k = Zeroizing::new(kdf_native((*x, *y), coords(&r_pt), coords(&sk.public().point()), name_hash(name), len));
        [&*k, &*x, &*y].map(|v| crate::mask_secret(&mut limb_bytes(v)))
    }

    /// A field element exactly as it sits in memory (its limbs).
    #[cfg(target_os = "linux")]
    fn limb_bytes(v: &Fp) -> Vec<u8> {
        let size = std::mem::size_of::<Fp>();
        let mut out = vec![0u8; size];
        unsafe { std::ptr::copy_nonoverlapping((v as *const Fp).cast::<u8>(), out.as_mut_ptr(), size) };
        out
    }
    use crate::CampaignSecret;
    use circuit::add_mixed_native;
    use cs::Lc;
    use k256::elliptic_curve::group::Group;
    use k256::elliptic_curve::Field;
    use k256::Scalar;
    use rand_core::OsRng;
    use secq::{msm, Point};

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn secq_group_order_is_p() {
        let p = Point::hash_to_curve(b"test", 1);
        assert!(p.mul(&-Fp::ONE).add(&p).is_identity());
        assert!(!p.mul(&Fp::from_u64(5)).is_identity());
    }

    #[test]
    fn secq_encoding_roundtrips() {
        for i in 0..5 {
            let p = Point::hash_to_curve(b"test", i).mul(&Fp::random());
            assert!(Point::from_bytes(&p.to_bytes()).unwrap().equals(&p));
        }
        assert!(Point::from_bytes(&Point::IDENTITY.to_bytes()).unwrap().is_identity());
    }

    #[test]
    fn glv_split_recombines_and_endomorphism_matches() {
        let g = secq::glv();
        let p = Point::hash_to_curve(b"glv", 7);
        let pa = p.to_affine().unwrap();
        assert!(pa.endo().to_point().equals(&p.mul(&g.lambda)));
        for _ in 0..500 {
            let k = Fp::random();
            let [(n1, m1), (n2, m2)] = secq::glv_split(&k);
            let signed = |neg: bool, m: u128| if neg { -Fp::from_u128(m) } else { Fp::from_u128(m) };
            assert_eq!(signed(n1, m1) + signed(n2, m2) * g.lambda, k);
        }
    }

    #[test]
    fn generator_cache_reads_only_the_prefix_it_needs() {
        let label = b"cache-test";
        let pts: Vec<secq::Affine> = (0..300).map(|i| secq::Affine::hash_to_curve(label, i)).collect();
        let dir = std::env::temp_dir().join(format!("cv-cache-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gens.bin");
        secq::write_cache(&path, &pts);
        assert_eq!(secq::read_cache(&path, label, 100).unwrap(), pts[..100].to_vec());
        assert_eq!(secq::read_cache(&path, label, 500).unwrap(), pts);
        // Wrong label: the recomputed sample does not match.
        assert!(secq::read_cache(&path, b"other", 100).is_none());
        // Truncated file.
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(secq::read_cache(&path, label, 100).is_none());
        // A point off the curve inside the prefix.
        let mut bad = bytes.clone();
        bad[16 + 64 * 7 + 63] ^= 1;
        std::fs::write(&path, &bad).unwrap();
        assert!(secq::read_cache(&path, label, 100).is_none());
        // Damage past the prefix is not read at all.
        assert_eq!(secq::read_cache(&path, label, 5).unwrap(), pts[..5].to_vec());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn single_scalar_fold_handles_edge_scalars() {
        let n = 300;
        let p: Vec<secq::Affine> = (0..n).map(|i| secq::Affine::hash_to_curve(b"ep", i as u64)).collect();
        let q: Vec<secq::Affine> = (0..n).map(|i| secq::Affine::hash_to_curve(b"eq", i as u64)).collect();
        for s in [Fp::ONE, Fp::from_u64(2), Fp::from_u64(15), -Fp::ONE, secq::glv().lambda, Fp::from_u128(u128::MAX)] {
            let out = secq::fold_single(&s, &p, &q);
            for j in [0, n - 1] {
                assert!(out[j].to_point().equals(&p[j].to_point().add(&q[j].to_point().mul(&s))));
            }
        }
    }

    #[test]
    fn single_scalar_fold_matches_plain_arithmetic() {
        for n in [1usize, 5, 5000] {
            let p: Vec<secq::Affine> = (0..n).map(|i| secq::Affine::hash_to_curve(b"sp", i as u64)).collect();
            let q: Vec<secq::Affine> = (0..n).map(|i| secq::Affine::hash_to_curve(b"sq", i as u64)).collect();
            let s = Fp::random();
            let out = secq::fold_single(&s, &p, &q);
            for j in [0, n / 2, n - 1] {
                let want = p[j].to_point().add(&q[j].to_point().mul(&s));
                assert!(out[j].to_point().equals(&want));
            }
        }
    }

    #[test]
    fn batched_msm_matches_plain_including_collisions() {
        // Large enough for the batched path; repeated and negated points with
        // equal scalars force doublings and cancellations inside buckets.
        let n = 3000;
        let mut pts: Vec<secq::Affine> = (0..n).map(|i| secq::Affine::hash_to_curve(b"msm", i as u64 % 1000)).collect();
        for i in (0..n).step_by(7) {
            pts[i] = pts[i].neg();
        }
        let mut sc: Vec<Fp> = (0..n).map(|_| Fp::random()).collect();
        for i in 0..500 {
            sc[i + 1000] = sc[i];
            sc[i + 2000] = sc[i];
        }
        let naive = pts.iter().zip(&sc).fold(Point::IDENTITY, |a, (p, s)| a.add(&p.to_point().mul(s)));
        assert!(secq::msm_affine(&pts, &sc).equals(&naive));
    }

    #[test]
    fn batched_msm_is_linear_for_small_scalars() {
        // Mostly 0/1 scalars (as in witness commitments) pile into one bucket;
        // this used to be quadratic.
        let n = 1 << 14;
        let pts: Vec<secq::Affine> = (0..n).map(|i| secq::Affine::hash_to_curve(b"small", i as u64)).collect();
        let sc: Vec<Fp> = (0..n).map(|i| Fp::from_u64((i % 3 == 0) as u64)).collect();
        let t = std::time::Instant::now();
        let fast = secq::msm_affine(&pts, &sc);
        assert!(t.elapsed().as_secs() < 5);
        let want = pts.iter().zip(&sc).filter(|(_, s)| !s.is_zero()).fold(Point::IDENTITY, |a, (p, _)| a.add_affine(p));
        assert!(fast.equals(&want));
    }

    #[test]
    fn msm_matches_naive() {
        for n in [1usize, 9, 40] {
            let pts: Vec<Point> = (0..n).map(|i| Point::hash_to_curve(b"m", i as u64)).collect();
            let sc: Vec<Fp> = (0..n).map(|_| Fp::random()).collect();
            let naive = pts.iter().zip(&sc).fold(Point::IDENTITY, |a, (p, s)| a.add(&p.mul(s)));
            assert!(msm(&pts, &sc).equals(&naive));
        }
    }

    #[test]
    fn complete_addition_matches_k256() {
        let check = |p: ProjectivePoint, q: ProjectivePoint, lambda: Fp| {
            let (px, py) = coords(&p.to_affine());
            let (qx, qy) = coords(&q.to_affine());
            let (x3, y3, z3) = add_mixed_native((px * lambda, py * lambda, lambda), (qx, qy));
            let sum = p + q;
            if bool::from(sum.is_identity()) {
                assert!(z3.is_zero());
            } else {
                let (sx, sy) = coords(&sum.to_affine());
                let zi = z3.inv();
                assert_eq!((x3 * zi, y3 * zi), (sx, sy));
            }
        };
        let p = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
        let q = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
        for lambda in [Fp::ONE, Fp::random()] {
            check(p, q, lambda);
            check(p, p, lambda);
            check(p, -p, lambda);
        }
    }

    #[test]
    fn poseidon_gadget_matches_native() {
        let mut cs = Cs::new(true);
        let input: [Fp; poseidon::T] = std::array::from_fn(|_| Fp::random());
        let lanes: [Lc; poseidon::T] = std::array::from_fn(|i| Lc::var(cs.square(Lc::constant(input[i])).0));
        let out = circuit::perm_gadget(&mut cs, lanes);
        let mut native = input;
        poseidon::permute(&mut native);
        for i in 0..poseidon::T {
            assert_eq!(cs.value(&out[i]), native[i]);
        }
        assert!(cs.is_satisfied());
    }

    #[test]
    fn bulletproof_accepts_true_and_rejects_false_statements() {
        // Knowledge of a, b with a·b = 35 and a + b = 12.
        let make = |a: u64, b: u64, sum: u64, prover: bool| {
            let mut cs = Cs::new(prover);
            let (l, r, o) = cs.alloc(Fp::from_u64(a), Fp::from_u64(b));
            cs.constrain(Lc::var(o) + (-Fp::from_u64(35)));
            cs.constrain(Lc::var(l) + Lc::var(r) + (-Fp::from_u64(sum)));
            cs
        };
        let gens = Gens::new(4);
        let honest = make(5, 7, 12, true);
        assert!(honest.is_satisfied());
        let pf = bp::prove(&honest, &gens, &mut Transcript::new(b"t"));
        let pf = Proof::from_bytes(&pf.to_bytes()).unwrap();
        assert!(bp::verify(&make(0, 0, 12, false).cons, &gens, &mut Transcript::new(b"t"), &pf));
        // Same proof, different statement or transcript.
        assert!(!bp::verify(&make(0, 0, 13, false).cons, &gens, &mut Transcript::new(b"t"), &pf));
        assert!(!bp::verify(&make(0, 0, 12, false).cons, &gens, &mut Transcript::new(b"u"), &pf));
        // A prover without a valid witness.
        let cheat = make(5, 8, 12, true);
        let pf = bp::prove(&cheat, &gens, &mut Transcript::new(b"t"));
        assert!(!bp::verify(&make(0, 0, 12, false).cons, &gens, &mut Transcript::new(b"t"), &pf));
    }

    #[test]
    fn proven_files_verify_and_open() {
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        for len in [0usize, 31, 100] {
            let data = sample(len);
            let s = seal_and_prove(&pk, "art.bin", &data, DEFAULT_MAX_BYTES).unwrap();
            verify(&s.meta, &pk, &s.encrypted, &s.proof, DEFAULT_MAX_BYTES).unwrap();
            assert_eq!(open(&s.meta, &sk, &s.encrypted).unwrap(), data);
            assert_eq!(s.meta.fingerprint, fingerprint_hex(&data));
            assert!(s.proof.len() < 1700, "proof is {} bytes", s.proof.len());
        }
    }

    #[test]
    fn proofs_do_not_transfer_or_survive_tampering() {
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        let data = b"a small but important piece of art".to_vec();
        let s = seal_and_prove(&pk, "art.bin", &data, DEFAULT_MAX_BYTES).unwrap();

        let other = CampaignSecret::generate().public();
        assert!(matches!(verify(&s.meta, &other, &s.encrypted, &s.proof, DEFAULT_MAX_BYTES), Err(Error::WrongCampaign)));

        let mut m = s.meta.clone();
        m.file_name = "other.bin".into();
        assert!(matches!(verify(&m, &pk, &s.encrypted, &s.proof, DEFAULT_MAX_BYTES), Err(Error::BadProof)));

        let mut m = s.meta.clone();
        m.fingerprint = fingerprint_hex(b"something else entirely");
        assert!(matches!(verify(&m, &pk, &s.encrypted, &s.proof, DEFAULT_MAX_BYTES), Err(Error::BadProof)));

        let mut enc = s.encrypted.clone();
        enc[39] ^= 1;
        let mut m = s.meta.clone();
        m.ciphertext_sha256 = hex::encode(Sha256::digest(&enc));
        assert!(matches!(verify(&m, &pk, &enc, &s.proof, DEFAULT_MAX_BYTES), Err(Error::BadProof)));

        let mut p = s.proof.clone();
        p[100] ^= 1;
        assert!(verify(&s.meta, &pk, &s.encrypted, &p, DEFAULT_MAX_BYTES).is_err());

        let s2 = seal_and_prove(&pk, "art.bin", &data, DEFAULT_MAX_BYTES).unwrap();
        assert!(matches!(verify(&s.meta, &pk, &s.encrypted, &s2.proof, DEFAULT_MAX_BYTES), Err(Error::BadProof)));
    }

    #[test]
    fn the_wrong_key_cannot_be_proven() {
        // Build the real statement, then try to prove it with a different r.
        let pk = CampaignSecret::generate().public();
        let s = seal_and_prove(&pk, "art.bin", &sample(50), DEFAULT_MAX_BYTES).unwrap();
        let p = parse(&s.meta, &s.encrypted).unwrap();
        let st = Statement {
            campaign: p.x,
            sealed: p.r,
            name_h: name_hash("art.bin"),
            len: 50,
            ct: p.ct,
            fingerprint: p.fp,
        };
        let mut cs = Cs::new(true);
        circuit::build(&mut cs, &st, &circuit::scalar_bits(&Scalar::random(&mut OsRng))).unwrap();
        assert!(!cs.is_satisfied());
        let n = cs.gates().next_power_of_two();
        let gens = Gens::new(n);
        let pf = bp::prove(&cs, &gens, &mut transcript(&s.meta, &s.encrypted, n.trailing_zeros()));
        let mut forged = PROOF_MAGIC.to_vec();
        forged.extend(pf.to_bytes());
        assert!(matches!(verify(&s.meta, &pk, &s.encrypted, &forged, DEFAULT_MAX_BYTES), Err(Error::BadProof)));
    }

    /// Regression for the review finding: a creator seals elements that are not
    /// valid 31-byte chunks. The proof still verifies, and the file must still
    /// open (to bytes whose fingerprint is not the committed one, since they
    /// were never a real file).
    #[test]
    fn a_verified_file_always_opens() {
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        let (name, len) = ("art.bin", 31u64);
        let m = vec![Fp::from_canonical(&[0x42; 32]).unwrap()];
        let x_pt = pk.point();
        let r = nonzero_scalar();
        let r_pt = (ProjectivePoint::GENERATOR * *r).to_affine();
        let s_pt = (ProjectivePoint::from(x_pt) * *r).to_affine();
        let k = kdf_native(coords(&s_pt), coords(&r_pt), coords(&x_pt), name_hash(name), len);
        let ct: Vec<Fp> = m.iter().zip(keystream(k, 1)).map(|(m, k)| *m + k).collect();
        let fp = fingerprint_native(&m, len);
        let mut enc = FILE_MAGIC.to_vec();
        enc.extend_from_slice(&ct[0].to_bytes());
        let meta = ZkMetadata {
            format: FORMAT.into(),
            campaign_key: pk.compressed_hex(),
            sealed_key: hex::encode(compressed(&r_pt)),
            file_name: name.into(),
            plaintext_len: len,
            fingerprint: hex::encode(fp.to_bytes()),
            ciphertext_len: enc.len() as u64,
            ciphertext_sha256: hex::encode(Sha256::digest(&enc)),
        };
        let st = Statement { campaign: x_pt, sealed: r_pt, name_h: name_hash(name), len, ct, fingerprint: fp };
        let mut cs = Cs::new(true);
        circuit::build(&mut cs, &st, &circuit::scalar_bits(&r)).unwrap();
        let n = cs.gates().next_power_of_two();
        let pf = bp::prove(&cs, &Gens::new(n), &mut transcript(&meta, &enc, n.trailing_zeros()));
        let mut proof = PROOF_MAGIC.to_vec();
        proof.extend(pf.to_bytes());

        verify(&meta, &pk, &enc, &proof, DEFAULT_MAX_BYTES).unwrap();
        let opened = open(&meta, &sk, &enc).unwrap();
        assert_eq!(opened.len(), 31);
        assert_ne!(fingerprint_hex(&opened), meta.fingerprint);
    }

    #[test]
    fn verification_refuses_oversized_files() {
        let pk = CampaignSecret::generate().public();
        let s = seal_and_prove(&pk, "a", &sample(40), DEFAULT_MAX_BYTES).unwrap();
        assert!(matches!(verify(&s.meta, &pk, &s.encrypted, &s.proof, 39), Err(Error::TooLarge(40, 39))));
    }

    #[test]
    fn absurd_sizes_are_rejected_not_wrapped() {
        assert_eq!(ciphertext_len_for(u64::MAX), None);
        assert_eq!(crate::ciphertext_len_for(u64::MAX), None);
    }

    #[test]
    fn open_checks_the_fingerprint_and_size_limit_holds() {
        let sk = CampaignSecret::generate();
        let s = seal_and_prove(&sk.public(), "a", &sample(40), DEFAULT_MAX_BYTES).unwrap();
        let mut m = s.meta.clone();
        m.fingerprint = fingerprint_hex(b"promised");
        assert!(matches!(open(&m, &sk, &s.encrypted), Err(Error::FingerprintMismatch)));
        assert!(matches!(
            seal_and_prove(&sk.public(), "a", &sample(11), 10),
            Err(Error::TooLarge(11, 10))
        ));
    }
}
