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
//!
//! A proven file is one file, in the [`crate::container`] layout:
//!
//! ```text
//!   FILE_MAGIC ‖ ciphertext elements (32 bytes each) ‖ proof ‖ footer ‖ footer length ‖ FOOTER_MAGIC
//! ```
//!
//! Every footer field that matters is in the proof's transcript, so an edited
//! footer fails verification.

pub mod bp;
pub mod circuit;
pub mod cs;
pub mod field;
pub mod poseidon;
pub mod secq;

use std::io::{Read, Seek};

use k256::{AffinePoint, ProjectivePoint};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

use crate::{compressed, container, nonzero_scalar, parse_canonical, read_full, CampaignKey, CampaignSecret, Error, Result};
use bp::{Gens, Proof, Transcript};
use circuit::{coords, fingerprint_native, kdf_native, keystream_native, Statement};
use cs::Cs;
use field::Fp;

pub const FORMAT: &str = "crowdvault-seal/zk2";
pub const FILE_MAGIC: &[u8; 8] = b"CVZK2\0\0\0";
pub const PROOF_MAGIC: &[u8; 8] = b"CVPF1\0\0\0";
/// Bytes per field element of plaintext.
pub const CHUNK: usize = 31;
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024;

/// The footer of a proven file.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// Bytes of proof between the ciphertext and the footer.
    pub proof_len: u64,
}

impl ZkMetadata {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(s: &[u8]) -> Result<Self> {
        let m: Self = serde_json::from_slice(s)?;
        if m.format != FORMAT {
            return Err(Error::Format);
        }
        Ok(m)
    }
}

pub fn chunks_for(len: u64) -> u64 {
    len.div_ceil(CHUNK as u64)
}

/// Size of the magic and ciphertext elements, the part the proof commits to
/// (None on overflow).
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
    if Some(enc.len() as u64) != ciphertext_len_for(meta.plaintext_len) {
        return Err(Error::Malformed("sizes are inconsistent"));
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
    /// The whole `.sealed` file: ciphertext, proof and footer.
    pub file: Vec<u8>,
    pub gates: usize,
}

/// A proven file's parts: its metadata, the magic and ciphertext elements the
/// proof commits to, and the proof. With `max_bytes`, a file claiming more
/// plaintext than that is refused before its body is read.
fn read_parts<R: Read + Seek>(file: &mut R, max_bytes: Option<u64>) -> Result<(ZkMetadata, Vec<u8>, Vec<u8>)> {
    let f = container::read_footer(file)?;
    if &f.magic != FILE_MAGIC {
        return Err(Error::Format);
    }
    let meta = ZkMetadata::from_json(&f.json)?;
    if let Some(max) = max_bytes {
        if meta.plaintext_len > max {
            return Err(Error::TooLarge(meta.plaintext_len, max));
        }
    }
    let enc_len = ciphertext_len_for(meta.plaintext_len).ok_or(Error::Malformed("sizes are inconsistent"))?;
    if (FILE_MAGIC.len() as u64).checked_add(f.body_len) != enc_len.checked_add(meta.proof_len) {
        return Err(Error::Malformed("sizes are inconsistent"));
    }
    let mut enc = FILE_MAGIC.to_vec();
    enc.resize(enc_len as usize, 0);
    let mut proof = vec![0u8; meta.proof_len as usize];
    container::seek_body(file)?;
    if read_full(file, &mut enc[FILE_MAGIC.len()..])? != enc.len() - FILE_MAGIC.len() || read_full(file, &mut proof)? != proof.len() {
        return Err(Error::Truncated);
    }
    Ok((meta, enc, proof))
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
    let mut meta = ZkMetadata {
        format: FORMAT.to_string(),
        campaign_key: campaign.compressed_hex(),
        sealed_key: hex::encode(compressed(&r_pt)),
        file_name: file_name.to_string(),
        plaintext_len: len,
        fingerprint: hex::encode(fp.to_bytes()),
        proof_len: 0,
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
    meta.proof_len = proof.len() as u64;

    // Never hand out a proof that doesn't verify.
    let t = std::time::Instant::now();
    verify_with(&meta, campaign, &encrypted, &proof, max_bytes, Some((&gens, &cs.cons)))?;
    profile("self-check verification", t);
    let mut file = encrypted;
    file.extend_from_slice(&proof);
    file.extend(container::trailer(meta.to_json()?.as_bytes())?);
    Ok(Sealed { meta, file, gates: cs.gates() })
}

/// Check a proven `.sealed` file before contributing. Needs no secret.
/// Refuses files over `max_bytes` before reading their body, so a hostile
/// "proven" file can't exhaust the verifier.
///
/// If this passes, the key the vault reveals opens the file to a
/// `plaintext_len`-byte file with the committed fingerprint; if that
/// fingerprint was computed from a known work, it is exactly that work.
pub fn verify<R: Read + Seek>(file: &mut R, campaign: &CampaignKey, max_bytes: u64) -> Result<ZkMetadata> {
    let (meta, enc, proof) = read_parts(file, Some(max_bytes))?;
    verify_with(&meta, campaign, &enc, &proof, max_bytes, None)?;
    Ok(meta)
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

/// Decrypt a proven `.sealed` file with the revealed campaign secret.
pub fn open<R: Read + Seek>(file: &mut R, secret: &CampaignSecret) -> Result<(ZkMetadata, Vec<u8>)> {
    let (meta, enc, _) = read_parts(file, None)?;
    let result = open_inner(&meta, secret, &enc);
    crate::burn_stacks();
    Ok((meta, result?))
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

    /// The ciphertext (with magic) and proof inside a sealed file.
    fn parts(s: &Sealed) -> (Vec<u8>, Vec<u8>) {
        let (_, enc, proof) = read_parts(&mut std::io::Cursor::new(&s.file), None).unwrap();
        (enc, proof)
    }

    fn verify_parts(meta: &ZkMetadata, pk: &CampaignKey, enc: &[u8], proof: &[u8], max: u64) -> Result<()> {
        verify_with(meta, pk, enc, proof, max, None)
    }

    fn verify_file(file: &[u8], pk: &CampaignKey, max: u64) -> Result<ZkMetadata> {
        verify(&mut std::io::Cursor::new(file), pk, max)
    }

    fn open_file(file: &[u8], sk: &CampaignSecret) -> Result<Vec<u8>> {
        open(&mut std::io::Cursor::new(file), sk).map(|(_, pt)| pt)
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
            assert_eq!(verify_file(&s.file, &pk, DEFAULT_MAX_BYTES).unwrap(), s.meta);
            assert_eq!(open_file(&s.file, &sk).unwrap(), data);
            assert_eq!(s.meta.fingerprint, fingerprint_hex(&data));
            assert!(s.meta.proof_len < 1700, "proof is {} bytes", s.meta.proof_len);
            let m = crate::read_metadata(&mut std::io::Cursor::new(&s.file)).unwrap();
            assert!(matches!(m, crate::SealedMeta::Proven(m) if m == s.meta));
        }
    }

    #[test]
    fn proofs_do_not_transfer_or_survive_tampering() {
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        let data = b"a small but important piece of art".to_vec();
        let s = seal_and_prove(&pk, "art.bin", &data, DEFAULT_MAX_BYTES).unwrap();
        let (encrypted, proof) = parts(&s);

        let other = CampaignSecret::generate().public();
        assert!(matches!(verify_file(&s.file, &other, DEFAULT_MAX_BYTES), Err(Error::WrongCampaign)));

        let mut m = s.meta.clone();
        m.file_name = "other.bin".into();
        assert!(matches!(verify_parts(&m, &pk, &encrypted, &proof, DEFAULT_MAX_BYTES), Err(Error::BadProof)));

        let mut m = s.meta.clone();
        m.fingerprint = fingerprint_hex(b"something else entirely");
        assert!(matches!(verify_parts(&m, &pk, &encrypted, &proof, DEFAULT_MAX_BYTES), Err(Error::BadProof)));

        let mut enc = encrypted.clone();
        enc[39] ^= 1;
        assert!(matches!(verify_parts(&s.meta, &pk, &enc, &proof, DEFAULT_MAX_BYTES), Err(Error::BadProof)));

        let mut p = proof.clone();
        p[100] ^= 1;
        assert!(verify_parts(&s.meta, &pk, &encrypted, &p, DEFAULT_MAX_BYTES).is_err());

        let s2 = seal_and_prove(&pk, "art.bin", &data, DEFAULT_MAX_BYTES).unwrap();
        let (_, proof2) = parts(&s2);
        assert!(matches!(verify_parts(&s.meta, &pk, &encrypted, &proof2, DEFAULT_MAX_BYTES), Err(Error::BadProof)));
    }

    #[test]
    fn the_wrong_key_cannot_be_proven() {
        // Build the real statement, then try to prove it with a different r.
        let pk = CampaignSecret::generate().public();
        let s = seal_and_prove(&pk, "art.bin", &sample(50), DEFAULT_MAX_BYTES).unwrap();
        let (encrypted, _) = parts(&s);
        let p = parse(&s.meta, &encrypted).unwrap();
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
        let pf = bp::prove(&cs, &gens, &mut transcript(&s.meta, &encrypted, n.trailing_zeros()));
        let mut forged = PROOF_MAGIC.to_vec();
        forged.extend(pf.to_bytes());
        assert!(matches!(verify_parts(&s.meta, &pk, &encrypted, &forged, DEFAULT_MAX_BYTES), Err(Error::BadProof)));
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
            proof_len: 0,
        };
        let st = Statement { campaign: x_pt, sealed: r_pt, name_h: name_hash(name), len, ct, fingerprint: fp };
        let mut cs = Cs::new(true);
        circuit::build(&mut cs, &st, &circuit::scalar_bits(&r)).unwrap();
        let n = cs.gates().next_power_of_two();
        let pf = bp::prove(&cs, &Gens::new(n), &mut transcript(&meta, &enc, n.trailing_zeros()));
        let mut proof = PROOF_MAGIC.to_vec();
        proof.extend(pf.to_bytes());

        verify_parts(&meta, &pk, &enc, &proof, DEFAULT_MAX_BYTES).unwrap();
        let opened = open_inner(&meta, &sk, &enc).unwrap();
        assert_eq!(opened.len(), 31);
        assert_ne!(fingerprint_hex(&opened), meta.fingerprint);
    }

    #[test]
    fn verification_refuses_oversized_files() {
        let pk = CampaignSecret::generate().public();
        let s = seal_and_prove(&pk, "a", &sample(40), DEFAULT_MAX_BYTES).unwrap();
        assert!(matches!(verify_file(&s.file, &pk, 39), Err(Error::TooLarge(40, 39))));
    }

    /// A hostile file claiming a huge plaintext is refused from its footer
    /// alone, before any of its body is read.
    #[test]
    fn oversized_claims_are_refused_before_reading_the_body() {
        let pk = CampaignSecret::generate().public();
        let s = seal_and_prove(&pk, "a", &sample(40), DEFAULT_MAX_BYTES).unwrap();
        let mut m = s.meta.clone();
        m.plaintext_len = 1 << 40;
        let mut file = FILE_MAGIC.to_vec();
        file.extend(crate::container::trailer(m.to_json().unwrap().as_bytes()).unwrap());
        assert!(matches!(verify_file(&file, &pk, DEFAULT_MAX_BYTES), Err(Error::TooLarge(_, _))));
        assert!(matches!(open_file(&file, &CampaignSecret::generate()), Err(Error::Malformed("sizes are inconsistent"))));
    }

    #[test]
    fn edited_footer_or_body_fails_as_a_whole_file() {
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        let s = seal_and_prove(&pk, "art.bin", b"proven, in one file", DEFAULT_MAX_BYTES).unwrap();
        let (encrypted, proof) = parts(&s);
        let rebuild = |m: &ZkMetadata, enc: &[u8], proof: &[u8]| {
            let mut f = enc.to_vec();
            f.extend_from_slice(proof);
            f.extend(crate::container::trailer(m.to_json().unwrap().as_bytes()).unwrap());
            f
        };
        let mut m = s.meta.clone();
        m.fingerprint = fingerprint_hex(b"a different promise");
        assert!(matches!(verify_file(&rebuild(&m, &encrypted, &proof), &pk, DEFAULT_MAX_BYTES), Err(Error::BadProof)));
        let mut m = s.meta.clone();
        m.proof_len += 1;
        assert!(matches!(verify_file(&rebuild(&m, &encrypted, &proof), &pk, DEFAULT_MAX_BYTES), Err(Error::Malformed(_))));
        let mut file = s.file.clone();
        file[8] ^= 1;
        assert!(verify_file(&file, &pk, DEFAULT_MAX_BYTES).is_err());
        let mut longer = s.file.clone();
        longer.push(0);
        assert!(matches!(verify_file(&longer, &pk, DEFAULT_MAX_BYTES), Err(Error::NoFooter)));
        let mut old = s.file.clone();
        old[..8].copy_from_slice(b"CVZK1\0\0\0");
        assert!(matches!(open_file(&old, &sk), Err(Error::OldFormat)));
    }

    #[test]
    fn absurd_sizes_are_rejected_not_wrapped() {
        assert_eq!(ciphertext_len_for(u64::MAX), None);
        assert_eq!(crate::body_len_for(u64::MAX), None);
    }

    #[test]
    fn open_checks_the_fingerprint_and_size_limit_holds() {
        let sk = CampaignSecret::generate();
        let s = seal_and_prove(&sk.public(), "a", &sample(40), DEFAULT_MAX_BYTES).unwrap();
        let (encrypted, _) = parts(&s);
        let mut m = s.meta.clone();
        m.fingerprint = fingerprint_hex(b"promised");
        assert!(matches!(open_inner(&m, &sk, &encrypted), Err(Error::FingerprintMismatch)));
        assert!(matches!(
            seal_and_prove(&sk.public(), "a", &sample(11), 10),
            Err(Error::TooLarge(11, 10))
        ));
    }
}
