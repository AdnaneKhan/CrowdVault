//! The library behind the CrowdVault tools: `vault-seal` (creators and the
//! coordinator) and `vault-open` (backers).
//!
//! Sealing turns a file into one `<name>.sealed` file: the content encrypted
//! in 64 KiB chunks (STREAM construction over AES-256-GCM), so files of any
//! size stream through without being held in memory, followed by a footer of
//! JSON metadata: the sealed key plus the file's name, size and BLAKE3 hash.
//! See [`container`] for the layout.
//!
//! ```text
//!   r           ← random scalar
//!   sealed_key  = R = r·G                       (in the footer)
//!   file key K  = BLAKE3-derive-key(context, r·X ‖ R ‖ X ‖ format ‖ name ‖ chunk size)
//!   .sealed     = MAGIC ‖ STREAM-AES-256-GCM(K, file) ‖ footer ‖ footer length ‖ FOOTER_MAGIC
//!                 (the last chunk also authenticates the footer, byte for byte)
//! ```
//!
//! After the reveal, anyone computes K from x·R, because x·R = r·X.
//!
//! What anyone can check before the reveal, with certainty and no trust:
//! the footer names the vault's campaign key X, and `sealed_key` is a valid
//! curve point. K is then a fixed function of x and public data, so the key
//! the contract will reveal (it enforces x·G = X) is guaranteed to produce
//! exactly this file key. There is no wrapped blob that could turn out not to
//! open.
//!
//! What is trusted: that the creator encrypted the promised content
//! under that key. After the reveal, [`open`] detects any mismatch against the
//! creator's committed hash, and anyone can reproduce it.
//!
//! The whole footer is bound in: the name and format feed the key, and the
//! last chunk authenticates the footer's exact bytes, so a file with any edit
//! to its metadata will not open.
//!
//! Ephemeral secrets are wiped as soon as they are used: r, r·X and K live in
//! zeroizing wrappers, the AES key schedule sits in its own allocation that is
//! locked out of swap where allowed and overwritten before release, and every
//! seal and open ends by overwriting the stacks of all threads involved
//! ([`burn_stacks`]), where moves and library internals leave stray copies.

pub mod container;
pub mod zk;

use std::io::{self, Read, Seek, Write};

use rayon::prelude::*;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::{Field, PrimeField};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use zeroize::{Zeroize, Zeroizing};

pub const FORMAT: &str = "crowdvault-seal/3";
pub const FILE_MAGIC: &[u8; 8] = b"CVSEAL3\0";
pub const CHUNK_SIZE: usize = 64 * 1024;
const TAG_LEN: u64 = 16;
/// A chunk on disk: ciphertext and its tag.
const CT_CHUNK: usize = CHUNK_SIZE + TAG_LEN as usize;
/// Chunks per batch (4 MiB), enough to split across cores.
const BATCH: usize = 64;
/// BLAKE3 key-derivation context: hard-coded, unique to this use.
const KEY_CONTEXT: &str = "CrowdVault vault-seal 2026-09-28 file key v3";
const CHUNK_AAD: &[u8] = b"crowdvault/3/chunk";
const LAST_CHUNK_AAD: &[u8] = b"crowdvault/3/last-chunk";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported metadata format (expected {FORMAT})")]
    Format,
    #[error("invalid point encoding")]
    BadPoint,
    #[error("invalid secret encoding")]
    BadScalar,
    #[error("metadata is malformed: {0}")]
    Malformed(&'static str),
    #[error("this file was sealed to a different campaign key")]
    WrongCampaign,
    #[error("secret does not match the campaign key")]
    WrongSecret,
    #[error("not a sealed CrowdVault file")]
    NotEncrypted,
    #[error("this is the earlier two-file format (a .enc beside a .meta.json), which this version doesn't read; seal the original again")]
    OldFormat,
    #[error("sealed file is incomplete, or has extra data at the end: its metadata footer is missing")]
    NoFooter,
    #[error("sealed file or its metadata was altered, corrupted or reordered")]
    Decrypt,
    #[error("sealed file is truncated")]
    Truncated,
    #[error("sealed file has unexpected data after the end")]
    TrailingData,
    #[error("decrypted file does not match the hash the creator committed to (creator fault)")]
    PlaintextHash,
    #[error("proof is invalid: it does not show that this file opens as committed")]
    BadProof,
    #[error("proof is missing or malformed")]
    MalformedProof,
    #[error("file is {0} bytes; proofs are limited to {1} bytes (raise the limit with --max-kib)")]
    TooLarge(u64, u64),
    #[error("decrypted file does not match the fingerprint the creator committed to")]
    FingerprintMismatch,
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

// ============================================================ keys

/// Campaign secret x. Zeroized on drop.
pub struct CampaignSecret(Zeroizing<[u8; 32]>);

impl CampaignSecret {
    pub fn generate() -> Self {
        Self(Zeroizing::new(nonzero_scalar().to_bytes().into()))
    }

    /// Parse 32-byte big-endian hex, with or without `0x`, as the contract's
    /// `revealedKey()` / `Claimed` event returns it.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim().trim_start_matches("0x");
        if s.is_empty() || s.len() > 64 {
            return Err(Error::BadScalar);
        }
        let padded = Zeroizing::new(format!("{s:0>64}"));
        let bytes = Zeroizing::new(hex::decode(&*padded).map_err(|_| Error::BadScalar)?);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let sc = Option::<Scalar>::from(Scalar::from_repr(arr.into())).ok_or(Error::BadScalar)?;
        if bool::from(sc.is_zero()) {
            return Err(Error::BadScalar);
        }
        Ok(Self(Zeroizing::new(arr)))
    }

    pub(crate) fn scalar(&self) -> Zeroizing<Scalar> {
        Zeroizing::new({
            Scalar::from_repr((*self.0).into()).unwrap()
        })
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(*self.0))
    }

    pub fn public(&self) -> CampaignKey {
        CampaignKey((ProjectivePoint::GENERATOR * *self.scalar()).to_affine())
    }
}

/// Campaign public key X.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignKey(AffinePoint);

impl CampaignKey {
    /// Accepts SEC1 compressed (33 bytes) or uncompressed (65 bytes) hex.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim().trim_start_matches("0x")).map_err(|_| Error::BadPoint)?;
        Ok(Self(parse_point(&bytes)?))
    }

    /// From the contract's `keyX()` / `keyY()` values.
    pub fn from_xy(x: &[u8; 32], y: &[u8; 32]) -> Result<Self> {
        let ep = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        Ok(Self(parse_encoded(&ep)?))
    }

    pub fn compressed_hex(&self) -> String {
        hex::encode(compressed(&self.0))
    }

    /// (keyX, keyY) as 0x-prefixed 32-byte hex, for the contract constructor.
    pub fn xy_hex(&self) -> (String, String) {
        let ep = self.0.to_encoded_point(false);
        (format!("0x{}", hex::encode(ep.x().unwrap())), format!("0x{}", hex::encode(ep.y().unwrap())))
    }

    /// Ethereum address of X, equal to the contract's `keyAddress()`.
    pub fn eth_address(&self) -> String {
        let ep = self.0.to_encoded_point(false);
        let h = Keccak256::digest(&ep.as_bytes()[1..]);
        format!("0x{}", hex::encode(&h[12..]))
    }

    pub(crate) fn point(&self) -> AffinePoint {
        self.0
    }

    /// True iff `secret` is the discrete log of this key.
    pub fn matches(&self, secret: &CampaignSecret) -> bool {
        secret.public() == *self
    }
}

pub(crate) fn compressed(p: &AffinePoint) -> Vec<u8> {
    p.to_encoded_point(true).as_bytes().to_vec()
}

fn parse_point(bytes: &[u8]) -> Result<AffinePoint> {
    let ep = EncodedPoint::from_bytes(bytes).map_err(|_| Error::BadPoint)?;
    parse_encoded(&ep)
}

/// Metadata keys must be the exact 33-byte compressed encoding. Other valid
/// SEC1 forms (uncompressed, compact) are refused, so one footer can only
/// ever mean one point and one file key.
pub(crate) fn parse_canonical(hex_str: &str) -> Result<AffinePoint> {
    let bytes = hex::decode(hex_str).map_err(|_| Error::BadPoint)?;
    let p = parse_point(&bytes)?;
    if bytes.len() != 33 || compressed(&p) != bytes {
        return Err(Error::BadPoint);
    }
    Ok(p)
}

fn parse_encoded(ep: &EncodedPoint) -> Result<AffinePoint> {
    let p = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(ep)).ok_or(Error::BadPoint)?;
    if bool::from(ProjectivePoint::from(p).is_identity()) {
        return Err(Error::BadPoint);
    }
    Ok(p)
}

pub(crate) fn nonzero_scalar() -> Zeroizing<Scalar> {
    loop {
        let s = Scalar::random(&mut OsRng);
        if !bool::from(s.is_zero()) {
            return Zeroizing::new(s);
        }
    }
}

// ============================================================ metadata

/// The footer of an ordinary sealed file.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub format: String,
    /// X, compressed hex
    pub campaign_key: String,
    /// R = r·G, compressed hex. The file key is sealed here: x·R recovers it.
    pub sealed_key: String,
    pub file_name: String,
    pub plaintext_len: u64,
    /// BLAKE3 of the plaintext, hex. The last chunk authenticates it.
    pub plaintext_blake3: String,
    pub chunk_size: u64,
}

fn put(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

/// The last chunk authenticates the footer exactly as written, so no byte of
/// the metadata can change without the file failing to open.
fn last_chunk_aad(footer: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    put(&mut t, LAST_CHUNK_AAD);
    put(&mut t, footer);
    t
}

impl Metadata {
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

    fn check_shape(&self) -> Result<(AffinePoint, AffinePoint)> {
        if self.format != FORMAT {
            return Err(Error::Format);
        }
        if self.chunk_size != CHUNK_SIZE as u64 {
            return Err(Error::Malformed("unsupported chunk size"));
        }
        Ok((parse_canonical(&self.campaign_key)?, parse_canonical(&self.sealed_key)?))
    }
}

fn chunk_count(plaintext_len: u64) -> u64 {
    plaintext_len.div_ceil(CHUNK_SIZE as u64).max(1)
}

/// Size of the encrypted chunks for a given plaintext size (None on overflow).
pub fn body_len_for(plaintext_len: u64) -> Option<u64> {
    plaintext_len.checked_add(TAG_LEN.checked_mul(chunk_count(plaintext_len))?)
}

/// The metadata of either kind of sealed file, read from its footer.
#[derive(Debug, Clone)]
pub enum SealedMeta {
    Stream(Metadata),
    Proven(zk::ZkMetadata),
}

impl SealedMeta {
    pub fn file_name(&self) -> &str {
        match self {
            SealedMeta::Stream(m) => &m.file_name,
            SealedMeta::Proven(m) => &m.file_name,
        }
    }
}

/// Reads a sealed file's metadata without checking anything else, to decide
/// how to handle it.
pub fn read_metadata<R: Read + Seek>(file: &mut R) -> Result<SealedMeta> {
    let f = container::read_footer(file)?;
    Ok(if &f.magic == zk::FILE_MAGIC {
        SealedMeta::Proven(zk::ZkMetadata::from_json(&f.json)?)
    } else {
        SealedMeta::Stream(Metadata::from_json(&f.json)?)
    })
}

/// An ordinary sealed file's footer, checked for shape and size.
fn read_stream_footer<R: Read + Seek>(file: &mut R) -> Result<(Metadata, Vec<u8>, u64, AffinePoint, AffinePoint)> {
    let f = container::read_footer(file)?;
    if &f.magic != FILE_MAGIC {
        return Err(Error::Format);
    }
    let meta = Metadata::from_json(&f.json)?;
    let (x, r) = meta.check_shape()?;
    if Some(f.body_len) != body_len_for(meta.plaintext_len) {
        return Err(Error::Malformed("sizes are inconsistent"));
    }
    Ok((meta, f.json, f.body_len, x, r))
}

/// K = BLAKE3-derive-key(KEY_CONTEXT, S ‖ R ‖ X ‖ format ‖ name ‖ chunk size),
/// each field length-prefixed. The hasher is wiped once K is out.
fn file_key(shared: &AffinePoint, r_pt: &AffinePoint, x_pt: &AffinePoint, file_name: &str) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(KEY_CONTEXT);
    let s = Zeroizing::new(compressed(shared));
    let chunk = (CHUNK_SIZE as u64).to_be_bytes();
    let (r, x) = (compressed(r_pt), compressed(x_pt));
    for field in [&s[..], &r, &x, FORMAT.as_bytes(), file_name.as_bytes(), &chunk] {
        h.update(&(field.len() as u64).to_be_bytes());
        h.update(field);
    }
    let mut k = Zeroizing::new([0u8; 32]);
    let mut out = h.finalize_xof();
    out.fill(&mut k[..]);
    out.zeroize();
    h.zeroize();
    k
}

// ============================================================ secret hygiene

/// Overwrite `len` bytes at `p` with zeros in a way the compiler may not
/// remove (volatile writes, then a fence).
///
/// # Safety
/// `p` must be valid for writes of `len` bytes. The bytes need not be
/// initialized.
pub unsafe fn wipe_memory(p: *mut u8, len: usize) {
    let head = p.align_offset(8).min(len);
    let mut i = 0;
    while i < head {
        p.add(i).write_volatile(0);
        i += 1;
    }
    while i + 8 <= len {
        p.add(i).cast::<u64>().write_volatile(0);
        i += 8;
    }
    while i < len {
        p.add(i).write_volatile(0);
        i += 1;
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// A global allocator that zeroes every heap block before freeing it, and
/// copies and wipes a growing block rather than letting it move. Key material
/// inside any library (curve arithmetic, the cipher, the hasher, proof
/// witnesses) then never survives in freed memory. The CLI installs it;
/// programs using this library should too:
///
/// ```ignore
/// #[global_allocator]
/// static ALLOCATOR: vault_seal::WipeOnFree<std::alloc::System> = vault_seal::WipeOnFree(std::alloc::System);
/// ```
pub struct WipeOnFree<A>(pub A);

unsafe impl<A: std::alloc::GlobalAlloc> std::alloc::GlobalAlloc for WipeOnFree<A> {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        self.0.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        self.0.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: std::alloc::Layout) {
        wipe_memory(p, layout.size());
        self.0.dealloc(p, layout)
    }

    unsafe fn realloc(&self, p: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        let q = self.0.alloc(std::alloc::Layout::from_size_align_unchecked(new_size, layout.align()));
        if !q.is_null() {
            std::ptr::copy_nonoverlapping(p, q, layout.size().min(new_size));
            self.dealloc(p, layout);
        }
        q
    }
}

// Tests run under the same allocator as the CLI.
#[cfg(test)]
#[global_allocator]
static TEST_ALLOCATOR: WipeOnFree<std::alloc::System> = WipeOnFree(std::alloc::System);

/// Test support: search this process's whole readable memory (every heap
/// region and thread stack) for a secret, held only as `masked` XOR `mask` so
/// the search itself never materialises it.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn memory_contains(masked: &[u8], mask: &[u8]) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let n = masked.len();
    let first = masked[0] ^ mask[0];
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut mem = std::fs::File::open("/proc/self/mem").unwrap();
    let mut buf = vec![0u8; 1 << 20];
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let (range, perms) = (parts.next().unwrap(), parts.next().unwrap());
        if !perms.starts_with('r') || line.contains("[vvar]") || line.contains("[vsyscall]") {
            continue;
        }
        let (a, b) = range.split_once('-').unwrap();
        let (mut pos, end) = (u64::from_str_radix(a, 16).unwrap(), u64::from_str_radix(b, 16).unwrap());
        while pos < end {
            let want = ((end - pos) as usize).min(buf.len());
            if mem.seek(SeekFrom::Start(pos)).is_err() {
                break;
            }
            let got = match mem.read(&mut buf[..want]) {
                Ok(g) if g >= n => g,
                _ => break,
            };
            let hay = &buf[..got];
            for i in 0..=got - n {
                if hay[i] == first && (1..n).all(|j| hay[i + j] == masked[j] ^ mask[j]) {
                    return true;
                }
            }
            pos += (got - (n - 1)) as u64;
        }
    }
    false
}

/// Test support: mask a secret with fresh randomness and wipe the original.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn mask_secret(secret: &mut [u8]) -> (Vec<u8>, Vec<u8>) {
    let mut mask = vec![0u8; secret.len()];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut mask);
    let masked = secret.iter().zip(&mask).map(|(s, m)| s ^ m).collect();
    secret.zeroize();
    (masked, mask)
}

/// How much stack [`burn_stack`] overwrites: far more than sealing uses.
const STACK_BURN: usize = 256 * 1024;

/// Overwrite this thread's stack below the caller. Moving a value, and the
/// internals of the curve and cipher libraries, leave copies of secrets in
/// frames that are no longer live; this clears them.
#[inline(never)]
pub fn burn_stack() {
    let mut scratch = [0u8; STACK_BURN];
    unsafe { wipe_memory(scratch.as_mut_ptr(), STACK_BURN) };
    std::hint::black_box(&scratch);
}

/// [`burn_stack`] on this thread and on every worker thread.
pub fn burn_stacks() {
    burn_stack();
    rayon::broadcast(|_| burn_stack());
}

#[cfg(unix)]
fn lock_memory(p: *const u8, len: usize) {
    // Best effort: if resource limits refuse the lock, wiping still applies.
    unsafe { libc::mlock(p.cast(), len) };
}

#[cfg(unix)]
fn unlock_memory(p: *const u8, len: usize) {
    unsafe { libc::munlock(p.cast(), len) };
}

#[cfg(windows)]
fn lock_memory(p: *const u8, len: usize) {
    // Best effort, as on Unix: if the working-set quota refuses, wiping still applies.
    unsafe { windows_sys::Win32::System::Memory::VirtualLock(p.cast(), len) };
}

#[cfg(windows)]
fn unlock_memory(p: *const u8, len: usize) {
    unsafe { windows_sys::Win32::System::Memory::VirtualUnlock(p.cast(), len) };
}

#[cfg(not(any(unix, windows)))]
fn lock_memory(_: *const u8, _: usize) {}

#[cfg(not(any(unix, windows)))]
fn unlock_memory(_: *const u8, _: usize) {}

// ============================================================ chunk cipher

/// The STREAM (BE32) nonce for a chunk: a zero 7-byte prefix, the chunk
/// position as a big-endian u32, and a last-chunk flag. Computing it directly
/// lets chunks be encrypted and decrypted in parallel, byte-for-byte as the
/// sequential STREAM encryptor would.
fn chunk_nonce(position: u64, last: bool) -> Result<[u8; 12]> {
    let pos = u32::try_from(position).map_err(|_| Error::Malformed("file too large for the chunk counter"))?;
    let mut n = [0u8; 12];
    n[7..11].copy_from_slice(&pos.to_be_bytes());
    n[11] = last as u8;
    Ok(n)
}

/// AES-256-GCM for one file's chunks (ring: 7.6 GB/s on one core here). The
/// expanded key lives in its own heap allocation, which is locked out of swap
/// where the OS allows and overwritten before it is freed. ring keeps the
/// whole key schedule inline in that allocation, with no pointers elsewhere.
struct ChunkCipher {
    key: std::ptr::NonNull<LessSafeKey>,
}

// SAFETY: the allocation is owned exclusively and only lent out as
// &LessSafeKey, which is Send and Sync.
unsafe impl Send for ChunkCipher {}
unsafe impl Sync for ChunkCipher {}

impl ChunkCipher {
    fn new(key: &[u8; 32]) -> Self {
        let unbound = UnboundKey::new(&AES_256_GCM, key).expect("a 32-byte key");
        let key = std::ptr::NonNull::from(Box::leak(Box::new(LessSafeKey::new(unbound))));
        lock_memory(key.as_ptr().cast(), std::mem::size_of::<LessSafeKey>());
        Self { key }
    }

    fn key(&self) -> &LessSafeKey {
        // SAFETY: allocated in `new`, freed only in `drop`.
        unsafe { self.key.as_ref() }
    }

    /// Encrypt `buf` in place and return the tag.
    fn seal(&self, position: u64, last: bool, aad: &[u8], buf: &mut [u8]) -> Result<[u8; 16]> {
        let nonce = Nonce::assume_unique_for_key(chunk_nonce(position, last)?);
        let tag = self.key().seal_in_place_separate_tag(nonce, Aad::from(aad), buf).map_err(|_| Error::Decrypt)?;
        let mut t = [0u8; 16];
        t.copy_from_slice(tag.as_ref());
        Ok(t)
    }

    /// Decrypt `buf` (ciphertext then tag) in place; returns the plaintext length.
    fn open(&self, position: u64, last: bool, aad: &[u8], buf: &mut [u8]) -> Result<usize> {
        let nonce = Nonce::assume_unique_for_key(chunk_nonce(position, last)?);
        Ok(self.key().open_in_place(nonce, Aad::from(aad), buf).map_err(|_| Error::Decrypt)?.len())
    }
}

/// Drop the key in place and zero its bytes, leaving the memory to be freed.
///
/// # Safety
/// `p` must point to a live, owned `LessSafeKey` that is never used again.
unsafe fn destroy_key(p: *mut LessSafeKey) {
    std::ptr::drop_in_place(p);
    wipe_memory(p.cast(), std::mem::size_of::<LessSafeKey>());
}

impl Drop for ChunkCipher {
    fn drop(&mut self) {
        let p = self.key.as_ptr();
        unsafe {
            destroy_key(p);
            unlock_memory(p.cast(), std::mem::size_of::<LessSafeKey>());
            drop(Box::from_raw(p.cast::<std::mem::MaybeUninit<LessSafeKey>>()));
        }
    }
}

// ============================================================ streaming

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Read up to `max` bytes into `buf`, reusing its allocation.
fn fill<R: Read>(input: &mut R, buf: &mut Vec<u8>, max: usize) -> io::Result<usize> {
    buf.clear();
    buf.resize(max, 0);
    let n = read_full(input, buf)?;
    buf.truncate(n);
    Ok(n)
}

fn parallel() -> bool {
    rayon::current_num_threads() > 1
}

/// Hash into `h`, across cores when there are spare ones and enough data.
fn hash_into(h: &mut blake3::Hasher, data: &[u8]) {
    if parallel() && data.len() >= 1 << 17 {
        h.update_rayon(data);
    } else {
        h.update(data);
    }
}

/// Calls `f` on successive pieces of `input` of `size` bytes (the final one
/// may be shorter, or empty), saying whether each piece is the last. With
/// spare cores the next piece is read on another thread in the meantime.
fn for_each_piece<R: Read + Send>(
    input: &mut R,
    size: usize,
    mut f: impl FnMut(&mut Vec<u8>, bool) -> Result<()>,
) -> Result<()> {
    if !parallel() {
        let (mut cur, mut next) = (Vec::new(), Vec::new());
        fill(input, &mut cur, size)?;
        loop {
            let last = cur.len() < size || fill(input, &mut next, size)? == 0;
            f(&mut cur, last)?;
            if last {
                return Ok(());
            }
            std::mem::swap(&mut cur, &mut next);
        }
    }
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<io::Result<Vec<u8>>>(2);
        let (spare_tx, spare_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        scope.spawn(move || loop {
            let mut buf = spare_rx.try_recv().unwrap_or_default();
            let res = fill(input, &mut buf, size);
            let more = matches!(res, Ok(n) if n == size);
            if tx.send(res.map(|_| buf)).is_err() || !more {
                break;
            }
        });
        let next = || -> Result<Vec<u8>> {
            match rx.recv() {
                Ok(piece) => Ok(piece?),
                Err(_) => Err(Error::Io(io::Error::other("reader thread stopped"))),
            }
        };
        let mut cur = next()?;
        loop {
            let ahead = if cur.len() < size { None } else { Some(next()?) };
            let last = ahead.as_ref().map_or(true, |a| a.is_empty());
            f(&mut cur, last)?;
            if last {
                return Ok(());
            }
            let _ = spare_tx.send(std::mem::replace(&mut cur, ahead.expect("checked above")));
        }
    })
}

/// Runs `body` with a function that writes a buffer to `out` and hands back
/// an empty one for reuse. With spare cores the writing happens on another
/// thread, overlapping the next batch's work.
fn with_writer<W: Write + Send, T>(
    out: &mut W,
    body: impl FnOnce(&mut dyn FnMut(Vec<u8>) -> Result<Vec<u8>>) -> Result<T>,
) -> Result<T> {
    if !parallel() {
        let mut put = |mut b: Vec<u8>| -> Result<Vec<u8>> {
            out.write_all(&b)?;
            b.clear();
            Ok(b)
        };
        let r = body(&mut put)?;
        out.flush()?;
        return Ok(r);
    }
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(2);
        let (back_tx, back_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let writer = scope.spawn(move || -> io::Result<()> {
            for mut b in rx {
                out.write_all(&b)?;
                b.clear();
                let _ = back_tx.send(b);
            }
            out.flush()
        });
        let result = {
            let mut put = move |b: Vec<u8>| -> Result<Vec<u8>> {
                tx.send(b).map_err(|_| Error::Io(io::Error::other("writer thread stopped")))?;
                Ok(back_rx.try_recv().unwrap_or_default())
            };
            body(&mut put)
        };
        // `put` and its sender are gone, so the writer finishes.
        match (result, writer.join().expect("writer thread")) {
            (_, Err(e)) => Err(e.into()),
            (r, Ok(())) => r,
        }
    })
}

/// Encrypt whole chunks of `pt` into consecutive `CT_CHUNK` slots of `ct`.
fn encrypt_chunks(cipher: &ChunkCipher, first: u64, pt: &[u8], ct: &mut [u8]) -> Result<()> {
    let one = |i: usize, slot: &mut [u8], p: &[u8]| -> Result<()> {
        let (body, tag) = slot.split_at_mut(p.len());
        body.copy_from_slice(p);
        tag.copy_from_slice(&cipher.seal(first + i as u64, false, CHUNK_AAD, body)?);
        Ok(())
    };
    if parallel() {
        ct.par_chunks_mut(CT_CHUNK).zip(pt.par_chunks(CHUNK_SIZE)).enumerate().try_for_each(|(i, (s, p))| one(i, s, p))
    } else {
        ct.chunks_mut(CT_CHUNK).zip(pt.chunks(CHUNK_SIZE)).enumerate().try_for_each(|(i, (s, p))| one(i, s, p))
    }
}

/// Decrypt consecutive whole `CT_CHUNK` slots in place.
fn decrypt_chunks(cipher: &ChunkCipher, first: u64, ct: &mut [u8]) -> Result<()> {
    let one = |i: usize, slot: &mut [u8]| cipher.open(first + i as u64, false, CHUNK_AAD, slot).map(|_| ());
    if parallel() {
        ct.par_chunks_mut(CT_CHUNK).enumerate().try_for_each(|(i, s)| one(i, s))
    } else {
        ct.chunks_mut(CT_CHUNK).enumerate().try_for_each(|(i, s)| one(i, s))
    }
}

// ============================================================ seal

/// Seal `input` into `output`, the whole `.sealed` file, under a key sealed to
/// `campaign`, and return the metadata written to its footer. Every ephemeral
/// secret is wiped before this returns.
pub fn seal<R: Read + Send, W: Write + Send>(campaign: &CampaignKey, file_name: &str, input: R, output: W) -> Result<Metadata> {
    let result = seal_inner(campaign, file_name, input, output, None);
    burn_stacks();
    result
}

fn seal_inner<R: Read + Send, W: Write + Send>(
    campaign: &CampaignKey,
    file_name: &str,
    mut input: R,
    mut output: W,
    lying_hash: Option<&str>,
) -> Result<Metadata> {
    let x_pt = campaign.0;
    let (r_pt, cipher) = {
        let r = nonzero_scalar();
        let r_pt = (ProjectivePoint::GENERATOR * *r).to_affine();
        let shared = Zeroizing::new((ProjectivePoint::from(x_pt) * *r).to_affine());
        let key = file_key(&shared, &r_pt, &x_pt, file_name);
        (r_pt, ChunkCipher::new(&key))
    }; // r, r·X and K are wiped here; the cipher holds the only key material.
    let template = Metadata {
        format: FORMAT.to_string(),
        campaign_key: campaign.compressed_hex(),
        sealed_key: hex::encode(compressed(&r_pt)),
        file_name: file_name.to_string(),
        plaintext_len: 0,
        plaintext_blake3: String::new(),
        chunk_size: CHUNK_SIZE as u64,
    };
    let meta = seal_stream(&cipher, &mut input, &mut output, template, lying_hash)?;
    drop(cipher);
    Ok(meta)
}

/// Batches of 64 chunks: hash the plaintext, encrypt the chunks (across cores
/// when there are several), write. Reading and writing overlap the work when
/// there are spare cores. Only a full chunk can be followed by more data; the
/// chunk with nothing after it is sealed as the last one, and by then the
/// length and hash are known, so it authenticates the finished footer, which
/// follows it. Truncation and edits are detectable.
fn seal_stream<R: Read + Send, W: Write + Send>(
    cipher: &ChunkCipher,
    input: &mut R,
    out: &mut W,
    mut meta: Metadata,
    lying_hash: Option<&str>,
) -> Result<Metadata> {
    let mut pt_hash = blake3::Hasher::new();
    let (mut pt_len, mut position) = (0u64, 0u64);
    with_writer(out, |put| {
        let mut ct = FILE_MAGIC.to_vec();
        for_each_piece(input, BATCH * CHUNK_SIZE, |pt, last| {
            hash_into(&mut pt_hash, pt);
            pt_len += pt.len() as u64;
            // The last piece ends with the file's final chunk (possibly empty).
            let regular = if last { pt.len().saturating_sub(1) / CHUNK_SIZE } else { pt.len() / CHUNK_SIZE };
            let body = regular * CHUNK_SIZE;
            let start = ct.len();
            let tail = if last { pt.len() - body + TAG_LEN as usize } else { 0 };
            ct.resize(start + regular * CT_CHUNK + tail, 0);
            encrypt_chunks(cipher, position, &pt[..body], &mut ct[start..start + regular * CT_CHUNK])?;
            position += regular as u64;
            if last {
                meta.plaintext_len = pt_len;
                meta.plaintext_blake3 = match lying_hash {
                    Some(h) => h.to_string(),
                    None => pt_hash.finalize().to_hex().to_string(),
                };
                let footer = meta.to_json()?;
                let trailer = container::trailer(footer.as_bytes())?;
                let aad = last_chunk_aad(footer.as_bytes());
                let slot = &mut ct[start + regular * CT_CHUNK..];
                let n = pt.len() - body;
                slot[..n].copy_from_slice(&pt[body..]);
                let tag = cipher.seal(position, true, &aad, &mut slot[..n])?;
                slot[n..].copy_from_slice(&tag);
                ct.extend_from_slice(&trailer);
            }
            ct = put(std::mem::take(&mut ct))?;
            Ok(())
        })
    })?;
    Ok(meta)
}

// ============================================================ verify

/// Pre-reveal check, needing no secret, and reading only the footer.
///
/// Certain, no trust: the metadata names `campaign` (take it from the vault's
/// `keyX()`/`keyY()`), the sealed key is a valid curve point, so the key the
/// vault reveals will produce exactly this file's key, and the file is the
/// size its metadata says.
///
/// Not checkable: whether the creator encrypted the promised content, or that
/// the chunks are intact (only the key can tell; opening checks every byte).
pub fn verify<R: Read + Seek>(file: &mut R, campaign: &CampaignKey) -> Result<Metadata> {
    let (meta, _, _, x, _) = read_stream_footer(file)?;
    if x != campaign.0 {
        return Err(Error::WrongCampaign);
    }
    Ok(meta)
}

// ============================================================ open

/// Decrypt a `.sealed` file into `output` and check the creator's hash.
///
/// Output is written as it is authenticated, batch by batch; on any error the
/// caller must discard what was written (the CLI writes to a temporary file).
/// The derived key is wiped before this returns.
pub fn open<R: Read + Seek + Send, W: Write + Send>(file: R, secret: &CampaignSecret, output: W) -> Result<Metadata> {
    let result = open_inner(file, secret, output);
    burn_stacks();
    result
}

fn open_inner<R: Read + Seek + Send, W: Write + Send>(mut file: R, secret: &CampaignSecret, mut output: W) -> Result<Metadata> {
    let (meta, footer, body_len, x_pt, r_pt) = read_stream_footer(&mut file)?;
    if secret.public().0 != x_pt {
        return Err(Error::WrongSecret);
    }
    let cipher = {
        let shared = Zeroizing::new((ProjectivePoint::from(r_pt) * *secret.scalar()).to_affine());
        let key = file_key(&shared, &r_pt, &x_pt, &meta.file_name);
        ChunkCipher::new(&key)
    };
    container::seek_body(&mut file)?;
    let mut body = file.take(body_len);
    let digest = open_stream(&cipher, &mut body, &mut output, &meta, &footer, body_len)?;
    drop(cipher);
    // The last chunk authenticated this hash as the creator's own claim, so a
    // mismatch here is the creator's fault, not tampering in transit.
    if digest.to_hex().as_str() != meta.plaintext_blake3 {
        return Err(Error::PlaintextHash);
    }
    Ok(meta)
}

/// Batches of 64 chunks: decrypt across cores when there are several, hash
/// the plaintext, write. The metadata fixes where every chunk ends, so a
/// short stream is truncation and anything past the end is trailing data.
fn open_stream<R: Read + Send, W: Write + Send>(
    cipher: &ChunkCipher,
    input: &mut R,
    out: &mut W,
    meta: &Metadata,
    footer: &[u8],
    expected: u64,
) -> Result<blake3::Hash> {
    let chunks = chunk_count(meta.plaintext_len);
    let last_len = (meta.plaintext_len - (chunks - 1) * CHUNK_SIZE as u64) as usize + TAG_LEN as usize;
    let mut h = blake3::Hasher::new();
    let (mut seen, mut position) = (0u64, 0u64);
    with_writer(out, |put| {
        let mut plain = Vec::new();
        for_each_piece(input, BATCH * CT_CHUNK, |ct, last_piece| {
            seen += ct.len() as u64;
            if seen > expected {
                return Err(Error::TrailingData);
            }
            let final_piece = seen == expected;
            if !final_piece && last_piece {
                return Err(Error::Truncated);
            }
            if final_piece && !last_piece {
                return Err(Error::TrailingData);
            }
            let regular = if final_piece { (chunks - 1 - position) as usize } else { BATCH };
            let body = regular * CT_CHUNK;
            if ct.len() != body + if final_piece { last_len } else { 0 } {
                return Err(Error::Truncated);
            }
            decrypt_chunks(cipher, position, &mut ct[..body])?;
            plain.clear();
            for c in ct[..body].chunks(CT_CHUNK) {
                plain.extend_from_slice(&c[..CHUNK_SIZE]);
            }
            if final_piece {
                let aad = last_chunk_aad(footer);
                let n = cipher.open(chunks - 1, true, &aad, &mut ct[body..])?;
                plain.extend_from_slice(&ct[body..body + n]);
            }
            hash_into(&mut h, &plain);
            plain = put(std::mem::take(&mut plain))?;
            position += regular as u64 + final_piece as u64;
            Ok(())
        })
    })?;
    if seen != expected {
        return Err(Error::Truncated);
    }
    Ok(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    fn seal_bytes(pk: &CampaignKey, data: &[u8]) -> (Metadata, Vec<u8>) {
        let mut file = Vec::new();
        let meta = seal(pk, "goods.bin", data, &mut file).unwrap();
        (meta, file)
    }

    fn open_bytes(sk: &CampaignSecret, file: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        open(Cursor::new(file), sk, &mut out)?;
        Ok(out)
    }

    fn verify_bytes(pk: &CampaignKey, file: &[u8]) -> Result<Metadata> {
        verify(&mut Cursor::new(file), pk)
    }

    /// The same file with its footer replaced by `json`.
    fn with_footer(file: &[u8], json: &str) -> Vec<u8> {
        let f = container::read_footer(&mut Cursor::new(file)).unwrap();
        let mut out = file[..8 + f.body_len as usize].to_vec();
        out.extend(container::trailer(json.as_bytes()).unwrap());
        out
    }

    fn footer_json(file: &[u8]) -> String {
        String::from_utf8(container::read_footer(&mut Cursor::new(file)).unwrap().json).unwrap()
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn roundtrip_across_chunk_boundaries() {
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        for len in [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 5] {
            let d = data(len);
            let (meta, file) = seal_bytes(&pk, &d);
            assert_eq!(verify_bytes(&pk, &file).unwrap(), meta, "len {len}");
            assert_eq!(open_bytes(&sk, &file).unwrap(), d, "len {len}");
        }
    }

    #[test]
    fn chunks_match_the_reference_stream_encryptor() {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::aead::stream::EncryptorBE32;
        use aes_gcm::aead::{KeyInit, Payload};
        use aes_gcm::Aes256Gcm;
        let key = [9u8; 32];
        let chunks = [data(CHUNK_SIZE), data(CHUNK_SIZE), data(77)];
        let fresh = || EncryptorBE32::from_aead(Aes256Gcm::new(GenericArray::from_slice(&key)), &GenericArray::from([0u8; 7]));
        let mut reference = fresh();
        let cipher = ChunkCipher::new(&key);
        for (i, c) in chunks.iter().enumerate() {
            let last = i == chunks.len() - 1;
            let p = Payload { msg: c.as_slice(), aad: b"aad" };
            let want = if last {
                std::mem::replace(&mut reference, fresh()).encrypt_last(p).unwrap()
            } else {
                reference.encrypt_next(p).unwrap()
            };
            let mut got = c.clone();
            let tag = cipher.seal(i as u64, last, b"aad", &mut got).unwrap();
            got.extend_from_slice(&tag);
            assert_eq!(got, want, "chunk {i}");
            let n = cipher.open(i as u64, last, b"aad", &mut got).unwrap();
            assert_eq!(&got[..n], &c[..], "chunk {i} round trip");
        }
    }

    #[test]
    fn cipher_key_memory_is_wiped() {
        let p = Box::into_raw(Box::new(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0x5a; 32]).unwrap())));
        unsafe {
            destroy_key(p);
            let bytes = std::slice::from_raw_parts(p.cast::<u8>(), std::mem::size_of::<LessSafeKey>());
            assert!(bytes.iter().all(|b| *b == 0), "key schedule left in memory");
            drop(Box::from_raw(p.cast::<std::mem::MaybeUninit<LessSafeKey>>()));
        }
    }

    #[test]
    fn wipe_memory_handles_any_alignment_and_length() {
        for start in 0..9 {
            for len in [0, 1, 7, 8, 9, 63, 64, 100] {
                let mut buf = vec![0xa5u8; 128];
                unsafe { wipe_memory(buf.as_mut_ptr().add(start), len) };
                for (i, b) in buf.iter().enumerate() {
                    let inside = i >= start && i < start + len;
                    assert_eq!(*b, if inside { 0 } else { 0xa5 }, "start {start} len {len} byte {i}");
                }
            }
        }
    }

    #[test]
    fn file_key_binds_every_field() {
        let pts: Vec<AffinePoint> = (1..=4u64).map(|i| (ProjectivePoint::GENERATOR * Scalar::from(i)).to_affine()).collect();
        let base = file_key(&pts[0], &pts[1], &pts[2], "a.txt");
        assert_eq!(*base, *file_key(&pts[0], &pts[1], &pts[2], "a.txt"));
        for other in [
            file_key(&pts[3], &pts[1], &pts[2], "a.txt"),
            file_key(&pts[0], &pts[3], &pts[2], "a.txt"),
            file_key(&pts[0], &pts[1], &pts[3], "a.txt"),
            file_key(&pts[0], &pts[1], &pts[2], "b.txt"),
        ] {
            assert_ne!(*base, *other);
        }
    }

    #[test]
    fn freed_and_moved_blocks_are_wiped() {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::sync::atomic::{AtomicBool, Ordering};
        static FREED_ZEROED: AtomicBool = AtomicBool::new(false);
        /// Records whether a block was all zeros at the moment it was freed.
        struct Inspect;
        unsafe impl GlobalAlloc for Inspect {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                System.alloc(layout)
            }
            unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
                FREED_ZEROED.store((0..layout.size()).all(|i| p.add(i).read() == 0), Ordering::SeqCst);
                System.dealloc(p, layout)
            }
        }
        let a = WipeOnFree(Inspect);
        unsafe {
            let layout = Layout::from_size_align(1000, 8).unwrap();
            let p = a.alloc(layout);
            std::ptr::write_bytes(p, 0xab, 1000);
            a.dealloc(p, layout);
            assert!(FREED_ZEROED.load(Ordering::SeqCst), "freed block kept its contents");
            let p = a.alloc(layout);
            std::ptr::write_bytes(p, 0xcd, 1000);
            FREED_ZEROED.store(false, Ordering::SeqCst);
            let q = a.realloc(p, layout, 5000);
            assert!(FREED_ZEROED.load(Ordering::SeqCst), "old block kept its contents when moved");
            assert!((0..1000).all(|i| q.add(i).read() == 0xcd), "contents not carried over");
            a.dealloc(q, Layout::from_size_align(5000, 8).unwrap());
        }
    }

    /// The file key and shared secret for `meta`, masked. Derived in a frame of
    /// its own, so nothing of them outlives the call on this stack.
    #[cfg(target_os = "linux")]
    #[inline(never)]
    fn masked_secrets(meta: &Metadata, sk: &CampaignSecret) -> ((Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>)) {
        let (x_pt, r_pt) = meta.check_shape().unwrap();
        let shared = Zeroizing::new((ProjectivePoint::from(r_pt) * *sk.scalar()).to_affine());
        let mut k = file_key(&shared, &r_pt, &x_pt, &meta.file_name);
        let mut s = Zeroizing::new(compressed(&shared));
        (mask_secret(&mut k[..]), mask_secret(&mut s[..]))
    }

    /// The no-leak tests only mean something if the scan can see this
    /// process's memory. If it could not (a restricted /proc, say), they would
    /// pass without checking anything; this fails instead.
    #[cfg(target_os = "linux")]
    #[test]
    fn memory_scan_finds_a_planted_secret() {
        let mut secret = vec![0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut secret);
        let planted = secret.clone();
        let (masked, mask) = mask_secret(&mut secret);
        assert!(memory_contains(&masked, &mask), "the memory scan cannot see this process's memory");
        std::hint::black_box(&planted);
    }

    /// End to end: after sealing and after opening, neither the file key nor
    /// the shared secret r·X = x·R is anywhere in this process's memory, on
    /// one thread or several.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_key_material_survives_sealing_or_opening() {
        let sk = CampaignSecret::generate();
        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            let d = data(3 * CHUNK_SIZE + 5);
            let (meta, file) = pool.install(|| seal_bytes(&sk.public(), &d));
            let ((mk, kmask), (ms, smask)) = masked_secrets(&meta, &sk);
            burn_stack(); // this test's own derivation
            assert!(!memory_contains(&mk, &kmask), "file key survived sealing ({threads} threads)");
            assert!(!memory_contains(&ms, &smask), "shared secret survived sealing ({threads} threads)");
            assert_eq!(pool.install(|| open_bytes(&sk, &file)).unwrap(), d);
            assert!(!memory_contains(&mk, &kmask), "file key survived opening ({threads} threads)");
            assert!(!memory_contains(&ms, &smask), "shared secret survived opening ({threads} threads)");
        }
    }

    #[test]
    fn stacks_are_burned_on_every_thread() {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build().unwrap();
        pool.install(burn_stacks);
        burn_stacks();
    }

    #[test]
    fn earlier_formats_are_refused() {
        let sk = CampaignSecret::generate();
        let (meta, file) = seal_bytes(&sk.public(), b"hello");
        let json = meta.to_json().unwrap().replace("crowdvault-seal/3", "crowdvault-seal/2");
        assert!(matches!(Metadata::from_json(json.as_bytes()), Err(Error::Format)));
        assert!(matches!(open_bytes(&sk, &with_footer(&file, &json)), Err(Error::Format)));
        // The two-file format: an .enc file, or its .meta.json passed by mistake.
        let mut old = file.clone();
        old[..8].copy_from_slice(b"CVENC2\0\0");
        assert!(matches!(open_bytes(&sk, &old), Err(Error::OldFormat)));
        assert!(matches!(open_bytes(&sk, meta.to_json().unwrap().as_bytes()), Err(Error::OldFormat)));
    }

    #[test]
    fn sequential_and_pipelined_seals_both_open() {
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            for len in [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, BATCH * CHUNK_SIZE + 5, 3 * BATCH * CHUNK_SIZE] {
                let d = data(len);
                let (meta, file) = pool.install(|| seal_bytes(&pk, &d));
                assert_eq!(meta.plaintext_len, len as u64, "{threads} threads, {len} bytes");
                assert_eq!(pool.install(|| open_bytes(&sk, &file)).unwrap(), d, "{threads} threads, {len} bytes");
                let mut longer = file.clone();
                longer.push(0);
                assert!(matches!(pool.install(|| open_bytes(&sk, &longer)), Err(Error::NoFooter)));
                assert!(matches!(pool.install(|| open_bytes(&sk, &file[..file.len() - 1])), Err(Error::NoFooter)));
                let mut flipped = file.clone();
                flipped[FILE_MAGIC.len()] ^= 1;
                assert!(matches!(pool.install(|| open_bytes(&sk, &flipped)), Err(Error::Decrypt)));
            }
        }
    }

    #[test]
    fn verify_reads_only_the_footer() {
        let pk = CampaignSecret::generate().public();
        let (meta, file) = seal_bytes(&pk, &data(3 * CHUNK_SIZE + 7));
        // Damaged chunks can't be seen without the key; opening catches them.
        let mut damaged = file.clone();
        damaged[100] ^= 1;
        assert_eq!(verify_bytes(&pk, &damaged).unwrap(), meta);
        // A file of the wrong size for its metadata is refused.
        let mut cut = file[..8 + CT_CHUNK].to_vec();
        cut.extend(container::trailer(footer_json(&file).as_bytes()).unwrap());
        assert!(matches!(verify_bytes(&pk, &cut), Err(Error::Malformed("sizes are inconsistent"))));
        assert!(matches!(verify_bytes(&pk, &file[..file.len() - 3]), Err(Error::NoFooter)));
        assert!(matches!(verify_bytes(&pk, b"CVSEAL3\0"), Err(Error::NoFooter)));
        assert!(matches!(verify_bytes(&pk, b"plain text, not sealed"), Err(Error::NotEncrypted)));
    }

    #[test]
    fn footer_rejects_absurd_lengths() {
        let pk = CampaignSecret::generate().public();
        let (_, file) = seal_bytes(&pk, b"x");
        let mut huge = file.clone();
        let at = huge.len() - 12;
        huge[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(verify_bytes(&pk, &huge), Err(Error::Malformed("footer length"))));
        assert!(container::trailer(&vec![b' '; container::MAX_FOOTER + 1]).is_err());
    }

    #[test]
    fn metadata_survives_json() {
        let sk = CampaignSecret::generate();
        let (meta, file) = seal_bytes(&sk.public(), b"hello");
        let back = Metadata::from_json(meta.to_json().unwrap().as_bytes()).unwrap();
        assert_eq!(back, meta);
        assert_eq!(footer_json(&file), meta.to_json().unwrap());
        assert_eq!(open_bytes(&sk, &file).unwrap(), b"hello");
        assert!(matches!(read_metadata(&mut Cursor::new(&file)).unwrap(), SealedMeta::Stream(m) if m == meta));
    }

    #[test]
    fn wrong_secret_rejected() {
        let (_, file) = seal_bytes(&CampaignSecret::generate().public(), b"x");
        assert!(matches!(open_bytes(&CampaignSecret::generate(), &file), Err(Error::WrongSecret)));
    }

    #[test]
    fn verify_rejects_other_campaign() {
        let pk = CampaignSecret::generate().public();
        let (_, file) = seal_bytes(&pk, b"one");
        let other = CampaignSecret::generate().public();
        assert!(matches!(verify_bytes(&other, &file), Err(Error::WrongCampaign)));
        verify_bytes(&pk, &file).unwrap();
    }

    #[test]
    fn edited_metadata_will_not_open() {
        let sk = CampaignSecret::generate();
        let (meta, file) = seal_bytes(&sk.public(), b"the goods");
        let edit = |f: &dyn Fn(&mut Metadata)| {
            let mut m = meta.clone();
            f(&mut m);
            with_footer(&file, &m.to_json().unwrap())
        };
        let renamed = edit(&|m| m.file_name = "something-else.png".into());
        assert!(matches!(open_bytes(&sk, &renamed), Err(Error::Decrypt)));
        let rehashed = edit(&|m| m.plaintext_blake3 = blake3::hash(b"promised").to_hex().to_string());
        assert!(matches!(open_bytes(&sk, &rehashed), Err(Error::Decrypt)));
        let other_key = seal_bytes(&sk.public(), b"other").0.sealed_key;
        let rekeyed = edit(&|m| m.sealed_key = other_key.clone());
        assert!(matches!(open_bytes(&sk, &rekeyed), Err(Error::Decrypt)));
        let resized = edit(&|m| m.plaintext_len += 1);
        assert!(matches!(open_bytes(&sk, &resized), Err(Error::Malformed("sizes are inconsistent"))));
        // Even a change that means the same thing: the footer is authenticated byte for byte.
        let compact = serde_json::to_string(&meta).unwrap();
        assert!(matches!(open_bytes(&sk, &with_footer(&file, &compact)), Err(Error::Decrypt)));
        let extra = footer_json(&file).replacen('{', "{\"note\": \"hi\",", 1);
        assert!(matches!(open_bytes(&sk, &with_footer(&file, &extra)), Err(Error::Json(_))));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let sk = CampaignSecret::generate();
        let (_, mut file) = seal_bytes(&sk.public(), &data(2 * CHUNK_SIZE + 10));
        file[100] ^= 1;
        assert!(matches!(open_bytes(&sk, &file), Err(Error::Decrypt)));
    }

    #[test]
    fn missing_chunks_rejected() {
        let sk = CampaignSecret::generate();
        let (_, file) = seal_bytes(&sk.public(), &data(3 * CHUNK_SIZE));
        // Drop the last chunk but keep the footer: the sizes no longer agree.
        let mut cut = file[..8 + 2 * CT_CHUNK].to_vec();
        cut.extend(container::trailer(footer_json(&file).as_bytes()).unwrap());
        assert!(matches!(open_bytes(&sk, &cut), Err(Error::Malformed("sizes are inconsistent"))));
    }

    #[test]
    fn swapped_chunks_rejected() {
        let sk = CampaignSecret::generate();
        let (_, mut file) = seal_bytes(&sk.public(), &data(3 * CHUNK_SIZE));
        let c = CHUNK_SIZE + 16;
        let (a, b) = file[8..8 + 2 * c].split_at_mut(c);
        a.swap_with_slice(b);
        assert!(matches!(open_bytes(&sk, &file), Err(Error::Decrypt)));
    }

    #[test]
    fn not_an_encrypted_file() {
        let sk = CampaignSecret::generate();
        assert!(matches!(open_bytes(&sk, b"plain text"), Err(Error::NotEncrypted)));
        assert!(matches!(open_bytes(&sk, b""), Err(Error::NotEncrypted)));
    }

    #[test]
    fn same_file_sealed_twice_differs() {
        let pk = CampaignSecret::generate().public();
        let (m1, e1) = seal_bytes(&pk, b"same");
        let (m2, e2) = seal_bytes(&pk, b"same");
        assert_ne!(e1, e2);
        assert_ne!(m1.sealed_key, m2.sealed_key);
        assert_eq!(m1.plaintext_blake3, m2.plaintext_blake3);
    }

    #[test]
    fn verify_rejects_invalid_sealed_key() {
        let pk = CampaignSecret::generate().public();
        let (meta, file) = seal_bytes(&pk, b"x");
        let with_key = |k: String| {
            let mut m = meta.clone();
            m.sealed_key = k;
            with_footer(&file, &m.to_json().unwrap())
        };
        // The 0x05 "compact" form is valid SEC1 but not canonical here.
        assert!(matches!(verify_bytes(&pk, &with_key(format!("05{}", &meta.sealed_key[2..]))), Err(Error::BadPoint)));
        assert!(matches!(verify_bytes(&pk, &with_key("00".into())), Err(Error::BadPoint)));
        // Uncompressed form of a valid point is refused too.
        let (x, y) = pk.xy_hex();
        assert!(matches!(verify_bytes(&pk, &with_key(format!("04{}{}", &x[2..], &y[2..]))), Err(Error::BadPoint)));
    }

    #[test]
    fn any_valid_sealed_key_opens_with_the_revealed_secret() {
        // The property backers rely on: once verify passes, the file key is fixed
        // by x and public data. Check it over many independent seals.
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        for i in 0..20u8 {
            let d = vec![i; 1000 + i as usize];
            let (_, file) = seal_bytes(&pk, &d);
            verify_bytes(&pk, &file).unwrap();
            assert_eq!(open_bytes(&sk, &file).unwrap(), d);
        }
    }

    #[test]
    fn lying_creator_is_caught_on_open_as_creator_fault() {
        let sk = CampaignSecret::generate();
        let pk = sk.public();
        let promised = blake3::hash(b"what was promised").to_hex().to_string();
        let mut file = Vec::new();
        seal_inner(&pk, "promise.mp4", &b"junk"[..], &mut file, Some(&promised)).unwrap();
        verify_bytes(&pk, &file).unwrap();
        assert!(matches!(open_bytes(&sk, &file), Err(Error::PlaintextHash)));
    }

    #[test]
    fn secret_hex_parsing() {
        let sk = CampaignSecret::generate();
        assert_eq!(CampaignSecret::from_hex(&sk.to_hex()).unwrap().public(), sk.public());
        assert!(CampaignSecret::from_hex("0x0").is_err());
        assert!(CampaignSecret::from_hex("").is_err());
        assert!(CampaignSecret::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").is_err());
        let small = CampaignSecret::from_hex("0xA11CE5EC2E7").unwrap();
        assert!(small.public().matches(&small));
    }

    #[test]
    fn eth_address_matches_known_vector() {
        let sk = CampaignSecret::from_hex("0x1").unwrap();
        assert_eq!(sk.public().eth_address(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn key_encodings_roundtrip() {
        let pk = CampaignSecret::generate().public();
        assert_eq!(CampaignKey::from_hex(&pk.compressed_hex()).unwrap(), pk);
        let (x, y) = pk.xy_hex();
        let xb: [u8; 32] = hex::decode(&x[2..]).unwrap().try_into().unwrap();
        let yb: [u8; 32] = hex::decode(&y[2..]).unwrap().try_into().unwrap();
        assert_eq!(CampaignKey::from_xy(&xb, &yb).unwrap(), pk);
    }
}
