//! secq256k1: y² = x³ + 7 over secp256k1's scalar field. Its group has prime
//! order p, secp256k1's base-field prime, so commitments over this curve take
//! scalars from the field where secp256k1 arithmetic is native.

use std::sync::OnceLock;

use crypto_bigint::{Encoding, U256};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use super::field::{Fp, Fs};

/// A point in Jacobian coordinates; z = 0 is the identity.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    x: Fs,
    y: Fs,
    z: Fs,
}

fn seven() -> Fs {
    Fs::from_u64(7)
}

impl Point {
    pub const IDENTITY: Point = Point { x: Fs::ONE, y: Fs::ONE, z: Fs::ZERO };

    pub fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    pub fn from_affine(x: Fs, y: Fs) -> Point {
        Point { x, y, z: Fs::ONE }
    }

    pub fn double(&self) -> Point {
        if self.is_identity() || self.y.is_zero() {
            return Self::IDENTITY;
        }
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let t = (self.x + b).square() - a - c;
        let d = t + t;
        let e = a + a + a;
        let f = e.square();
        let x3 = f - d - d;
        let c2 = c + c;
        let c4 = c2 + c2;
        let y3 = e * (d - x3) - (c4 + c4);
        let yz = self.y * self.z;
        Point { x: x3, y: y3, z: yz + yz }
    }

    pub fn add(&self, o: &Point) -> Point {
        if self.is_identity() {
            return *o;
        }
        if o.is_identity() {
            return *self;
        }
        let z1z1 = self.z.square();
        let z2z2 = o.z.square();
        let u1 = self.x * z2z2;
        let u2 = o.x * z1z1;
        let s1 = self.y * o.z * z2z2;
        let s2 = o.y * self.z * z1z1;
        if u1 == u2 {
            return if s1 == s2 { self.double() } else { Self::IDENTITY };
        }
        let h = u2 - u1;
        let i = (h + h).square();
        let j = h * i;
        let rr = s2 - s1;
        let r = rr + rr;
        let v = u1 * i;
        let x3 = r.square() - j - v - v;
        let s1j = s1 * j;
        let y3 = r * (v - x3) - s1j - s1j;
        let z3 = ((self.z + o.z).square() - z1z1 - z2z2) * h;
        Point { x: x3, y: y3, z: z3 }
    }

    pub fn neg(&self) -> Point {
        Point { x: self.x, y: -self.y, z: self.z }
    }

    pub fn mul(&self, k: &Fp) -> Point {
        let mut acc = Self::IDENTITY;
        for byte in k.to_bytes() {
            for i in (0..8).rev() {
                acc = acc.double();
                if (byte >> i) & 1 == 1 {
                    acc = acc.add(self);
                }
            }
        }
        acc
    }

    pub fn equals(&self, o: &Point) -> bool {
        match (self.is_identity(), o.is_identity()) {
            (true, true) => true,
            (true, false) | (false, true) => false,
            _ => {
                let z1z1 = self.z.square();
                let z2z2 = o.z.square();
                self.x * z2z2 == o.x * z1z1 && self.y * o.z * z2z2 == o.y * self.z * z1z1
            }
        }
    }

    pub fn affine(&self) -> Option<(Fs, Fs)> {
        if self.is_identity() {
            return None;
        }
        let zi = self.z.inv();
        let zi2 = zi.square();
        Some((self.x * zi2, self.y * zi2 * zi))
    }

    /// 33-byte compressed encoding; the identity is 33 zero bytes.
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        if let Some((x, y)) = self.affine() {
            out[0] = if y.is_odd() { 3 } else { 2 };
            out[1..].copy_from_slice(&x.to_bytes());
        }
        out
    }

    pub fn from_bytes(b: &[u8; 33]) -> Option<Point> {
        if b.iter().all(|v| *v == 0) {
            return Some(Self::IDENTITY);
        }
        let odd = match b[0] {
            2 => false,
            3 => true,
            _ => return None,
        };
        let mut xb = [0u8; 32];
        xb.copy_from_slice(&b[1..]);
        let x = Fs::from_canonical(&xb)?;
        let y = (x.square() * x + seven()).sqrt()?;
        let y = if y.is_odd() == odd { y } else { -y };
        Some(Point::from_affine(x, y))
    }

    /// Jacobian + affine (madd-2007-bl): 7M + 4S instead of 11M + 5S.
    pub fn add_affine(&self, o: &Affine) -> Point {
        if self.is_identity() {
            return Point::from_affine(o.x, o.y);
        }
        let z1z1 = self.z.square();
        let u2 = o.x * z1z1;
        let s2 = o.y * self.z * z1z1;
        if u2 == self.x {
            return if s2 == self.y { self.double() } else { Self::IDENTITY };
        }
        let h = u2 - self.x;
        let hh = h.square();
        let i = hh.double().double();
        let j = h * i;
        let r = (s2 - self.y).double();
        let v = self.x * i;
        let x3 = r.square() - j - v.double();
        let y3 = r * (v - x3) - (self.y * j).double();
        let z3 = (self.z + h).square() - z1z1 - hh;
        Point { x: x3, y: y3, z: z3 }
    }

    pub fn to_affine(&self) -> Option<Affine> {
        self.affine().map(|(x, y)| Affine { x, y })
    }

    /// Nothing-up-my-sleeve generator: try-and-increment on SHA-256 output.
    /// Nobody knows the discrete log of any of these relative to another.
    pub fn hash_to_curve(label: &[u8], index: u64) -> Point {
        let a = Affine::hash_to_curve(label, index);
        Point::from_affine(a.x, a.y)
    }
}

// ============================================================ affine points

/// A non-identity point in affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Affine {
    pub x: Fs,
    pub y: Fs,
}

impl Affine {
    pub fn is_on_curve(&self) -> bool {
        self.y.square() == self.x.square() * self.x + seven()
    }

    pub fn neg(&self) -> Affine {
        Affine { x: self.x, y: -self.y }
    }

    /// The GLV endomorphism φ(x, y) = (βx, y), which equals multiplication by λ.
    pub fn endo(&self) -> Affine {
        Affine { x: glv().beta * self.x, y: self.y }
    }

    pub fn to_point(&self) -> Point {
        Point::from_affine(self.x, self.y)
    }

    pub fn hash_to_curve(label: &[u8], index: u64) -> Affine {
        for ctr in 0u32.. {
            let mut wide = [0u8; 64];
            for half in 0..2u8 {
                let mut h = Sha256::new();
                h.update(b"crowdvault/zk1/hash-to-secq");
                h.update((label.len() as u64).to_be_bytes());
                h.update(label);
                h.update(index.to_be_bytes());
                h.update(ctr.to_be_bytes());
                h.update([half]);
                wide[half as usize * 32..][..32].copy_from_slice(&h.finalize());
            }
            let x = Fs::from_wide(&wide);
            if let Some(y) = (x.square() * x + seven()).sqrt() {
                let y = if y.is_odd() { -y } else { y };
                return Affine { x, y };
            }
        }
        unreachable!()
    }
}

/// Affine forms of many points with one field inversion (identities dropped
/// to None).
pub fn batch_normalize(points: &[Point]) -> Vec<Option<Affine>> {
    let mut zs: Vec<Fs> = points.iter().map(|p| if p.is_identity() { Fs::ONE } else { p.z }).collect();
    batch_invert(&mut zs);
    points
        .iter()
        .zip(zs)
        .map(|(p, zi)| {
            if p.is_identity() {
                None
            } else {
                let zi2 = zi.square();
                Some(Affine { x: p.x * zi2, y: p.y * zi2 * zi })
            }
        })
        .collect()
}

/// Montgomery's trick: invert every element with one inversion and 3
/// multiplications each. Returns false (leaving v unchanged) if any is zero.
pub fn batch_invert(v: &mut [Fs]) -> bool {
    let mut prefix = Vec::with_capacity(v.len());
    batch_invert_with(v, &mut prefix)
}

/// As [`batch_invert`], reusing a caller's buffer for the prefix products.
pub fn batch_invert_with(v: &mut [Fs], prefix: &mut Vec<Fs>) -> bool {
    prefix.clear();
    let mut acc = Fs::ONE;
    for x in v.iter() {
        prefix.push(acc);
        acc = acc * *x;
    }
    if acc.is_zero() {
        return false;
    }
    let mut inv = acc.inv();
    for i in (0..v.len()).rev() {
        let t = inv * v[i];
        v[i] = inv * prefix[i];
        inv = t;
    }
    true
}

// ============================================================ GLV

pub struct Glv {
    /// Cube root of unity in F_s (secp256k1's λ).
    pub beta: Fs,
    /// The matching eigenvalue in F_p (secp256k1's β): φ(P) = λ·P.
    pub lambda: Fp,
    g1: U256,
    g2: U256,
    a1: Fp,
    b1_abs: Fp,
    a2: Fp,
    b2: Fp,
}

pub fn glv() -> &'static Glv {
    static G: OnceLock<Glv> = OnceLock::new();
    G.get_or_init(|| {
        let fp = |h: &str| Fp::from_canonical(&U256::from_be_hex(h).to_be_bytes()).unwrap();
        let fs = |h: &str| Fs::from_canonical(&U256::from_be_hex(h).to_be_bytes()).unwrap();
        Glv {
            beta: fs("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72"),
            lambda: fp("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
            g1: U256::from_be_hex("3086d221a7d46bcde86c90e49284eb160000000000000000000000003086d2db"),
            g2: U256::from_be_hex("e4437ed6010e88286f547fa90abfe4c3000000000000000000000000e443823d"),
            // Short basis of {(a, b) : a + b·λ ≡ 0 (mod p)} from the extended
            // Euclidean algorithm. These differ by one from libsecp256k1's
            // values, which are for the other field of the cycle.
            a1: fp("000000000000000000000000000000003086d221a7d46bcde86c90e49284eb16"),
            b1_abs: fp("00000000000000000000000000000000e4437ed6010e88286f547fa90abfe4c3"),
            a2: fp("0000000000000000000000000000000114ca50f7a8e2f3f657c1108d9d44cfd9"),
            b2: fp("000000000000000000000000000000003086d221a7d46bcde86c90e49284eb16"),
        }
    })
}

/// round(k·g / 2^384) for a 256-bit k.
fn mul_shift_384(k: &U256, g: &U256) -> Fp {
    let (_lo, hi) = k.mul_wide(g);
    let b = hi.to_be_bytes();
    let c = u128::from_be_bytes(b[..16].try_into().unwrap());
    let round = (b[16] >> 7) as u128;
    Fp::from_u128(c + round)
}

/// Split k into (k1, k2) with k ≡ k1 + k2·λ (mod p) and |k1|, |k2| < 2^128.
/// Each half is (is_negative, magnitude).
pub fn glv_split(k: &Fp) -> [(bool, u128); 2] {
    let g = glv();
    let kk = k.to_uint();
    let c1 = mul_shift_384(&kk, &g.g1);
    let c2 = mul_shift_384(&kk, &g.g2);
    let k1 = *k - c1 * g.a1 - c2 * g.a2;
    let k2 = c1 * g.b1_abs - c2 * g.b2;
    let signed = |v: Fp| {
        let neg = -v;
        let (is_neg, mag) = if v.to_bytes()[0] >= 0x80 { (true, neg) } else { (false, v) };
        let b = mag.to_bytes();
        debug_assert!(b[..16].iter().all(|x| *x == 0), "GLV half out of range");
        (is_neg, u128::from_be_bytes(b[16..].try_into().unwrap()))
    };
    [signed(k1), signed(k2)]
}

// ============================================================ lockstep batch-affine

/// Scratch buffers for batched affine arithmetic.
#[derive(Default)]
struct Scratch {
    d: Vec<Fs>,
    e: Vec<Fs>,
    f: Vec<Fs>,
    prefix: Vec<Fs>,
}

// The batched helpers below fuse Montgomery's batch inversion into the
// arithmetic around it: a forward pass accumulates prefix products and the
// backward pass produces each inverse exactly when it is consumed (for the
// fused double-add it also accumulates the suffix products the second
// inversion needs). Same multiplication count, about half the memory passes.

/// Every point doubled, one inversion for all (no 2-torsion on this curve).
fn batch_double(a: &mut [Affine], sc: &mut Scratch) {
    let n = a.len();
    sc.prefix.clear();
    let mut acc = Fs::ONE;
    for p in a.iter() {
        acc *= p.y.double();
        sc.prefix.push(acc);
    }
    let mut inv = acc.inv();
    for j in (0..n).rev() {
        let p = a[j];
        let inv_j = if j == 0 { inv } else { inv * sc.prefix[j - 1] };
        inv *= p.y.double();
        let xx = p.x.square();
        let l = (xx.double() + xx) * inv_j;
        let x3 = l.square() - p.x.double();
        a[j] = Affine { x: x3, y: l * (p.x - x3) - p.y };
    }
}

/// out_j = P_j + s·Q_j for all j: the single-scalar fold, in parallel chunks.
/// Falls back to plain Jacobian arithmetic for any chunk where two points
/// collide (never seen in practice).
pub fn fold_single(s: &Fp, p: &[Affine], q: &[Affine]) -> Vec<Affine> {
    let chunk = fold_chunk_size(p.len());
    let parts: Vec<Vec<Affine>> = p
        .par_chunks(chunk)
        .zip(q.par_chunks(chunk))
        .map(|(pc, qc)| fold_single_chunk(s, pc, qc).unwrap_or_else(|| fold_fallback(&Fp::ONE, pc, s, qc)))
        .collect();
    parts.concat()
}

/// Chunks share each inversion across their points, but past about 1,024
/// points a chunk's working set leaves L2 and folding gets 3x slower
/// (measured), so chunks stay at 1,024 and parallelism comes from their count.
fn fold_chunk_size(n: usize) -> usize {
    let threads = rayon::current_num_threads().max(1);
    n.div_ceil(threads).clamp(256, 1024)
}

fn fold_fallback(a: &Fp, pc: &[Affine], b: &Fp, qc: &[Affine]) -> Vec<Affine> {
    let pts: Vec<Point> = pc.iter().zip(qc).map(|(x, y)| double_mul(a, &x.to_point(), b, &y.to_point())).collect();
    batch_normalize(&pts).into_iter().map(|o| o.expect("folded generators are never the identity")).collect()
}

/// Width-w NAF of a 128-bit magnitude, least significant digit first: digits
/// in {0, ±1, ±3, …, ±(2^(w−1) − 1)}, with at least w−1 zeros after each
/// non-zero digit.
fn wnaf(k: u128, w: u32) -> Vec<i8> {
    let (window, half) = (1i32 << w, 1i32 << (w - 1));
    let mut out = Vec::with_capacity(130);
    let (mut lo, mut hi) = (k, 0u128);
    while lo != 0 || hi != 0 {
        let mut d = 0i32;
        if lo & 1 == 1 {
            let m = (lo & ((1u128 << w) - 1)) as i32;
            d = if m >= half { m - window } else { m };
            if d > 0 {
                lo -= d as u128;
            } else {
                let (v, c) = lo.overflowing_add((-d) as u128);
                lo = v;
                hi += c as u128;
            }
        }
        out.push(d as i8);
        lo = (lo >> 1) | (hi << 127);
        hi = 0;
    }
    out
}

/// Width of the NAF recoding in folds. Width 5 measured only 3% faster and
/// its tables sit at the edge of L2 at 1,024 points, so width 4 it is.
const FOLD_W: u32 = 4;

/// a_j ← a_j ± b_j in place (one sign for the call), one inversion for all.
/// None if some a_j = ±b_j.
fn batch_add_assign(a: &mut [Affine], b: &[Affine], neg: bool, sc: &mut Scratch) -> Option<()> {
    let n = a.len();
    sc.prefix.clear();
    let mut acc = Fs::ONE;
    for (p, q) in a.iter().zip(b) {
        let d = q.x - p.x;
        if d.is_zero() {
            return None;
        }
        acc *= d;
        sc.prefix.push(acc);
    }
    let mut inv = acc.inv();
    for j in (0..n).rev() {
        let (p, q) = (a[j], b[j]);
        let inv_j = if j == 0 { inv } else { inv * sc.prefix[j - 1] };
        inv *= q.x - p.x;
        let qy = if neg { -q.y } else { q.y };
        let l = (qy - p.y) * inv_j;
        let x3 = l.square() - p.x - q.x;
        a[j] = Affine { x: x3, y: l * (p.x - x3) - p.y };
    }
    Some(())
}

/// a_j ← 2·a_j ± b_j, as (a ± b) + a (Eisenträger–Lauter–Montgomery),
/// skipping the middle point's y: 9M + 2S per point including both batched
/// inversions, against 10M + 3S for a doubling then an addition. Three passes.
fn batch_double_add_signed(a: &mut [Affine], b: &[Affine], neg: bool, sc: &mut Scratch) -> Option<()> {
    let n = a.len();
    sc.prefix.clear();
    let mut acc = Fs::ONE;
    for (p, q) in a.iter().zip(b) {
        let d = q.x - p.x;
        if d.is_zero() {
            return None;
        }
        acc *= d;
        sc.prefix.push(acc);
    }
    let mut inv = acc.inv();
    // Backward: λ1 and x3 of P ± Q, and suffix products of (x3 − xP).
    sc.d.resize(n, Fs::ZERO);
    sc.e.resize(n, Fs::ZERO);
    sc.f.resize(n, Fs::ZERO);
    let mut suffix = Fs::ONE;
    for j in (0..n).rev() {
        let (p, q) = (a[j], b[j]);
        let inv_j = if j == 0 { inv } else { inv * sc.prefix[j - 1] };
        inv *= q.x - p.x;
        let qy = if neg { -q.y } else { q.y };
        let l1 = (qy - p.y) * inv_j;
        let x3 = l1.square() - p.x - q.x;
        let f = x3 - p.x;
        if f.is_zero() {
            return None;
        }
        suffix *= f;
        sc.d[j] = l1;
        sc.e[j] = x3;
        sc.f[j] = suffix;
    }
    let mut inv2 = suffix.inv();
    // Forward: finish (P ± Q) + P.
    for j in 0..n {
        let p = a[j];
        let x3 = sc.e[j];
        let inv_f = if j + 1 < n { inv2 * sc.f[j + 1] } else { inv2 };
        inv2 *= x3 - p.x;
        let l2 = -sc.d[j] - p.y.double() * inv_f;
        let x4 = l2.square() - p.x - x3;
        a[j] = Affine { x: x4, y: l2 * (p.x - x4) - p.y };
    }
    Some(())
}

/// P_j + s·Q_j for a chunk: GLV halves, each in width-FOLD_W NAF over a table
/// of odd multiples of ±Q (and of φ(Q), taken from it for free).
fn fold_single_chunk(s: &Fp, p: &[Affine], q: &[Affine]) -> Option<Vec<Affine>> {
    let [(neg1, m1), (neg2, m2)] = glv_split(s);
    let (naf1, naf2) = (wnaf(m1, FOLD_W), wnaf(m2, FOLD_W));
    let len = naf1.len().max(naf2.len());
    let entries = 1usize << (FOLD_W - 2);
    let mut sc = Scratch::default();

    // t1[k] = (2k+1)·(±Q), t2[k] = (2k+1)·(±φ(Q)) = ±φ(t1[k]).
    let b1: Vec<Affine> = q.iter().map(|v| if neg1 { v.neg() } else { *v }).collect();
    let mut t1: Vec<Vec<Affine>> = vec![b1];
    if entries > 1 {
        let mut two = t1[0].clone();
        batch_double(&mut two, &mut sc);
        for k in 1..entries {
            let mut next = t1[k - 1].clone();
            batch_add_assign(&mut next, &two, false, &mut sc)?;
            t1.push(next);
        }
    }
    let flip = neg1 != neg2;
    let t2: Vec<Vec<Affine>> =
        t1.iter().map(|v| v.iter().map(|a| if flip { a.endo().neg() } else { a.endo() }).collect()).collect();
    let pick = |d: i8| ((d.unsigned_abs() as usize - 1) / 2, d < 0);

    let mut acc: Option<Vec<Affine>> = None;
    for i in (0..len).rev() {
        let d1 = naf1.get(i).copied().unwrap_or(0);
        let d2 = naf2.get(i).copied().unwrap_or(0);
        match acc.as_mut() {
            None => {
                let first = if d1 != 0 { Some((&t1, d1)) } else if d2 != 0 { Some((&t2, d2)) } else { None };
                if let Some((tab, d)) = first {
                    let (k, ng) = pick(d);
                    let mut v = tab[k].clone();
                    if ng {
                        v.iter_mut().for_each(|a| *a = a.neg());
                    }
                    if d1 != 0 && d2 != 0 {
                        let (k2, ng2) = pick(d2);
                        batch_add_assign(&mut v, &t2[k2], ng2, &mut sc)?;
                    }
                    acc = Some(v);
                }
            }
            Some(cur) => match (d1 != 0, d2 != 0) {
                (false, false) => batch_double(cur, &mut sc),
                (true, false) => {
                    let (k, ng) = pick(d1);
                    batch_double_add_signed(cur, &t1[k], ng, &mut sc)?
                }
                (false, true) => {
                    let (k, ng) = pick(d2);
                    batch_double_add_signed(cur, &t2[k], ng, &mut sc)?
                }
                (true, true) => {
                    let (k, ng) = pick(d1);
                    batch_double_add_signed(cur, &t1[k], ng, &mut sc)?;
                    let (k2, ng2) = pick(d2);
                    batch_add_assign(cur, &t2[k2], ng2, &mut sc)?
                }
            },
        }
    }
    let mut acc = acc?;
    batch_add_assign(&mut acc, p, false, &mut sc)?;
    Some(acc)
}

/// a·P + b·Q with a shared doubling chain.
pub fn double_mul(a: &Fp, p: &Point, b: &Fp, q: &Point) -> Point {
    let pq = p.add(q);
    let (ab, bb) = (a.to_bytes(), b.to_bytes());
    let mut acc = Point::IDENTITY;
    for i in 0..32 {
        for bit in (0..8).rev() {
            acc = acc.double();
            match ((ab[i] >> bit) & 1, (bb[i] >> bit) & 1) {
                (1, 1) => acc = acc.add(&pq),
                (1, 0) => acc = acc.add(p),
                (0, 1) => acc = acc.add(q),
                _ => {}
            }
        }
    }
    acc
}

fn digit(be: &[u8; 32], start: usize, c: usize) -> usize {
    let mut d = 0usize;
    for k in 0..c {
        let bit = start + k;
        if bit >= 256 {
            break;
        }
        if (be[31 - bit / 8] >> (bit % 8)) & 1 == 1 {
            d |= 1 << k;
        }
    }
    d
}

/// Small inputs: plain Pippenger with mixed additions.
pub fn msm_affine_simple(points: &[Affine], scalars: &[Fp]) -> Point {
    let n = points.len();
    if n < 8 {
        return points.iter().zip(scalars).fold(Point::IDENTITY, |acc, (p, s)| acc.add(&p.to_point().mul(s)));
    }
    let c = (((n as f64).log2() * 0.7) as usize + 1).clamp(2, 16);
    let bytes: Vec<[u8; 32]> = scalars.iter().map(|s| s.to_bytes()).collect();
    let windows = 256usize.div_ceil(c);
    let mut acc = Point::IDENTITY;
    let mut buckets = vec![Point::IDENTITY; (1 << c) - 1];
    for w in (0..windows).rev() {
        for _ in 0..c {
            acc = acc.double();
        }
        buckets.iter_mut().for_each(|b| *b = Point::IDENTITY);
        for (i, p) in points.iter().enumerate() {
            let d = digit(&bytes[i], w * c, c);
            if d != 0 {
                buckets[d - 1] = buckets[d - 1].add_affine(p);
            }
        }
        let mut running = Point::IDENTITY;
        let mut sum = Point::IDENTITY;
        for b in buckets.iter().rev() {
            running = running.add(b);
            sum = sum.add(&running);
        }
        acc = acc.add(&sum);
    }
    acc
}

/// c bits of a little-endian 256-bit value starting at `pos` (zero past the end).
#[inline(always)]
fn bits_at(l: &[u64; 4], pos: usize, c: usize) -> u64 {
    if pos >= 256 {
        return 0;
    }
    let (idx, off) = (pos / 64, pos % 64);
    let mut v = l[idx] >> off;
    if off + c > 64 && idx + 1 < 4 {
        v |= l[idx + 1] << (64 - off);
    }
    v & ((1u64 << c) - 1)
}

/// The signed c-bit digit of window w, in [−2^(c−1), 2^(c−1)). The carry
/// into window w is exactly bit w·c − 1 of the scalar, so every window's
/// digits are computed independently, straight from the scalar.
#[inline(always)]
fn signed_digit(l: &[u64; 4], w: usize, c: usize) -> i32 {
    let d = bits_at(l, w * c, c) as i64;
    let carry_in = if w == 0 { 0 } else { bits_at(l, w * c - 1, 1) as i64 };
    let carry_out = bits_at(l, (w + 1) * c - 1, 1) as i64;
    (d + carry_in - (carry_out << c)) as i32
}

/// One window of Pippenger with affine buckets filled by batched additions
/// (one inversion per batch of 512). A point whose bucket is already in the
/// current batch goes into that bucket's Jacobian overflow accumulator
/// instead of waiting, so the cost stays linear however the digits are
/// distributed (heavy buckets from small scalars, or a narrow top window).
/// x-coordinate collisions (a doubling, or a point meeting its negation) are
/// handled individually.
fn window_batched(points: &[Affine], scalars: &[[u64; 4]], w: usize, c: usize) -> Point {
    const BATCH: usize = 512;
    let nb = 1usize << (c - 1);
    let mut buckets = vec![Affine { x: Fs::ZERO, y: Fs::ZERO }; nb];
    let mut filled = vec![false; nb];
    let mut busy = vec![false; nb];
    let mut overflow = vec![Point::IDENTITY; nb];
    let mut batch: Vec<(usize, Affine)> = Vec::with_capacity(BATCH);
    let mut den: Vec<Fs> = Vec::with_capacity(BATCH);
    let mut prefix: Vec<Fs> = Vec::with_capacity(BATCH);

    // Forward pass: prefix products of the x-differences; backward pass: each
    // inverse as it is consumed. Same x (a doubling, or a point meeting its
    // negation) is rare and handled on its own.
    let flush = |batch: &mut Vec<(usize, Affine)>,
                 buckets: &mut [Affine],
                 filled: &mut [bool],
                 busy: &mut [bool],
                 den: &mut Vec<Fs>,
                 prefix: &mut Vec<Fs>| {
        if batch.is_empty() {
            return;
        }
        den.clear();
        prefix.clear();
        let mut acc = Fs::ONE;
        for (b, p) in batch.iter() {
            let d = p.x - buckets[*b].x;
            let d = if d.is_zero() { Fs::ONE } else { d };
            den.push(d);
            acc *= d;
            prefix.push(acc);
        }
        let mut inv = acc.inv();
        for k in (0..batch.len()).rev() {
            let (b, p) = batch[k];
            let inv_k = if k == 0 { inv } else { inv * prefix[k - 1] };
            inv *= den[k];
            let q = buckets[b];
            if p.x == q.x {
                match (p.to_point().add(&q.to_point())).to_affine() {
                    Some(r) => buckets[b] = r,
                    None => filled[b] = false,
                }
            } else {
                let l = (p.y - q.y) * inv_k;
                let x3 = l.square() - q.x - p.x;
                buckets[b] = Affine { x: x3, y: l * (q.x - x3) - q.y };
            }
            busy[b] = false;
        }
        batch.clear();
    };

    for (p, l) in points.iter().zip(scalars) {
        let d = signed_digit(l, w, c);
        if d == 0 {
            continue;
        }
        let (b, p) = if d > 0 { (d as usize - 1, *p) } else { ((-d) as usize - 1, p.neg()) };
        if busy[b] {
            overflow[b] = overflow[b].add_affine(&p);
        } else if !filled[b] {
            buckets[b] = p;
            filled[b] = true;
        } else {
            busy[b] = true;
            batch.push((b, p));
            if batch.len() == BATCH {
                flush(&mut batch, &mut buckets, &mut filled, &mut busy, &mut den, &mut prefix);
            }
        }
    }
    flush(&mut batch, &mut buckets, &mut filled, &mut busy, &mut den, &mut prefix);

    let mut running = Point::IDENTITY;
    let mut sum = Point::IDENTITY;
    for b in (0..nb).rev() {
        if filled[b] {
            running = running.add_affine(&buckets[b]);
        }
        if !overflow[b].is_identity() {
            running = running.add(&overflow[b]);
        }
        sum = sum.add(&running);
    }
    sum
}

/// Multi-scalar multiplication over affine points: Pippenger with signed
/// digits and batch-affine buckets (about 6 field multiplications per point
/// per window instead of 11), windows in parallel.
///
/// Below 2^17 points, when most scalars are full-size, each scalar k also
/// becomes k1 + k2·λ over P and φ(P) (GLV): as many additions, half the
/// windows. Measured, that is 20% faster at 2^14 and 5% at 2^16, but 7% slower
/// at 2^18 and 2.5x slower on 0/1 scalars, where splitting costs more than it
/// saves. So the inner-product rounds use it; the large commitments, the
/// small-valued witness commitments and the verifier do not.
pub fn msm_affine(points: &[Affine], scalars: &[Fp]) -> Point {
    assert_eq!(points.len(), scalars.len());
    let n = points.len();
    if n < 256 {
        return msm_affine_simple(points, scalars);
    }
    let limbs: Vec<[u64; 4]> = scalars.par_iter().map(|s| s.canonical_limbs()).collect();
    let small = limbs.iter().filter(|l| l[1] == 0 && l[2] == 0 && l[3] == 0).count();
    if n < 1 << 17 && small * 4 < n {
        let split: Vec<[(Affine, [u64; 4]); 2]> = points
            .par_iter()
            .zip(scalars.par_iter())
            .map(|(p, s)| {
                let [(n1, m1), (n2, m2)] = glv_split(s);
                let e = p.endo();
                [
                    (if n1 { p.neg() } else { *p }, [m1 as u64, (m1 >> 64) as u64, 0, 0]),
                    (if n2 { e.neg() } else { e }, [m2 as u64, (m2 >> 64) as u64, 0, 0]),
                ]
            })
            .collect();
        let (pts, halves): (Vec<Affine>, Vec<[u64; 4]>) = split.into_iter().flatten().unzip();
        pippenger(&pts, &halves, 128)
    } else {
        pippenger(points, &limbs, 256)
    }
}

/// Pippenger over scalars of at most `bits` bits (little-endian limbs).
fn pippenger(points: &[Affine], limbs: &[[u64; 4]], bits: usize) -> Point {
    let m = points.len();
    // Cost ≈ (bits/c)·(6m + 27·2^(c−1)) field multiplications; minimise over c.
    let c = (6..=18usize)
        .min_by_key(|&c| ((6 * m + 27 * (1usize << (c - 1))) as f64 * (bits + 1) as f64 / c as f64) as u64)
        .unwrap();
    let windows = bits.div_ceil(c) + 1;
    let sums: Vec<Point> = (0..windows).into_par_iter().map(|w| window_batched(points, limbs, w, c)).collect();
    let mut acc = Point::IDENTITY;
    for sum in sums.iter().rev() {
        for _ in 0..c {
            acc = acc.double();
        }
        acc = acc.add(sum);
    }
    acc
}

/// Multi-scalar multiplication over any points (identities contribute nothing).
pub fn msm(points: &[Point], scalars: &[Fp]) -> Point {
    assert_eq!(points.len(), scalars.len());
    let (pts, sc): (Vec<Affine>, Vec<Fp>) = batch_normalize(points)
        .into_iter()
        .zip(scalars)
        .filter_map(|(p, s)| p.map(|p| (p, *s)))
        .unzip();
    msm_affine(&pts, &sc)
}

// ============================================================ generator cache

/// Nothing-up-my-sleeve generators are deterministic, so they are computed once
/// and cached (in $VAULT_SEAL_CACHE, or the user's cache folder: see
/// [`default_cache_dir`]). Loading checks
/// every point is on the curve and recomputes a random sample to catch a
/// corrupted or substituted file. VAULT_SEAL_NO_CACHE=1 disables the cache.
pub fn cached_generators(label: &[u8], n: usize) -> Vec<Affine> {
    let compute = |from: usize| -> Vec<Affine> {
        (from..n).into_par_iter().map(|i| Affine::hash_to_curve(label, i as u64)).collect()
    };
    if std::env::var_os("VAULT_SEAL_NO_CACHE").is_some() {
        return compute(0);
    }
    let dir = std::env::var_os("VAULT_SEAL_CACHE").map(std::path::PathBuf::from).or_else(default_cache_dir);
    let Some(dir) = dir else { return compute(0) };
    let path = dir.join(format!("generators-v1-{}.bin", hex::encode(Sha256::digest(label))));

    let mut have: Vec<Affine> = read_cache(&path, label, n).unwrap_or_default();
    if have.len() >= n {
        return have;
    }
    let from = have.len();
    have.extend(compute(from));
    if std::fs::create_dir_all(&dir).is_ok() {
        write_cache(&path, &have);
    }
    have
}

/// The per-user cache folder each platform expects: %LOCALAPPDATA%\\crowdvault
/// on Windows, ~/Library/Caches/crowdvault on macOS, and $XDG_CACHE_HOME or
/// ~/.cache (then /crowdvault) elsewhere. None if the variable is missing, in
/// which case generators are computed afresh each time.
pub(crate) fn default_cache_dir() -> Option<std::path::PathBuf> {
    let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(std::path::PathBuf::from);
    if cfg!(windows) {
        var("LOCALAPPDATA").map(|d| d.join("crowdvault"))
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|h| h.join("Library").join("Caches").join("crowdvault"))
    } else {
        var("XDG_CACHE_HOME").or_else(|| var("HOME").map(|h| h.join(".cache"))).map(|d| d.join("crowdvault"))
    }
}

/// Write a cache file atomically (temporary file, then rename).
pub(crate) fn write_cache(path: &std::path::Path, pts: &[Affine]) {
    let mut out = b"CVGEN1\0\0".to_vec();
    out.extend((pts.len() as u64).to_le_bytes());
    for p in pts {
        out.extend(p.x.to_bytes());
        out.extend(p.y.to_bytes());
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    if std::fs::write(&tmp, &out).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Read the first min(count, n) generators of a cache file. The cache holds
/// as many as the largest proof ever made needed; reading and checking only
/// the prefix in use keeps small proofs from paying for big ones.
pub(crate) fn read_cache(path: &std::path::Path, label: &[u8], n: usize) -> Option<Vec<Affine>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut head = [0u8; 16];
    f.read_exact(&mut head).ok()?;
    if &head[..8] != b"CVGEN1\0\0" {
        return None;
    }
    let count = u64::from_le_bytes(head[8..16].try_into().ok()?);
    // The length must match the count exactly, which catches truncated files.
    if f.metadata().ok()?.len() != count.checked_mul(64)?.checked_add(16)? {
        return None;
    }
    let take = usize::try_from(count).ok()?.min(n);
    let mut body = vec![0u8; take * 64];
    f.read_exact(&mut body).ok()?;
    parse_points(&body, label)
}

/// Parse and check cached points: each canonical and on the curve, and a
/// fresh random sample recomputed from scratch.
fn parse_points(b: &[u8], label: &[u8]) -> Option<Vec<Affine>> {
    let count = b.len() / 64;
    let pts: Vec<Affine> = b
        .par_chunks(64)
        .map(|c| {
            let x = Fs::from_canonical(c[..32].try_into().unwrap())?;
            let y = Fs::from_canonical(c[32..].try_into().unwrap())?;
            let a = Affine { x, y };
            a.is_on_curve().then_some(a)
        })
        .collect::<Option<Vec<_>>>()?;
    // Recompute a sample of indices, chosen fresh each time.
    let mut seed = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
    let mut r = u64::from_le_bytes(seed);
    for _ in 0..16.min(count) {
        r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let i = (r >> 11) as usize % count;
        if pts[i] != Affine::hash_to_curve(label, i as u64) {
            return None;
        }
    }
    Some(pts)
}
