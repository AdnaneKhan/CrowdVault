//! The statement proven for a sealed file, as an arithmetic circuit over F_p.
//!
//! Public: the campaign key X, the sealed key R, the file's name and length,
//! every ciphertext element c_i, and the fingerprint F.
//! Private: only r.
//!
//! 1. R = r·G and S = r·X, with 4-bit fixed-base windows and complete
//!    addition formulas (Renes–Costello–Batina 2016, algorithm 8), so no
//!    input can hit an exceptional case.
//! 2. K = Poseidon(S, R, X, name, length).
//! 3. keystream k_i = Poseidon(K, block), and the file is m_i = c_i − k_i.
//! 4. F = Poseidon-sponge(length; m_0, m_1, …).
//!
//! After the reveal x·R = r·X = S, so whoever knows x recomputes K and gets
//! exactly the file with fingerprint F.

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

use super::cs::{Cs, Lc, Var};
use super::field::Fp;
use super::poseidon::{self, domain, permute, RATE, RF, ROUNDS, RP, T};

pub struct Statement {
    pub campaign: AffinePoint,
    pub sealed: AffinePoint,
    pub name_h: Fp,
    pub len: u64,
    pub ct: Vec<Fp>,
    pub fingerprint: Fp,
}

/// Affine coordinates as field elements; None for the identity.
pub fn try_coords(p: &AffinePoint) -> Option<(Fp, Fp)> {
    let ep = p.to_encoded_point(false);
    let x: [u8; 32] = (*ep.x()?).into();
    let y: [u8; 32] = (*ep.y()?).into();
    Some((Fp::from_canonical(&x)?, Fp::from_canonical(&y)?))
}

/// For points already validated as non-identity.
pub fn coords(p: &AffinePoint) -> (Fp, Fp) {
    try_coords(p).expect("validated point")
}

pub fn scalar_bits(r: &Scalar) -> [bool; 256] {
    let b = r.to_bytes();
    std::array::from_fn(|i| (b[31 - i / 8] >> (i % 8)) & 1 == 1)
}

fn dom_kdf() -> Fp {
    domain(b"kdf")
}
fn dom_ks() -> Fp {
    domain(b"keystream")
}
fn dom_fp() -> Fp {
    domain(b"fingerprint")
}

// ============================================================ native

pub fn kdf_native(s: (Fp, Fp), r: (Fp, Fp), x: (Fp, Fp), name_h: Fp, len: u64) -> Fp {
    let mut st = [s.0, s.1, r.0, r.1, x.0, x.1, name_h, Fp::from_u64(len), dom_kdf()];
    permute(&mut st);
    st[0]
}

pub fn keystream_native(k: Fp, block: u64) -> [Fp; RATE] {
    let mut st = [Fp::ZERO; T];
    st[0] = k;
    st[1] = Fp::from_u64(block);
    st[T - 1] = dom_ks();
    permute(&mut st);
    std::array::from_fn(|i| st[i])
}

pub fn fingerprint_native(elems: &[Fp], len: u64) -> Fp {
    let mut st = [Fp::ZERO; T];
    st[T - 1] = dom_fp() + Fp::from_u64(len);
    for b in 0..elems.len().div_ceil(RATE).max(1) {
        for i in 0..RATE {
            if let Some(m) = elems.get(b * RATE + i) {
                st[i] += *m;
            }
        }
        permute(&mut st);
    }
    st[0]
}

// ============================================================ Poseidon gadget

fn pow5_var(cs: &mut Cs, x: Lc) -> Var {
    let (xv, x2) = cs.square(x);
    let (_, x4) = cs.square(Lc::var(x2));
    cs.mul(Lc::var(x4), Lc::var(xv))
}

fn full_round(cs: &mut Cs, st: &mut [Lc; T], r: usize) {
    let p = poseidon::params();
    for i in 0..T {
        let lc = std::mem::take(&mut st[i]) + p.rc[r][i];
        st[i] = Lc::var(pow5_var(cs, lc));
    }
    let lanes = std::mem::take(st);
    *st = std::array::from_fn(|i| {
        let mut lc = Lc::zero();
        for (j, lane) in lanes.iter().enumerate() {
            lc = lc + lane.clone() * p.mds[i][j];
        }
        lc
    });
}

/// The partial rounds are the same linear algebra in every permutation, so
/// it is worked out once: for each round, the S-box input as coefficients over
/// [the 9 input lanes | the S-box outputs so far | 1], and likewise the output
/// lanes. Each permutation then only combines its own wires with these.
struct PartialPlan {
    sbox_in: Vec<Vec<Fp>>,
    out: Vec<Vec<Fp>>,
}

fn partial_plan() -> &'static PartialPlan {
    static PLAN: std::sync::OnceLock<PartialPlan> = std::sync::OnceLock::new();
    PLAN.get_or_init(|| {
        let p = poseidon::params();
        let w = T + RP + 1;
        let c = w - 1;
        let unit = |i: usize| {
            let mut v = vec![Fp::ZERO; w];
            v[i] = Fp::ONE;
            v
        };
        let mut st: Vec<Vec<Fp>> = (0..T).map(unit).collect();
        let mut sbox_in = Vec::with_capacity(RP);
        for (k, r) in (RF / 2..RF / 2 + RP).enumerate() {
            for (i, lane) in st.iter_mut().enumerate() {
                lane[c] += p.rc[r][i];
            }
            sbox_in.push(st[0].clone());
            st[0] = unit(T + k);
            let old = st.clone();
            for (i, lane) in st.iter_mut().enumerate() {
                for (t, v) in lane.iter_mut().enumerate() {
                    *v = (0..T).fold(Fp::ZERO, |acc, j| acc + p.mds[i][j] * old[j][t]);
                }
            }
        }
        PartialPlan { sbox_in, out: st }
    })
}

fn partial_rounds(cs: &mut Cs, st: &mut [Lc; T]) {
    let plan = partial_plan();
    // The input lanes, dense over their own wires (plus a constant).
    let mut basis: Vec<Var> = Vec::new();
    for lc in st.iter() {
        for (v, _) in &lc.0 {
            if *v != Var::One && !basis.contains(v) {
                basis.push(*v);
            }
        }
    }
    let b = basis.len();
    let mut lanes = vec![vec![Fp::ZERO; b + 1]; T];
    for (i, lc) in st.iter().enumerate() {
        for (v, c) in &lc.0 {
            let idx = if *v == Var::One { b } else { basis.iter().position(|x| x == v).unwrap() };
            lanes[i][idx] += *c;
        }
    }
    let combine = |coef: &[Fp], sboxes: &[Var]| -> Lc {
        let mut dense = vec![Fp::ZERO; b + 1];
        for (i, lane) in lanes.iter().enumerate() {
            let k = coef[i];
            if !k.is_zero() {
                for (d, l) in dense.iter_mut().zip(lane) {
                    *d += k * *l;
                }
            }
        }
        dense[b] += coef[T + RP];
        let mut lc = Lc(Vec::with_capacity(b + sboxes.len() + 1));
        for t in 0..b {
            if !dense[t].is_zero() {
                lc.0.push((basis[t], dense[t]));
            }
        }
        for (k, v) in sboxes.iter().enumerate() {
            if !coef[T + k].is_zero() {
                lc.0.push((*v, coef[T + k]));
            }
        }
        if !dense[b].is_zero() {
            lc.0.push((Var::One, dense[b]));
        }
        lc
    };
    let mut sboxes: Vec<Var> = Vec::with_capacity(RP);
    for r in 0..RP {
        let lc = combine(&plan.sbox_in[r], &sboxes);
        sboxes.push(pow5_var(cs, lc));
    }
    for (i, lane) in st.iter_mut().enumerate() {
        *lane = combine(&plan.out[i], &sboxes);
    }
}

pub fn perm_gadget(cs: &mut Cs, mut st: [Lc; T]) -> [Lc; T] {
    for r in 0..RF / 2 {
        full_round(cs, &mut st, r);
    }
    partial_rounds(cs, &mut st);
    for r in RF / 2 + RP..ROUNDS {
        full_round(cs, &mut st, r);
    }
    st
}

// ============================================================ secp256k1 gadget

type Proj = (Lc, Lc, Lc);

/// Per window: the multilinear coefficients (x, y) of a 16-entry table.
pub struct Tables(Vec<[[Fp; 16]; 2]>);

fn offset_point() -> ProjectivePoint {
    for ctr in 0u64.. {
        let h = Sha256::new().chain_update(b"crowdvault/zk1/ec-offset").chain_update(ctr.to_be_bytes()).finalize();
        let mut enc = [2u8; 33];
        enc[1..].copy_from_slice(&h);
        if let Ok(ep) = EncodedPoint::from_bytes(enc) {
            if let Some(p) = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep)) {
                return p.into();
            }
        }
    }
    unreachable!()
}

/// Turns 16 table entries into coefficients of the monomials in 4 bits.
fn mobius(v: &mut [Fp; 16]) {
    for i in 0..4 {
        for m in 0..16 {
            if m & (1 << i) != 0 {
                v[m] = v[m] - v[m ^ (1 << i)];
            }
        }
    }
}

/// Window w holds d·16^w·B + Q for d = 0..15, with the last window shifted by
/// −64·Q so the offsets cancel. The offset Q (dlog unknown) keeps every table
/// entry away from the identity. None if some entry is the identity anyway,
/// which only a deliberately constructed campaign key can cause.
pub fn tables(base: &ProjectivePoint) -> Option<Tables> {
    let q = offset_point();
    let last = q - q * Scalar::from(64u64);
    let mut bw = *base;
    let mut out = Vec::with_capacity(64);
    for w in 0..64 {
        let mut xs = [Fp::ZERO; 16];
        let mut ys = [Fp::ZERO; 16];
        let mut acc = if w == 63 { last } else { q };
        for d in 0..16 {
            let (x, y) = try_coords(&acc.to_affine())?;
            xs[d] = x;
            ys[d] = y;
            acc += bw;
        }
        mobius(&mut xs);
        mobius(&mut ys);
        out.push([xs, ys]);
        for _ in 0..4 {
            bw = bw.double();
        }
    }
    Some(Tables(out))
}

/// Complete mixed addition on y² = x³ + 7 (RCB16 algorithm 8): 11 gates.
fn add_mixed(cs: &mut Cs, p: &Proj, q: &(Lc, Lc)) -> Proj {
    let (x1, y1, z1) = p;
    let (x2, y2) = q;
    let b3 = Fp::from_u64(21);
    let t0 = Lc::var(cs.mul(x1.clone(), x2.clone()));
    let t1 = Lc::var(cs.mul(y1.clone(), y2.clone()));
    let t3 = Lc::var(cs.mul(x2.clone() + y2.clone(), x1.clone() + y1.clone()));
    let t3 = t3 - (t0.clone() + t1.clone());
    let t4 = Lc::var(cs.mul(y2.clone(), z1.clone())) + y1.clone();
    let y3 = Lc::var(cs.mul(x2.clone(), z1.clone())) + x1.clone();
    let t0 = t0.clone() + t0.clone() + t0;
    let t2 = z1.clone() * b3;
    let z3 = t1.clone() + t2.clone();
    let t1 = t1 - t2;
    let y3 = y3 * b3;
    let x3 = Lc::var(cs.mul(t4.clone(), y3.clone()));
    let t2 = Lc::var(cs.mul(t3.clone(), t1.clone()));
    let x3 = t2 - x3;
    let y3 = Lc::var(cs.mul(y3, t0.clone()));
    let t1 = Lc::var(cs.mul(t1, z3.clone()));
    let y3 = t1 + y3;
    let t0 = Lc::var(cs.mul(t0, t3));
    let z3 = Lc::var(cs.mul(z3, t4)) + t0;
    (x3, y3, z3)
}

/// The same formula on plain values, for testing against k256.
#[cfg(test)]
pub fn add_mixed_native(p: (Fp, Fp, Fp), q: (Fp, Fp)) -> (Fp, Fp, Fp) {
    let ((x1, y1, z1), (x2, y2)) = (p, q);
    let b3 = Fp::from_u64(21);
    let t0 = x1 * x2;
    let t1 = y1 * y2;
    let t3 = (x2 + y2) * (x1 + y1) - (t0 + t1);
    let t4 = y2 * z1 + y1;
    let y3 = x2 * z1 + x1;
    let t0 = t0 + t0 + t0;
    let t2 = b3 * z1;
    let z3 = t1 + t2;
    let t1 = t1 - t2;
    let y3 = b3 * y3;
    let x3 = t3 * t1 - t4 * y3;
    let y3 = t1 * z3 + y3 * t0;
    let z3 = z3 * t4 + t0 * t3;
    (x3, y3, z3)
}

/// r·B1 and r·B2 for the same r, sharing the bit products between both.
fn fixed_base_pair(cs: &mut Cs, bits: &[Var], t1: &Tables, t2: &Tables) -> (Proj, Proj) {
    let mut acc1: Option<Proj> = None;
    let mut acc2: Option<Proj> = None;
    for w in 0..64 {
        let mut mono: Vec<Lc> = vec![Lc::zero(); 16];
        mono[0] = Lc::constant(Fp::ONE);
        for i in 0..4 {
            mono[1 << i] = Lc::var(bits[4 * w + i]);
        }
        for mask in 3..16usize {
            if mask.count_ones() >= 2 {
                let low = mask & mask.wrapping_neg();
                mono[mask] = Lc::var(cs.mul(mono[mask ^ low].clone(), mono[low].clone()));
            }
        }
        let sel = |coef: &[Fp; 16]| {
            let mut lc = Lc::zero();
            for (m, c) in coef.iter().enumerate() {
                if !c.is_zero() {
                    lc = lc + mono[m].clone() * *c;
                }
            }
            lc
        };
        let p1 = (sel(&t1.0[w][0]), sel(&t1.0[w][1]));
        let p2 = (sel(&t2.0[w][0]), sel(&t2.0[w][1]));
        acc1 = Some(match acc1 {
            None => (p1.0, p1.1, Lc::constant(Fp::ONE)),
            Some(a) => add_mixed(cs, &a, &p1),
        });
        acc2 = Some(match acc2 {
            None => (p2.0, p2.1, Lc::constant(Fp::ONE)),
            Some(a) => add_mixed(cs, &a, &p2),
        });
    }
    (acc1.unwrap(), acc2.unwrap())
}

// ============================================================ the statement

/// None if the campaign key can't be used for proofs (see `tables`).
pub fn build(cs: &mut Cs, st: &Statement, r_bits: &[bool; 256]) -> Option<()> {
    let c = Lc::constant;
    let tg = tables(&ProjectivePoint::GENERATOR)?;
    let tx = tables(&ProjectivePoint::from(st.campaign))?;
    let bits: Vec<Var> = r_bits.iter().map(|b| cs.bit(*b)).collect();
    let (rp, sp) = fixed_base_pair(cs, &bits, &tg, &tx);

    // R = r·G, matching the public sealed key.
    let (rx, ry) = coords(&st.sealed);
    cs.constrain(rp.0.clone() - rp.2.clone() * rx);
    cs.constrain(rp.1.clone() - rp.2.clone() * ry);
    cs.inverse(rp.2);

    // S = r·X, in affine form.
    let zi = cs.inverse(sp.2);
    let sx = cs.mul(sp.0, Lc::var(zi));
    let sy = cs.mul(sp.1, Lc::var(zi));

    // K = Poseidon(S, R, X, name, length)
    let (xx, xy) = coords(&st.campaign);
    let kdf_in = [
        Lc::var(sx),
        Lc::var(sy),
        c(rx),
        c(ry),
        c(xx),
        c(xy),
        c(st.name_h),
        c(Fp::from_u64(st.len)),
        c(dom_kdf()),
    ];
    let k = perm_gadget(cs, kdf_in)[0].clone();

    // m_i = c_i − keystream_i
    let n = st.ct.len();
    let mut m: Vec<Lc> = Vec::with_capacity(n);
    for b in 0..n.div_ceil(RATE) {
        let mut ks_in: [Lc; T] = std::array::from_fn(|_| Lc::zero());
        ks_in[0] = k.clone();
        ks_in[1] = c(Fp::from_u64(b as u64));
        ks_in[T - 1] = c(dom_ks());
        let ks = perm_gadget(cs, ks_in);
        for (i, lane) in ks.iter().enumerate().take(RATE) {
            if let Some(ci) = st.ct.get(b * RATE + i) {
                m.push(c(*ci) - lane.clone());
            }
        }
    }

    // F = sponge(length; m)
    let mut s: [Lc; T] = std::array::from_fn(|_| Lc::zero());
    s[T - 1] = c(dom_fp() + Fp::from_u64(st.len));
    for b in 0..n.div_ceil(RATE).max(1) {
        for (i, lane) in s.iter_mut().enumerate().take(RATE) {
            if let Some(mi) = m.get(b * RATE + i) {
                *lane = std::mem::take(lane) + mi.clone();
            }
        }
        s = perm_gadget(cs, s);
    }
    cs.constrain(s[0].clone() - c(st.fingerprint));
    Some(())
}
