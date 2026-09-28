//! Bulletproofs for arithmetic circuits: Bünz, Bootle, Boneh, Poelstra, Wuille
//! and Maxwell, "Bulletproofs: Short Proofs for Confidential Transactions and
//! More" (IEEE S&P 2018), section 5.3, without committed inputs, made
//! non-interactive with Fiat–Shamir over SHA-256.
//!
//! Transparent (no trusted setup), zero-knowledge, and sound under the
//! discrete-logarithm assumption in secq256k1. A proof is 2·log2(n) + 8 points
//! and 5 scalars.

use rayon::prelude::*;
use sha2::{Digest, Sha256};

use zeroize::{Zeroize, Zeroizing};
use super::cs::{Cs, Lc, Var};
use super::field::Fp;
use super::secq::{batch_normalize, cached_generators, fold_single, msm_affine, Affine, Point};

// ============================================================ transcript

/// Fiat–Shamir transcript: a SHA-256 hash chain over everything sent so far.
/// Callers must bind the full statement before proving or verifying.
pub struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    pub fn new(label: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"crowdvault/zk1/transcript");
        h.update((label.len() as u64).to_be_bytes());
        h.update(label);
        Self { state: h.finalize().into() }
    }

    pub fn append(&mut self, label: &[u8], data: &[u8]) {
        let mut h = Sha256::new();
        h.update(self.state);
        h.update((label.len() as u64).to_be_bytes());
        h.update(label);
        h.update((data.len() as u64).to_be_bytes());
        h.update(data);
        self.state = h.finalize().into();
    }

    fn point(&mut self, label: &[u8], p: &Point) {
        self.append(label, &p.to_bytes());
    }

    fn scalar(&mut self, label: &[u8], s: &Fp) {
        self.append(label, &s.to_bytes());
    }

    pub fn challenge(&mut self, label: &[u8]) -> Fp {
        loop {
            let mut wide = [0u8; 64];
            for half in 0..2u8 {
                let mut h = Sha256::new();
                h.update(self.state);
                h.update(b"challenge");
                h.update((label.len() as u64).to_be_bytes());
                h.update(label);
                h.update([half]);
                wide[half as usize * 32..][..32].copy_from_slice(&h.finalize());
            }
            self.append(b"challenge-drawn", label);
            let c = Fp::from_wide(&wide);
            if !c.is_zero() {
                return c;
            }
        }
    }
}

// ============================================================ generators

pub struct Gens {
    pub g: Vec<Affine>,
    pub h: Vec<Affine>,
    /// Commits to values.
    pub b: Affine,
    /// Commits to blinding factors.
    pub bb: Affine,
    /// Inner-product argument generator.
    pub u: Affine,
}

impl Gens {
    pub fn new(n: usize) -> Gens {
        let (g, h) = rayon::join(
            || cached_generators(b"crowdvault/zk1/G", n),
            || cached_generators(b"crowdvault/zk1/H", n),
        );
        Gens {
            g,
            h,
            b: Affine::hash_to_curve(b"crowdvault/zk1/B", 0),
            bb: Affine::hash_to_curve(b"crowdvault/zk1/B-blind", 0),
            u: Affine::hash_to_curve(b"crowdvault/zk1/U", 0),
        }
    }
}

// ============================================================ proof

#[derive(Clone)]
pub struct Proof {
    pub a_i: Point,
    pub a_o: Point,
    pub s: Point,
    /// T1, T3, T4, T5, T6
    pub t: [Point; 5],
    pub tau_x: Fp,
    pub mu: Fp,
    pub t_hat: Fp,
    pub ls: Vec<Point>,
    pub rs: Vec<Point>,
    pub a: Fp,
    pub b: Fp,
}

const T_EXPONENTS: [usize; 5] = [1, 3, 4, 5, 6];
const T_LABELS: [&[u8]; 5] = [b"T1", b"T3", b"T4", b"T5", b"T6"];

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn point(&mut self) -> Option<Point> {
        let mut a = [0u8; 33];
        a.copy_from_slice(self.b.get(self.pos..self.pos + 33)?);
        self.pos += 33;
        Point::from_bytes(&a)
    }
    fn scalar(&mut self) -> Option<Fp> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.b.get(self.pos..self.pos + 32)?);
        self.pos += 32;
        Fp::from_canonical(&a)
    }
}

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = vec![self.ls.len() as u8];
        for p in [&self.a_i, &self.a_o, &self.s].into_iter().chain(self.t.iter()) {
            o.extend_from_slice(&p.to_bytes());
        }
        for s in [&self.tau_x, &self.mu, &self.t_hat] {
            o.extend_from_slice(&s.to_bytes());
        }
        for (l, r) in self.ls.iter().zip(&self.rs) {
            o.extend_from_slice(&l.to_bytes());
            o.extend_from_slice(&r.to_bytes());
        }
        o.extend_from_slice(&self.a.to_bytes());
        o.extend_from_slice(&self.b.to_bytes());
        o
    }

    pub fn from_bytes(b: &[u8]) -> Option<Proof> {
        let k = *b.first()? as usize;
        if k > 40 || b.len() != 1 + (8 + 2 * k) * 33 + 5 * 32 {
            return None;
        }
        let mut r = Reader { b, pos: 1 };
        let (a_i, a_o, s) = (r.point()?, r.point()?, r.point()?);
        let t = [r.point()?, r.point()?, r.point()?, r.point()?, r.point()?];
        let (tau_x, mu, t_hat) = (r.scalar()?, r.scalar()?, r.scalar()?);
        let mut ls = Vec::with_capacity(k);
        let mut rs = Vec::with_capacity(k);
        for _ in 0..k {
            ls.push(r.point()?);
            rs.push(r.point()?);
        }
        let (a, bb) = (r.scalar()?, r.scalar()?);
        Some(Proof { a_i, a_o, s, t, tau_x, mu, t_hat, ls, rs, a, b: bb })
    }
}

// ============================================================ helpers

fn ip(a: &[Fp], b: &[Fp]) -> Fp {
    a.iter().zip(b).fold(Fp::ZERO, |s, (x, y)| s + *x * *y)
}

fn powers(x: Fp, n: usize) -> Vec<Fp> {
    let mut v = Vec::with_capacity(n);
    let mut c = Fp::ONE;
    for _ in 0..n {
        v.push(c);
        c *= x;
    }
    v
}

struct Weights {
    wl: Vec<Fp>,
    wr: Vec<Fp>,
    wo: Vec<Fp>,
    wc: Fp,
}

/// Fold the constraints with powers of z: w_X = Σ_q z^(q+1) W_X[q], and
/// wc = Σ_q z^(q+1) c_q where each constraint reads W·a = c.
fn weights(cons: &[Lc], n: usize, z: Fp) -> Weights {
    let mut w = Weights { wl: vec![Fp::ZERO; n], wr: vec![Fp::ZERO; n], wo: vec![Fp::ZERO; n], wc: Fp::ZERO };
    let mut zq = z;
    for lc in cons {
        for (v, k) in &lc.0 {
            let c = zq * *k;
            match v {
                Var::L(i) => w.wl[*i] += c,
                Var::R(i) => w.wr[*i] += c,
                Var::O(i) => w.wo[*i] += c,
                Var::One => w.wc -= c,
            }
        }
        zq *= z;
    }
    w
}

fn commit(gens: &Gens, blind: Fp, gv: &[Fp], hv: Option<&[Fp]>) -> Point {
    let mut pts: Vec<Affine> = vec![gens.bb];
    let mut sc = vec![blind];
    pts.extend_from_slice(&gens.g);
    sc.extend_from_slice(gv);
    if let Some(hv) = hv {
        pts.extend_from_slice(&gens.h);
        sc.extend_from_slice(hv);
    }
    msm_affine(&pts, &sc)
}

// ============================================================ prover

pub fn prove(cs: &Cs, gens: &Gens, tr: &mut Transcript) -> Proof {
    let t0 = std::time::Instant::now();
    let n = gens.g.len();
    assert!(n.is_power_of_two() && cs.gates() <= n);
    let pad = |v: &[Fp]| {
        let mut v = v.to_vec();
        v.resize(n, Fp::ZERO);
        v
    };
    let (al, ar, ao) = (Zeroizing::new(pad(&cs.al)), Zeroizing::new(pad(&cs.ar)), Zeroizing::new(pad(&cs.ao)));

    let (alpha, beta, rho) = (Fp::random(), Fp::random(), Fp::random());
    let sl: Zeroizing<Vec<Fp>> = Zeroizing::new((0..n).map(|_| Fp::random()).collect());
    let sr: Zeroizing<Vec<Fp>> = Zeroizing::new((0..n).map(|_| Fp::random()).collect());
    let ((a_i, a_o), s) = rayon::join(
        || rayon::join(|| commit(gens, alpha, &al, Some(&ar)), || commit(gens, beta, &ao, None)),
        || commit(gens, rho, &sl, Some(&sr)),
    );
    tr.point(b"A_I", &a_i);
    tr.point(b"A_O", &a_o);
    tr.point(b"S", &s);
    super::profile("  commitments A_I, A_O, S", t0);
    let t1 = std::time::Instant::now();
    let y = tr.challenge(b"y");
    let z = tr.challenge(b"z");

    let w = weights(&cs.cons, n, z);
    let yn = powers(y, n);
    let yinv = powers(y.inv(), n);

    // l(X) = l1·X + l2·X² + l3·X³,  r(X) = r0 + r1·X + r3·X³
    let l1: Zeroizing<Vec<Fp>> = Zeroizing::new((0..n).map(|i| al[i] + yinv[i] * w.wr[i]).collect());
    let l2 = ao;
    let l3 = sl;
    let r0: Vec<Fp> = (0..n).map(|i| w.wo[i] - yn[i]).collect();
    let r1: Zeroizing<Vec<Fp>> = Zeroizing::new((0..n).map(|i| yn[i] * ar[i] + w.wl[i]).collect());
    let r3: Zeroizing<Vec<Fp>> = Zeroizing::new((0..n).map(|i| yn[i] * sr[i]).collect());

    // Coefficients of X, X³, X⁴, X⁵, X⁶ in t(X) = <l(X), r(X)>. The X²
    // coefficient is fixed by the statement and never committed.
    let t = [
        ip(&l1, &r0),
        ip(&l2, &r1) + ip(&l3, &r0),
        ip(&l1, &r3) + ip(&l3, &r1),
        ip(&l2, &r3),
        ip(&l3, &r3),
    ];
    let taus: [Fp; 5] = std::array::from_fn(|_| Fp::random());
    let tpts: [Point; 5] = std::array::from_fn(|i| msm_affine(&[gens.b, gens.bb], &[t[i], taus[i]]));
    for (label, p) in T_LABELS.iter().zip(&tpts) {
        tr.point(label, p);
    }
    let x = tr.challenge(b"x");
    let xp = powers(x, 7);

    let l: Vec<Fp> = (0..n).map(|i| l1[i] * xp[1] + l2[i] * xp[2] + l3[i] * xp[3]).collect();
    let r: Vec<Fp> = (0..n).map(|i| r0[i] + r1[i] * xp[1] + r3[i] * xp[3]).collect();
    let t_hat = ip(&l, &r);
    let tau_x = (0..5).fold(Fp::ZERO, |acc, i| acc + taus[i] * xp[T_EXPONENTS[i]]);
    let mu = alpha * xp[1] + beta * xp[2] + rho * xp[3];
    tr.scalar(b"tau_x", &tau_x);
    tr.scalar(b"mu", &mu);
    tr.scalar(b"t_hat", &t_hat);
    let wch = tr.challenge(b"w");
    let u = gens.u.to_point().mul(&wch).to_affine().expect("w is non-zero");
    super::profile("  constraint weights and polynomials", t1);

    let t2 = std::time::Instant::now();
    let (ls, rs, a, b) = ipa_prove(tr, gens.g.clone(), gens.h.clone(), yinv, &u, l, r);
    super::profile("  inner-product argument", t2);
    Proof { a_i, a_o, s, t: tpts, tau_x, mu, t_hat, ls, rs, a, b }
}

/// Inner-product argument (protocol 2 of the paper) over generators g and
/// h_eff[j] = f[j]·h[j] with f[j] = y^(−j).
///
/// The points are stored up to a common scalar factor per vector (cg, ch),
/// tracked in scalar space. Each fold then needs one scalar, not two:
///
///   g'[j] = x⁻¹·g[j] + x·g[n/2+j]          = cg·x⁻¹ · (G[j] + x²·G[n/2+j])
///   h'[j] = x·h_eff[j] + x⁻¹·h_eff[n/2+j]  = ch·x·f[j] · (H[j] + x⁻²·y^(−n/2)·H[n/2+j])
///
/// and the weights stay f[j] = y^(−j). The factors only rescale the scalars of
/// each round's L and R. Proofs are unchanged.
fn ipa_prove(
    tr: &mut Transcript,
    mut g: Vec<Affine>,
    mut h: Vec<Affine>,
    f: Vec<Fp>,
    u: &Affine,
    mut a: Vec<Fp>,
    mut b: Vec<Fp>,
) -> (Vec<Point>, Vec<Point>, Fp, Fp) {
    let mut ls = Vec::new();
    let mut rs = Vec::new();
    let (mut cg, mut ch) = (Fp::ONE, Fp::ONE);
    let (mut t_msm, mut t_fold) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
    while a.len() > 1 {
        let n2 = a.len() / 2;
        let cl = ip(&a[..n2], &b[n2..]);
        let cr = ip(&a[n2..], &b[..n2]);

        let mut pl: Vec<Affine> = g[n2..].to_vec();
        pl.extend_from_slice(&h[..n2]);
        pl.push(*u);
        let mut sl: Vec<Fp> = a[..n2].iter().map(|v| *v * cg).collect();
        sl.extend((0..n2).map(|j| b[n2 + j] * f[j] * ch));
        sl.push(cl);

        let mut pr: Vec<Affine> = g[..n2].to_vec();
        pr.extend_from_slice(&h[n2..]);
        pr.push(*u);
        let mut sr: Vec<Fp> = a[n2..].iter().map(|v| *v * cg).collect();
        sr.extend((0..n2).map(|j| b[j] * f[n2 + j] * ch));
        sr.push(cr);

        let t0 = std::time::Instant::now();
        let (l, r) = rayon::join(|| msm_affine(&pl, &sl), || msm_affine(&pr, &sr));
        sl.zeroize();
        sr.zeroize();
        t_msm += t0.elapsed();
        tr.point(b"L", &l);
        tr.point(b"R", &r);
        let x = tr.challenge(b"x_ipa");
        let xi = x.inv();

        // a and b are secret (the witness, blinded): wipe each round's before replacing it.
        let na: Vec<Fp> = (0..n2).map(|j| a[j] * x + a[n2 + j] * xi).collect();
        let nb: Vec<Fp> = (0..n2).map(|j| b[j] * xi + b[n2 + j] * x).collect();
        a.zeroize();
        b.zeroize();
        a = na;
        b = nb;
        let (x2, xi2) = (x.square(), xi.square());
        let h_scalar = xi2 * f[n2];
        let t0 = std::time::Instant::now();
        let (ng, nh) =
            rayon::join(|| fold_single(&x2, &g[..n2], &g[n2..]), || fold_single(&h_scalar, &h[..n2], &h[n2..]));
        t_fold += t0.elapsed();
        cg *= xi;
        ch *= x;
        g = ng;
        h = nh;
        ls.push(l);
        rs.push(r);
    }
    if std::env::var_os("VAULT_SEAL_PROFILE").is_some() {
        eprintln!("  [profile]     IPA L/R multi-scalar multiplications: {t_msm:.2?}, folding: {t_fold:.2?}");
    }
    (ls, rs, a[0], b[0])
}

// ============================================================ verifier

/// Checks both verification equations of the protocol as one multi-scalar
/// multiplication, the t̂ check weighted by a fresh random scalar.
pub fn verify(cons: &[Lc], gens: &Gens, tr: &mut Transcript, pf: &Proof) -> bool {
    let n = gens.g.len();
    let k = n.trailing_zeros() as usize;
    if !n.is_power_of_two() || pf.ls.len() != k || pf.rs.len() != k {
        return false;
    }
    tr.point(b"A_I", &pf.a_i);
    tr.point(b"A_O", &pf.a_o);
    tr.point(b"S", &pf.s);
    let y = tr.challenge(b"y");
    let z = tr.challenge(b"z");
    for (label, p) in T_LABELS.iter().zip(&pf.t) {
        tr.point(label, p);
    }
    let x = tr.challenge(b"x");
    tr.scalar(b"tau_x", &pf.tau_x);
    tr.scalar(b"mu", &pf.mu);
    tr.scalar(b"t_hat", &pf.t_hat);
    let wch = tr.challenge(b"w");
    let mut xs = Vec::with_capacity(k);
    for j in 0..k {
        tr.point(b"L", &pf.ls[j]);
        tr.point(b"R", &pf.rs[j]);
        xs.push(tr.challenge(b"x_ipa"));
    }

    let w = weights(cons, n, z);
    let yinv = powers(y.inv(), n);
    let delta = (0..n).fold(Fp::ZERO, |acc, i| acc + yinv[i] * w.wr[i] * w.wl[i]);
    let xp = powers(x, 7);

    // s_i = Π_j x_j^(±1), + where bit (k−1−j) of i is set.
    let xinv: Vec<Fp> = xs.iter().map(|v| v.inv()).collect();
    let x2: Vec<Fp> = xs.iter().map(|v| v.square()).collect();
    let xinv2: Vec<Fp> = xinv.iter().map(|v| v.square()).collect();
    let mut s = vec![Fp::ZERO; n];
    let mut sinv = vec![Fp::ZERO; n];
    s[0] = xinv.iter().fold(Fp::ONE, |a, v| a * *v);
    sinv[0] = xs.iter().fold(Fp::ONE, |a, v| a * *v);
    for i in 1..n {
        let lg = (usize::BITS - 1 - i.leading_zeros()) as usize;
        let j = k - 1 - lg;
        s[i] = s[i - (1 << lg)] * x2[j];
        sinv[i] = sinv[i - (1 << lg)] * xinv2[j];
    }

    let c = Fp::random();
    let mut pts: Vec<Affine> = Vec::with_capacity(2 * n + 2 * k + 11);
    let mut sc: Vec<Fp> = Vec::with_capacity(2 * n + 2 * k + 11);
    pts.extend_from_slice(&gens.g);
    sc.extend((0..n).into_par_iter().map(|i| xp[1] * yinv[i] * w.wr[i] - pf.a * s[i]).collect::<Vec<_>>());
    pts.extend_from_slice(&gens.h);
    sc.extend(
        (0..n)
            .into_par_iter()
            .map(|i| yinv[i] * (xp[1] * w.wl[i] + w.wo[i] - pf.b * sinv[i]) - Fp::ONE)
            .collect::<Vec<_>>(),
    );
    pts.extend([gens.bb, gens.b, gens.u]);
    sc.extend([c * pf.tau_x - pf.mu, c * (pf.t_hat - xp[2] * (w.wc + delta)), wch * (pf.t_hat - pf.a * pf.b)]);
    // Points sent in the proof, normalised together; identities contribute nothing.
    let mut proof_pts = vec![pf.a_i, pf.a_o, pf.s];
    let mut proof_sc = vec![xp[1], xp[2], xp[3]];
    for (e, p) in T_EXPONENTS.iter().zip(&pf.t) {
        proof_pts.push(*p);
        proof_sc.push(-(c * xp[*e]));
    }
    for j in 0..k {
        proof_pts.extend([pf.ls[j], pf.rs[j]]);
        proof_sc.extend([x2[j], xinv2[j]]);
    }
    for (p, s) in batch_normalize(&proof_pts).into_iter().zip(proof_sc) {
        if let Some(p) = p {
            pts.push(p);
            sc.push(s);
        }
    }
    msm_affine(&pts, &sc).is_identity()
}
