//! A constraint system in the Bulletproofs form: n multiplication gates
//! a_L[i] · a_R[i] = a_O[i], plus any number of linear constraints over the
//! gate wires. Linear operations are free; only multiplications cost gates.
//!
//! The prover and the verifier run the same circuit code. The verifier's copy
//! carries no values, only structure, and the structure never depends on the
//! witness.

use std::ops::{Add, Mul, Sub};

use super::field::Fp;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Var {
    One,
    L(usize),
    R(usize),
    O(usize),
}

/// A linear combination Σ coeff · var.
#[derive(Clone, Debug, Default)]
pub struct Lc(pub Vec<(Var, Fp)>);

impl Lc {
    pub fn zero() -> Lc {
        Lc(Vec::new())
    }
    pub fn constant(c: Fp) -> Lc {
        Lc(vec![(Var::One, c)])
    }
    pub fn var(v: Var) -> Lc {
        Lc(vec![(v, Fp::ONE)])
    }
}

impl Add for Lc {
    type Output = Lc;
    fn add(mut self, o: Lc) -> Lc {
        self.0.extend(o.0);
        self
    }
}
impl Sub for Lc {
    type Output = Lc;
    fn sub(mut self, o: Lc) -> Lc {
        self.0.extend(o.0.into_iter().map(|(v, c)| (v, -c)));
        self
    }
}
impl Mul<Fp> for Lc {
    type Output = Lc;
    fn mul(mut self, k: Fp) -> Lc {
        self.0.iter_mut().for_each(|t| t.1 = t.1 * k);
        self
    }
}
impl Add<Fp> for Lc {
    type Output = Lc;
    fn add(mut self, c: Fp) -> Lc {
        self.0.push((Var::One, c));
        self
    }
}

pub struct Cs {
    pub prover: bool,
    pub al: Vec<Fp>,
    pub ar: Vec<Fp>,
    pub ao: Vec<Fp>,
    /// Each entry is a linear combination constrained to equal zero.
    pub cons: Vec<Lc>,
}

/// The witness holds r's bits, the shared secret and the file key: wipe it.
impl Drop for Cs {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.al.zeroize();
        self.ar.zeroize();
        self.ao.zeroize();
    }
}

impl Cs {
    pub fn new(prover: bool) -> Cs {
        Cs { prover, al: Vec::new(), ar: Vec::new(), ao: Vec::new(), cons: Vec::new() }
    }

    pub fn gates(&self) -> usize {
        self.al.len()
    }

    fn val(&self, v: Var) -> Fp {
        match v {
            Var::One => Fp::ONE,
            Var::L(i) => self.al[i],
            Var::R(i) => self.ar[i],
            Var::O(i) => self.ao[i],
        }
    }

    /// The prover's value of a linear combination (zero for the verifier).
    pub fn value(&self, lc: &Lc) -> Fp {
        if !self.prover {
            return Fp::ZERO;
        }
        lc.0.iter().fold(Fp::ZERO, |acc, (v, c)| acc + *c * self.val(*v))
    }

    /// A gate with free inputs and no linking constraints.
    pub fn alloc(&mut self, l: Fp, r: Fp) -> (Var, Var, Var) {
        let (l, r) = if self.prover { (l, r) } else { (Fp::ZERO, Fp::ZERO) };
        let i = self.al.len();
        self.al.push(l);
        self.ar.push(r);
        self.ao.push(l * r);
        (Var::L(i), Var::R(i), Var::O(i))
    }

    pub fn constrain(&mut self, lc: Lc) {
        self.cons.push(lc);
    }

    /// a · b, returning the output wire.
    pub fn mul(&mut self, a: Lc, b: Lc) -> Var {
        let (va, vb) = (self.value(&a), self.value(&b));
        let (l, r, o) = self.alloc(va, vb);
        self.constrain(a - Lc::var(l));
        self.constrain(b - Lc::var(r));
        o
    }

    /// a², returning (a as a wire, a² as a wire).
    pub fn square(&mut self, a: Lc) -> (Var, Var) {
        let v = self.value(&a);
        let (l, r, o) = self.alloc(v, v);
        self.constrain(a - Lc::var(l));
        self.constrain(Lc::var(r) - Lc::var(l));
        (l, o)
    }

    /// A wire constrained to 0 or 1.
    pub fn bit(&mut self, b: bool) -> Var {
        let v = Fp::from_bool(b);
        let (l, r, o) = self.alloc(v, Fp::ONE - v);
        self.constrain(Lc::var(l) + Lc::var(r) + (-Fp::ONE));
        self.constrain(Lc::var(o));
        l
    }

    /// The inverse of a, which also proves a ≠ 0.
    pub fn inverse(&mut self, a: Lc) -> Var {
        let v = self.value(&a);
        let (l, r, o) = self.alloc(v, v.inv());
        self.constrain(a - Lc::var(l));
        self.constrain(Lc::var(o) + (-Fp::ONE));
        r
    }

    /// Whether the prover's assignment satisfies every gate and constraint.
    pub fn is_satisfied(&self) -> bool {
        (0..self.gates()).all(|i| self.al[i] * self.ar[i] == self.ao[i])
            && self.cons.iter().all(|lc| {
                lc.0.iter().fold(Fp::ZERO, |acc, (v, c)| acc + *c * self.val(*v)).is_zero()
            })
    }
}
