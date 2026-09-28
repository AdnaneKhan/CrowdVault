//! The two prime fields of the secp256k1 / secq256k1 cycle, with hand-written
//! 4-limb Montgomery arithmetic (CIOS on 128-bit intermediates), about twice
//! as fast as generic big-integer Montgomery code for these moduli.
//!
//! * [`Fp`]: secp256k1's base field. Circuit values live here, and so do
//!   secq256k1 scalars, which is what lets the circuit do secp256k1 point
//!   arithmetic natively.
//! * [`Fs`]: secp256k1's scalar field, which is secq256k1's base field.
//!
//! Values are kept in Montgomery form and always fully reduced, so equality
//! is limb equality.

use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crypto_bigint::{Encoding, U256};
use rand_core::{OsRng, RngCore};

#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (t as u64, (t >> 127) as u64)
}

#[inline(always)]
fn add4(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut c = 0;
    for i in 0..4 {
        (r[i], c) = adc(a[i], b[i], c);
    }
    (r, c)
}

#[inline(always)]
fn sub4(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut borrow = 0;
    for i in 0..4 {
        (r[i], borrow) = sbb(a[i], b[i], borrow);
    }
    (r, borrow)
}

/// a·b·R⁻¹ mod m for a, b < m (coarsely integrated operand scanning).
#[inline(always)]
fn mont_mul(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4], inv: u64) -> [u64; 4] {
    let mut t = [0u64; 5];
    for i in 0..4 {
        let mut c = 0;
        for j in 0..4 {
            (t[j], c) = mac(t[j], a[j], b[i], c);
        }
        let (t4, t5) = adc(t[4], c, 0);
        let k = t[0].wrapping_mul(inv);
        let (_, mut c) = mac(t[0], k, m[0], 0);
        for j in 1..4 {
            (t[j - 1], c) = mac(t[j], k, m[j], c);
        }
        let (v, cc) = adc(t4, c, 0);
        t[3] = v;
        t[4] = t5 + cc;
    }
    let r = [t[0], t[1], t[2], t[3]];
    let (s, borrow) = sub4(&r, m);
    if t[4] != 0 || borrow == 0 {
        s
    } else {
        r
    }
}

/// Reduce a 512-bit value t < m·2^256 to t·R⁻¹ mod m.
#[inline(always)]
fn mont_reduce(r: [u64; 8], m: &[u64; 4], inv: u64) -> [u64; 4] {
    let [r0, r1, r2, r3, r4, r5, r6, r7] = r;
    let k = r0.wrapping_mul(inv);
    let (_, c) = mac(r0, k, m[0], 0);
    let (r1, c) = mac(r1, k, m[1], c);
    let (r2, c) = mac(r2, k, m[2], c);
    let (r3, c) = mac(r3, k, m[3], c);
    let (r4, c2) = adc(r4, 0, c);
    let k = r1.wrapping_mul(inv);
    let (_, c) = mac(r1, k, m[0], 0);
    let (r2, c) = mac(r2, k, m[1], c);
    let (r3, c) = mac(r3, k, m[2], c);
    let (r4, c) = mac(r4, k, m[3], c);
    let (r5, c2) = adc(r5, c2, c);
    let k = r2.wrapping_mul(inv);
    let (_, c) = mac(r2, k, m[0], 0);
    let (r3, c) = mac(r3, k, m[1], c);
    let (r4, c) = mac(r4, k, m[2], c);
    let (r5, c) = mac(r5, k, m[3], c);
    let (r6, c2) = adc(r6, c2, c);
    let k = r3.wrapping_mul(inv);
    let (_, c) = mac(r3, k, m[0], 0);
    let (r4, c) = mac(r4, k, m[1], c);
    let (r5, c) = mac(r5, k, m[2], c);
    let (r6, c) = mac(r6, k, m[3], c);
    let (r7, c2) = adc(r7, c2, c);
    let r = [r4, r5, r6, r7];
    let (s, borrow) = sub4(&r, m);
    if c2 != 0 || borrow == 0 {
        s
    } else {
        r
    }
}

/// a²·R⁻¹ mod m: 10 limb products instead of 16, then one reduction.
#[inline(always)]
fn mont_sqr(a: &[u64; 4], m: &[u64; 4], inv: u64) -> [u64; 4] {
    let (r1, c) = mac(0, a[0], a[1], 0);
    let (r2, c) = mac(0, a[0], a[2], c);
    let (r3, r4) = mac(0, a[0], a[3], c);
    let (r3, c) = mac(r3, a[1], a[2], 0);
    let (r4, r5) = mac(r4, a[1], a[3], c);
    let (r5, r6) = mac(r5, a[2], a[3], 0);
    let r7 = r6 >> 63;
    let r6 = (r6 << 1) | (r5 >> 63);
    let r5 = (r5 << 1) | (r4 >> 63);
    let r4 = (r4 << 1) | (r3 >> 63);
    let r3 = (r3 << 1) | (r2 >> 63);
    let r2 = (r2 << 1) | (r1 >> 63);
    let r1 = r1 << 1;
    let (r0, c) = mac(0, a[0], a[0], 0);
    let (r1, c) = adc(r1, 0, c);
    let (r2, c) = mac(r2, a[1], a[1], c);
    let (r3, c) = adc(r3, 0, c);
    let (r4, c) = mac(r4, a[2], a[2], c);
    let (r5, c) = adc(r5, 0, c);
    let (r6, c) = mac(r6, a[3], a[3], c);
    let (r7, _) = adc(r7, 0, c);
    mont_reduce([r0, r1, r2, r3, r4, r5, r6, r7], m, inv)
}

fn limbs_from_be(b: &[u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_be_bytes(b[24 - 8 * i..32 - 8 * i].try_into().unwrap()))
}

fn be_from_limbs(l: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[24 - 8 * i..32 - 8 * i].copy_from_slice(&l[i].to_be_bytes());
    }
    b
}

macro_rules! prime_field {
    ($name:ident, modulus: $m:expr, inv: $inv:expr, r2: $r2:expr, one: $one:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u64; 4]);

        impl $name {
            const M: [u64; 4] = $m;
            const INV: u64 = $inv;
            const R2: [u64; 4] = $r2;
            pub const ZERO: Self = Self([0; 4]);
            pub const ONE: Self = Self($one);

            pub fn modulus() -> U256 {
                U256::from_be_bytes(be_from_limbs(&Self::M))
            }

            /// Any 256-bit value, reduced.
            fn from_limbs(v: [u64; 4]) -> Self {
                let (s, borrow) = sub4(&v, &Self::M);
                let v = if borrow == 0 { s } else { v };
                Self(mont_mul(&v, &Self::R2, &Self::M, Self::INV))
            }

            pub fn from_uint(v: &U256) -> Self {
                Self::from_limbs(limbs_from_be(&v.to_be_bytes()))
            }

            pub fn from_u64(v: u64) -> Self {
                Self::from_limbs([v, 0, 0, 0])
            }

            pub fn from_u128(v: u128) -> Self {
                Self::from_limbs([v as u64, (v >> 64) as u64, 0, 0])
            }

            pub fn from_bool(b: bool) -> Self {
                if b {
                    Self::ONE
                } else {
                    Self::ZERO
                }
            }

            /// Reduce 64 uniformly random bytes (bias below 2^-256).
            pub fn from_wide(b: &[u8; 64]) -> Self {
                let hi = Self::from_limbs(limbs_from_be(b[..32].try_into().unwrap()));
                let lo = Self::from_limbs(limbs_from_be(b[32..].try_into().unwrap()));
                let two256 = Self::from_limbs([u64::MAX; 4]) + Self::ONE;
                hi * two256 + lo
            }

            /// Big-endian bytes, rejecting anything that is not fully reduced.
            pub fn from_canonical(b: &[u8; 32]) -> Option<Self> {
                let v = limbs_from_be(b);
                if sub4(&v, &Self::M).1 == 0 {
                    None
                } else {
                    Some(Self::from_limbs(v))
                }
            }

            /// The canonical (non-Montgomery) limbs, little-endian.
            pub fn canonical_limbs(&self) -> [u64; 4] {
                mont_mul(&self.0, &[1, 0, 0, 0], &Self::M, Self::INV)
            }

            pub fn to_bytes(&self) -> [u8; 32] {
                be_from_limbs(&self.canonical_limbs())
            }

            pub fn to_uint(&self) -> U256 {
                U256::from_be_bytes(self.to_bytes())
            }

            pub fn is_zero(&self) -> bool {
                self.0 == [0; 4]
            }

            pub fn is_odd(&self) -> bool {
                self.canonical_limbs()[0] & 1 == 1
            }

            #[inline(always)]
            pub fn square(&self) -> Self {
                Self(mont_sqr(&self.0, &Self::M, Self::INV))
            }

            #[inline(always)]
            pub fn double(&self) -> Self {
                *self + *self
            }

            pub fn pow(&self, e: &U256) -> Self {
                let mut acc = Self::ONE;
                for byte in e.to_be_bytes() {
                    for i in (0..8).rev() {
                        acc = acc.square();
                        if (byte >> i) & 1 == 1 {
                            acc = acc * *self;
                        }
                    }
                }
                acc
            }

            /// Multiplicative inverse by Fermat; zero maps to zero.
            pub fn inv(&self) -> Self {
                self.pow(&Self::modulus().wrapping_sub(&U256::from_u64(2)))
            }

            pub fn random() -> Self {
                let mut b = [0u8; 64];
                OsRng.fill_bytes(&mut b);
                Self::from_wide(&b)
            }

            /// Square root by Tonelli–Shanks, if one exists. One exponentiation
            /// per call: the field's constants are computed once.
            pub fn sqrt(&self) -> Option<Self> {
                use std::sync::OnceLock;
                static CONSTS: OnceLock<(U256, u32, $name)> = OnceLock::new();
                if self.is_zero() {
                    return Some(Self::ZERO);
                }
                let (qm1_2, s, c0) = *CONSTS.get_or_init(|| {
                    let m1 = Self::modulus().wrapping_sub(&U256::ONE);
                    let mut q = m1;
                    let mut s = 0u32;
                    while q.to_be_bytes()[31] & 1 == 0 {
                        q = q.shr_vartime(1);
                        s += 1;
                    }
                    let half = m1.shr_vartime(1);
                    let mut z = Self::from_u64(2);
                    while z.pow(&half) == Self::ONE {
                        z = z + Self::ONE;
                    }
                    (q.wrapping_sub(&U256::ONE).shr_vartime(1), s, z.pow(&q))
                });
                // w = a^((q−1)/2), so r = a^((q+1)/2) and t = a^q.
                let w = self.pow(&qm1_2);
                let mut r = *self * w;
                let mut t = r * w;
                let mut m = s;
                let mut c = c0;
                while t != Self::ONE {
                    let mut i = 0u32;
                    let mut tt = t;
                    while tt != Self::ONE {
                        tt = tt.square();
                        i += 1;
                        if i == m {
                            return None; // not a square
                        }
                    }
                    let mut b = c;
                    for _ in 0..(m - i - 1) {
                        b = b.square();
                    }
                    m = i;
                    c = b.square();
                    t = t * c;
                    r = r * b;
                }
                Some(r)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }
        impl Add for $name {
            type Output = Self;
            #[inline(always)]
            fn add(self, o: Self) -> Self {
                let (r, carry) = add4(&self.0, &o.0);
                let (s, borrow) = sub4(&r, &Self::M);
                Self(if carry != 0 || borrow == 0 { s } else { r })
            }
        }
        impl Sub for $name {
            type Output = Self;
            #[inline(always)]
            fn sub(self, o: Self) -> Self {
                let (r, borrow) = sub4(&self.0, &o.0);
                Self(if borrow != 0 { add4(&r, &Self::M).0 } else { r })
            }
        }
        impl Mul for $name {
            type Output = Self;
            #[inline(always)]
            fn mul(self, o: Self) -> Self {
                Self(mont_mul(&self.0, &o.0, &Self::M, Self::INV))
            }
        }
        impl Neg for $name {
            type Output = Self;
            #[inline(always)]
            fn neg(self) -> Self {
                Self::ZERO - self
            }
        }
        impl AddAssign for $name {
            fn add_assign(&mut self, o: Self) {
                *self = *self + o;
            }
        }
        impl SubAssign for $name {
            fn sub_assign(&mut self, o: Self) {
                *self = *self - o;
            }
        }
        impl MulAssign for $name {
            fn mul_assign(&mut self, o: Self) {
                *self = *self * o;
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.to_bytes()))
            }
        }
    };
}

prime_field!(
    Fp,
    modulus: [0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
    inv: 0xd838091dd2253531,
    r2: [0x000007a2000e90a1, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000],
    one: [0x00000001000003d1, 0, 0, 0]
);
prime_field!(
    Fs,
    modulus: [0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff],
    inv: 0x4b0dff665588b13f,
    r2: [0x896cf21467d7d140, 0x741496c20e7cf878, 0xe697f5e45bcd07c6, 0x9d671cd581c69bc5],
    one: [0x402da1732fc9bebf, 0x4551231950b75fc4, 0x0000000000000001, 0]
);

#[cfg(test)]
mod tests {
    //! Check the hand-written arithmetic against crypto-bigint's generic
    //! Montgomery implementation on random inputs.
    use super::*;
    use crypto_bigint::impl_modulus;
    use crypto_bigint::modular::constant_mod::Residue;

    impl_modulus!(RefP, U256, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    impl_modulus!(RefS, U256, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    macro_rules! check {
        ($f:ty, $r:ty) => {{
            type R = Residue<$r, { U256::LIMBS }>;
            let conv = |x: &$f| R::new(&x.to_uint());
            assert_eq!(<$f>::ONE, <$f>::from_u64(1));
            assert_eq!(<$f>::ONE.to_uint(), U256::ONE);
            for _ in 0..2000 {
                let (a, b) = (<$f>::random(), <$f>::random());
                let (ra, rb) = (conv(&a), conv(&b));
                assert_eq!((a * b).to_uint(), (ra * rb).retrieve());
                assert_eq!(a.square(), a * a);
                assert_eq!((a + b).to_uint(), (ra + rb).retrieve());
                assert_eq!((a - b).to_uint(), (ra - rb).retrieve());
                assert_eq!((-a).to_uint(), (R::ZERO - ra).retrieve());
                assert_eq!(a * a.inv(), <$f>::ONE);
                assert_eq!(<$f>::from_canonical(&a.to_bytes()), Some(a));
            }
            // Edge values: m − 1, and values at or above m are rejected.
            let m1 = <$f>::ZERO - <$f>::ONE;
            assert_eq!(m1.square(), <$f>::ONE);
            assert_eq!((m1 + <$f>::ONE), <$f>::ZERO);
            assert_eq!((m1 * m1), <$f>::ONE);
            assert!(<$f>::from_canonical(&<$f>::modulus().to_be_bytes()).is_none());
            assert!(<$f>::from_canonical(&[0xff; 32]).is_none());
            let s = <$f>::random().square();
            let r = s.sqrt().unwrap();
            assert_eq!(r * r, s);
        }};
    }

    #[test]
    fn matches_reference_arithmetic() {
        check!(Fp, RefP);
        check!(Fs, RefS);
    }
}

impl zeroize::Zeroize for Fp {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl zeroize::Zeroize for Fs {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
