//! Poseidon (Grassi, Khovratovich, Rechberger, Roy, Schofnegger 2021) over
//! F_p, secp256k1's base field.
//!
//! Width 9 (rate 8, capacity 1 element, about 256 bits), S-box x^5, which is
//! a permutation because gcd(5, p − 1) = 1. 8 full and 64 partial rounds: the
//! paper's bounds for a 256-bit field at 128-bit security need
//! R_F ≥ 6 and R_F + R_P ≥ 57; we use 72. The MDS matrix is the paper's
//! Cauchy construction, M[i][j] = 1 / (i + (t + j)). Round constants come
//! from SHA-256, nothing up our sleeve.
//!
//! Before production, run the reference parameter script's MDS checks
//! (infinitely long subspace trails) against this field and these choices.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::field::Fp;

pub const T: usize = 9;
pub const RATE: usize = 8;
pub const RF: usize = 8;
pub const RP: usize = 64;
pub const ROUNDS: usize = RF + RP;

pub struct Params {
    pub rc: Vec<[Fp; T]>,
    pub mds: [[Fp; T]; T],
}

/// SHA-256 based hash to F_p, uniform via 64-byte reduction.
pub fn hash_to_field(label: &[u8], parts: &[&[u8]]) -> Fp {
    let mut wide = [0u8; 64];
    for half in 0..2u8 {
        let mut h = Sha256::new();
        h.update((label.len() as u64).to_be_bytes());
        h.update(label);
        for p in parts {
            h.update((p.len() as u64).to_be_bytes());
            h.update(p);
        }
        h.update([half]);
        wide[half as usize * 32..][..32].copy_from_slice(&h.finalize());
    }
    Fp::from_wide(&wide)
}

pub fn domain(label: &[u8]) -> Fp {
    hash_to_field(b"crowdvault/zk1/domain", &[label])
}

pub fn params() -> &'static Params {
    static P: OnceLock<Params> = OnceLock::new();
    P.get_or_init(|| {
        let rc = (0..ROUNDS)
            .map(|r| {
                std::array::from_fn(|i| {
                    hash_to_field(
                        b"crowdvault/zk1/poseidon/round-constant",
                        &[&(r as u64).to_be_bytes(), &(i as u64).to_be_bytes()],
                    )
                })
            })
            .collect();
        let mds = std::array::from_fn(|i| {
            std::array::from_fn(|j| (Fp::from_u64(i as u64) + Fp::from_u64((T + j) as u64)).inv())
        });
        Params { rc, mds }
    })
}

pub fn is_full_round(r: usize) -> bool {
    r < RF / 2 || r >= RF / 2 + RP
}

pub fn pow5(x: Fp) -> Fp {
    x.square().square() * x
}

pub fn permute(s: &mut [Fp; T]) {
    let p = params();
    for r in 0..ROUNDS {
        for i in 0..T {
            s[i] += p.rc[r][i];
        }
        if is_full_round(r) {
            for v in s.iter_mut() {
                *v = pow5(*v);
            }
        } else {
            s[0] = pow5(s[0]);
        }
        let mut n = [Fp::ZERO; T];
        for i in 0..T {
            for j in 0..T {
                n[i] += p.mds[i][j] * s[j];
            }
        }
        *s = n;
    }
}
