/*
 * ============================================================================
 * CRATE: MIRLETIS (Rust Core) v1.1
 * DESCRIPTION: The Dragon-Lattice Post-Quantum Cryptography Library
 * SPEC: N=256, K=5, SHAKE-256, MIT
 * NOTE: 100% Safe Rust, No-std compatible, Branchless
 * ============================================================================
 */

#![no_std]
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use sha3::{Shake256, Sha3_256, Digest, digest::{Update, ExtendableOutput, XofReader}};
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/* === [1. Constants] === */
pub const N: usize = 256;
pub const K: usize = 5;
pub const Q_MASK: i32 = 0x1FFF;
pub const SHIFT: u32 = 5;
pub const SEED_LEN: usize = 32;
pub const SHARED_LEN: usize = 32;

/* Domain Separation Tags */
const DOM_MATRIX: u8 = 0x00;
const DOM_SECRET: u8 = 0x01;
const DOM_HASH:   u8 = 0x02;

/* === [2. Data Structures] === */

/// Mirletis Public Key.
/// Contains the seed for matrix A and the vector b.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MirPubkey {
    pub seed: [u8; SEED_LEN],
    pub b: [u8; K * N],
}

impl Default for MirPubkey {
    fn default() -> Self {
        Self {
            seed: [0u8; SEED_LEN],
            b: [0u8; K * N],
        }
    }
}

/// Mirletis Ciphertext.
/// Contains the vector u, the safe-zone mask, and the count of valid bits.
#[derive(Clone, Copy)]
pub struct MirCiphertext {
    pub u: [u8; K * N],
    pub mask: [u8; N / 8],
    pub cnt: u16,
}

/// Shared Secret Key.
/// Result of the Key Encapsulation Mechanism.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MirSharedKey {
    pub key: [u8; SHARED_LEN],
}

/* === [3. Secret Vault] === */

/// Protected container for the Secret Key component `s`.
/// Prevents accidental exposure by enforcing closure-based access.
/// This pattern mitigates potential side-channel leakage by limiting scope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MirSecretVault {
    secret_s: Vec<i16>,
}

impl MirSecretVault {
    pub fn new(s: Vec<i16>) -> Self {
        MirSecretVault { secret_s: s }
    }

    /// Access the secret key securely via a closure.
    pub fn access<F, R>(&self, f: F) -> R
    where
    F: FnOnce(&[i16]) -> R,
    {
        f(&self.secret_s)
    }
}

/* === [4. Branchless Primitives] === */
/// Constant-time operations to prevent timing attacks.
mod ct {
    #[inline(always)]
    pub const fn sign32(x: i32) -> i32 {
        x >> 31
    }

    #[inline(always)]
    pub const fn abs32(x: i32) -> i32 {
        let m = sign32(x);
        (x ^ m).wrapping_sub(m)
    }

    #[inline(always)]
    pub const fn min32(a: i32, b: i32) -> i32 {
        let d = a.wrapping_sub(b);
        b.wrapping_add(d & sign32(d))
    }

    #[inline(always)]
    pub const fn lt32(a: i32, b: i32) -> u32 {
        (a.wrapping_sub(b) as u32) >> 31
    }

    #[inline(always)]
    pub const fn eq32(a: i32, b: i32) -> u32 {
        let diff = a ^ b;
        let z = (diff | diff.wrapping_neg()) as u32;
        1 ^ (z >> 31)
    }

    #[inline(always)]
    pub const fn sel_u8(a: u8, b: u8, cond: u32) -> u8 {
        let mask = 0u8.wrapping_sub(cond as u8);
        (a & mask) | (b & !mask)
    }

    #[inline(always)]
    pub const fn sel_i16(a: i16, b: i16, cond: u32) -> i16 {
        let mask = 0i16.wrapping_sub(cond as i16);
        (a & mask) | (b & !mask)
    }

    #[inline(always)]
    pub fn bit_set(arr: &mut [u8], i: usize, v: u32) {
        arr[i >> 3] |= (v as u8) << (i & 7);
    }

    #[inline(always)]
    pub const fn bit_get(arr: &[u8], i: usize) -> u32 {
        ((arr[i >> 3] >> (i & 7)) & 1) as u32
    }

    /// Constant-time ternary sampler: {0,1,2,3} -> {-1,0,1,0}
    #[inline(always)]
    pub const fn ternary(r: u8) -> i16 {
        let val = (r & 3) as i32;
        let base = val - 1;
        let is_three = eq32(val, 3);
        sel_i16(0, base as i16, is_three)
    }

    /// Safe-Zone Logic: Returns 1 if distance < 12, else 0.
    #[inline(always)]
    pub fn safe_zone(v: u8) -> u32 {
        let val = v as i32;
        let d1 = abs32(val - 32);
        let d2 = abs32(val - 96);
        let d3 = abs32(val - 160);
        let d4 = abs32(val - 224);
        let m = min32(min32(d1, d2), min32(d3, d4));
        lt32(m, 12)
    }

    /// Constant-time slice comparison.
    #[inline]
    pub fn eq_slice(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        let mut i = 0;
        while i < a.len() {
            diff |= a[i] ^ b[i];
            i += 1;
        }
        diff == 0
    }
}

/* === [5. SHAKE-256 / SHA3-256 Engine] === */

fn mir_shake_xof(out: &mut [u8], data: &[u8], domain: u8) {
    let mut hasher = Shake256::default();
    hasher.update(&[domain]);
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

fn mir_sha3_256(out: &mut [u8; 32], data: &[u8], domain: u8) {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, &[domain]);
    Digest::update(&mut hasher, data);
    out.copy_from_slice(&hasher.finalize());
}

/* === [6. Matrix & Secret Generation] === */

fn gen_matrix_a(seed: &[u8; SEED_LEN]) -> Vec<i16> {
    let len = K * K * N;
    let mut buf = vec![0u8; len * 2];
    let mut matrix = vec![0i16; len];

    mir_shake_xof(&mut buf, seed, DOM_MATRIX);

    let mut idx = 0;
    let mut i = 0;
    while i < len {
        let val = u16::from_le_bytes([buf[idx], buf[idx + 1]]);
        matrix[i] = (val as i32 & Q_MASK) as i16;
        idx += 2;
        i += 1;
    }

    buf.zeroize();
    matrix
}

fn gen_secret_from_seed(seed: &[u8], out_s: &mut [i16]) {
    let len = out_s.len();
    let mut buf = vec![0u8; len];

    mir_shake_xof(&mut buf, seed, DOM_SECRET);

    let mut i = 0;
    while i < len {
        out_s[i] = ct::ternary(buf[i]);
        i += 1;
    }

    buf.zeroize();
}

/* === [7. Key Generation] === */

/// Generates a new Mirletis key pair.
///
/// # Returns
/// A tuple containing (`MirPubkey`, `MirSecretVault`).
pub fn keygen() -> (MirPubkey, MirSecretVault) {
    let mut pk = MirPubkey::default();

    // 1. Generate two independent seeds from OS RNG
    let mut master_seed = [0u8; 64];
    OsRng.fill_bytes(&mut master_seed);

    // 2. Public Key Seed (Front 32 bytes)
    pk.seed.copy_from_slice(&master_seed[..32]);

    // 3. Secret Key Seed (Back 32 bytes) - Independent derivation
    let mut s_temp = vec![0i16; K * N];
    gen_secret_from_seed(&master_seed[32..], &mut s_temp);

    // 4. Zeroize master seed immediately
    master_seed.zeroize();

    // 5. Generate Matrix A from seed
    let matrix_a = gen_matrix_a(&pk.seed);

    // 6. Compute b = A * s (Component-wise / Parallel)
    // Note: Uses branchless wrapping arithmetic.
    let mut i = 0;
    while i < K {
        let mut j = 0;
        while j < N {
            let mut acc: i32 = 0;
            let mut l = 0;
            while l < K {
                let idx_a = (i * K * N) + (l * N) + j;
                let idx_s = (l * N) + j;
                let term = (matrix_a[idx_a] as i32).wrapping_mul(s_temp[idx_s] as i32);
                acc = acc.wrapping_add(term);
                l += 1;
            }
            pk.b[i * N + j] = ((acc & Q_MASK) >> SHIFT) as u8;
            j += 1;
        }
        i += 1;
    }

    // 7. Transfer secret to the secure Vault
    let vault = MirSecretVault::new(s_temp);

    (pk, vault)
}

/* === [8. Encapsulation] === */

/// Encapsulates a shared secret for the given public key.
///
/// # Arguments
/// * `pk` - The recipient's Public Key.
///
/// # Returns
/// A tuple containing (`MirCiphertext`, `MirSharedKey`).
pub fn encaps(pk: &MirPubkey) -> (MirCiphertext, MirSharedKey) {
    // Generate ephemeral entropy
    let mut eph_seed = [0u8; 32];
    OsRng.fill_bytes(&mut eph_seed);

    let mut r = vec![0i16; K * N];
    gen_secret_from_seed(&eph_seed, &mut r);
    eph_seed.zeroize();

    let matrix_a = gen_matrix_a(&pk.seed);

    let mut ct = MirCiphertext {
        u: [0u8; K * N],
        mask: [0u8; N / 8],
        cnt: 0,
    };

    // Compute u = A^T * r
    let mut i = 0;
    while i < K {
        let mut j = 0;
        while j < N {
            let mut acc: i32 = 0;
            let mut l = 0;
            while l < K {
                let idx_a = (l * K * N) + (i * N) + j;
                let idx_r = (l * N) + j;
                let term = (matrix_a[idx_a] as i32).wrapping_mul(r[idx_r] as i32);
                acc = acc.wrapping_add(term);
                l += 1;
            }
            ct.u[i * N + j] = ((acc & Q_MASK) >> SHIFT) as u8;
            j += 1;
        }
        i += 1;
    }

    // Compute v = b * r
    let mut v = [0u8; N];
    let mut j = 0;
    while j < N {
        let mut acc: i32 = 0;
        let mut l = 0;
        while l < K {
            let idx_b = (l * N) + j;
            let idx_r = (l * N) + j;
            let term = (pk.b[idx_b] as i32).wrapping_mul(r[idx_r] as i32);
            acc = acc.wrapping_add(term);
            l += 1;
        }
        v[j] = (acc & 0xFF) as u8;
        j += 1;
    }

    // Safe-Zone Selection and Mask Generation
    let mut buf = [0u8; N];
    let mut widx: usize = 0;

    let mut idx = 0;
    while idx < N {
        let val = v[idx];
        let safe = ct::safe_zone(val);

        ct::bit_set(&mut ct.mask, idx, safe);
        // Extract 1 bit from the safe zone
        let bit = (val >> 6) & 1;
        buf[widx] = ct::sel_u8(bit, buf[widx], safe);
        widx = widx.wrapping_add(safe as usize);

        idx += 1;
    }

    ct.cnt = widx as u16;

    // KDF: SHA3-256
    let mut shared = MirSharedKey { key: [0u8; SHARED_LEN] };
    mir_sha3_256(&mut shared.key, &buf[..widx], DOM_HASH);

    // Cleanup sensitive data
    r.zeroize();
    v.zeroize();
    buf.zeroize();

    (ct, shared)
}

/* === [9. Decapsulation] === */

/// Decapsulates a shared secret using the secret vault.
///
/// # Arguments
/// * `ct` - The received Ciphertext.
/// * `vault` - The recipient's Secret Vault.
pub fn decaps(ct: &MirCiphertext, vault: &MirSecretVault) -> MirSharedKey {
    // Access secret key securely
    let v_prime = vault.access(|s| {
        let mut vp = [0u8; N];

        let mut j = 0;
        while j < N {
            let mut acc: i32 = 0;
            let mut l = 0;
            while l < K {
                let idx_u = (l * N) + j;
                let idx_s = (l * N) + j;
                let term = (ct.u[idx_u] as i32).wrapping_mul(s[idx_s] as i32);
                acc = acc.wrapping_add(term);
                l += 1;
            }
            vp[j] = (acc & 0xFF) as u8;
            j += 1;
        }

        vp
    });

    // Mask filtering (Reconciliation)
    let mut buf = [0u8; N];
    let mut widx: usize = 0;

    let mut idx = 0;
    while idx < N {
        let val = v_prime[idx];
        let sel = ct::bit_get(&ct.mask, idx);
        let bit = (val >> 6) & 1;

        buf[widx] = ct::sel_u8(bit, buf[widx], sel);
        widx = widx.wrapping_add(sel as usize);

        idx += 1;
    }

    // KDF: SHA3-256 (Same Domain)
    let mut shared = MirSharedKey { key: [0u8; SHARED_LEN] };
    mir_sha3_256(&mut shared.key, &buf[..widx], DOM_HASH);

    shared
}

/* === [10. Self Test & Verification] === */

/// Performs a self-test of the Key Encapsulation Mechanism.
/// Returns `true` if Alice and Bob derive the same shared secret.
pub fn self_test() -> bool {
    let (pk, vault) = keygen();
    let (ct, key_bob) = encaps(&pk);
    let key_alice = decaps(&ct, &vault);

    ct::eq_slice(&key_alice.key, &key_bob.key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correctness() {
        assert!(self_test(), "Key exchange failed");
    }

    #[test]
    fn test_stress_repeat() {
        for _ in 0..100 {
            assert!(self_test());
        }
    }

    #[test]
    fn test_constant_time_ops() {
        assert_eq!(ct::ternary(0), -1);
        assert_eq!(ct::ternary(1), 0);
        assert_eq!(ct::ternary(2), 1);
        assert_eq!(ct::ternary(3), 0);
        assert_eq!(ct::safe_zone(32), 1);
        assert_eq!(ct::safe_zone(64), 0);
    }
}

