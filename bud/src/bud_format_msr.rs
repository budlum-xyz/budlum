//! B.U.D. 2.0 - MSR regenerating code (4,2,3): real encoding plus exact repair.
//!
//! Remaining item #11: MSR regenerating codes, and not just the bandwidth
//! arithmetic - the code itself. The product-matrix construction, in the
//! Rashmi-Shah-Kumar pattern: C = Psi * M, with M being 3x2,
//! M = [[s1,s2],[s3,s4],[s2,s3]] over 4 free symbols, and Psi a fixed 4x3.
//!
//! The properties were verified by brute force over GF(2^8) mod 0x11D in the
//! sandbox on 2026-08-16, so none of this is asserted without measurement:
//!
//! - MDS: any 2 nodes yield all 4 symbols, a lossless decode.
//! - Exact repair: a dead node is restored bit for bit by downloading beta = 1
//!   packet from each of 3 healthy nodes, 3 packets in total. Plain erasure
//!   repair wants k * alpha = 4 packets, so this is 25 percent less.
//!
//! The repair coefficients are NOT baked into the code. Each repair is produced
//! generically, by solving lambda * D = target, and the test verifies every
//! attempt.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const MSR_MAGIC: [u8; 8] = *b"\xB5MSR1\0\0\0";

pub const N: usize = 4; // nodes
pub const K: usize = 2; // data nodes
pub const ALPHA: usize = 2; // packets per node
pub const BETA: usize = 1; // packets downloaded per helper during repair

// Psi (4x3): the constant verified for both MDS and repair.
const PSI: [[u8; 3]; N] = [[1, 0, 0], [0, 1, 0], [1, 1, 1], [1, 2, 3]];

// GF(2^8) mod 0x11D log and exp tables; deterministic, and no once_cell.
fn gf_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for i in 0..255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11D;
        }
    }
    for i in 255..512 {
        exp[i] = exp[i - 255];
    }
    (exp, log)
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = gf_tables();
    exp[(log[a as usize] as usize) + (log[b as usize] as usize)]
}

fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf_inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    let (exp, log) = gf_tables();
    Some(exp[255 - log[a as usize] as usize])
}

/// M (3x2): `[[s1,s2],[s3,s4],[s2,s3]]`, built from the 4 symbols.
fn build_m(s: &[u8; 4]) -> [[u8; 2]; 3] {
    [[s[0], s[1]], [s[2], s[3]], [s[1], s[2]]]
}

/// The 2 packets of node i, one row of C = Psi * M.
fn node_data(psi: &[u8; 3], m: &[[u8; 2]; 3]) -> [u8; 2] {
    let p0 = gf_add(
        gf_add(gf_mul(psi[0], m[0][0]), gf_mul(psi[1], m[1][0])),
        gf_mul(psi[2], m[2][0]),
    );
    let p1 = gf_add(
        gf_add(gf_mul(psi[0], m[0][1]), gf_mul(psi[1], m[1][1])),
        gf_mul(psi[2], m[2][1]),
    );
    [p0, p1]
}

/// Encode: 4 symbols into 4 nodes of 2 packets each.
pub fn msr_encode(s: &[u8; 4]) -> [[u8; 2]; N] {
    let m = build_m(s);
    let mut out = [[0u8; 2]; N];
    for i in 0..N {
        out[i] = node_data(&PSI[i], &m);
    }
    out
}

/// Solve a 4x4 system over GF(2^8) by Gauss-Jordan. A singular matrix yields
/// `None`.
fn solve4(a: &[[u8; 5]; 4]) -> Option<[u8; 4]> {
    let mut m = *a;
    for c in 0..4 {
        let piv = (c..4).find(|&r| m[r][c] != 0)?;
        m.swap(c, piv);
        let pinv = gf_inv(m[c][c])?;
        for col in 0..5 {
            m[c][col] = gf_mul(m[c][col], pinv);
        }
        for r in 0..4 {
            if r != c && m[r][c] != 0 {
                let f = m[r][c];
                for col in 0..5 {
                    m[r][col] = gf_add(m[r][col], gf_mul(f, m[c][col]));
                }
            }
        }
    }
    Some([m[0][4], m[1][4], m[2][4], m[3][4]])
}

/// Decode: recover all 4 symbols from the packets of any 2 nodes, the MDS
/// property.
pub fn msr_decode(nodes: &[(usize, [u8; 2])]) -> Option<[u8; 4]> {
    if nodes.len() != 2 {
        return None;
    }
    let (i, a) = nodes[0];
    let (j, b) = nodes[1];
    // packet0_i = r0*s1 + r2*s2 + r1*s3, packet1_i = r0*s2 + r2*s3 + r1*s4
    let r = |idx: usize| PSI[idx];
    let mut aug = [[0u8; 5]; 4];
    let (r0, r2, r1) = (r(i)[0], r(i)[2], r(i)[1]);
    aug[0] = [r0, r2, r1, 0, a[0]];
    aug[1] = [0, r0, r2, r1, a[1]];
    let (r0, r2, r1) = (r(j)[0], r(j)[2], r(j)[1]);
    aug[2] = [r0, r2, r1, 0, b[0]];
    aug[3] = [0, r0, r2, r1, b[1]];
    solve4(&aug)
}

/// Packet coefficients over s1..s4, used by the repair.
fn packet_coeffs(psi: &[u8; 3]) -> ([u8; 4], [u8; 4]) {
    let c0 = [psi[0], psi[2], psi[1], 0];
    let c1 = [0, psi[0], psi[2], psi[1]];
    (c0, c1)
}

/// Coefficients of the combination a helper sends: L = u*p0 + v*p1.
fn combo_coeffs(psi: &[u8; 3], u: u8, v: u8) -> [u8; 4] {
    let (c0, c1) = packet_coeffs(psi);
    [
        gf_add(gf_mul(u, c0[0]), gf_mul(v, c1[0])),
        gf_add(gf_mul(u, c0[1]), gf_mul(v, c1[1])),
        gf_add(gf_mul(u, c0[2]), gf_mul(v, c1[2])),
        gf_add(gf_mul(u, c0[3]), gf_mul(v, c1[3])),
    ]
}

/// Solve lambda * D = target, with 3 unknowns in lambda and D being 3x4.
///
/// Rather than fixing the columns, it tries each triple of the 4 columns, all
/// C(4,3) of them: on a singular submatrix it moves to the next triple, and
/// verifies with the remaining column. The rank-3 guarantee lives in D's four
/// columns, not in its first three.
fn solve_lambda(d: &[[u8; 4]; 3], target: &[u8; 4]) -> Option<[u8; 3]> {
    for cols in [[0usize, 1, 2], [0, 1, 3], [0, 2, 3], [1, 2, 3]] {
        let check_col = (0..4).find(|c| !cols.contains(c))?;
        // The 3x3 system:
        // lambda0*D[0][cols[c]] + lambda1*D[1][cols[c]] + lambda2*D[2][cols[c]]
        //   = target[cols[c]]
        let mut m = [[0u8; 4]; 3];
        for r in 0..3 {
            m[r] = [d[0][cols[r]], d[1][cols[r]], d[2][cols[r]], target[cols[r]]];
        }
        // Gauss-Jordan on 3x3.
        let mut ok = true;
        for c in 0..3 {
            let Some(piv) = (c..3).find(|&r| m[r][c] != 0) else {
                ok = false;
                break;
            };
            m.swap(c, piv);
            let Some(pinv) = gf_inv(m[c][c]) else {
                ok = false;
                break;
            };
            for col in 0..4 {
                m[c][col] = gf_mul(m[c][col], pinv);
            }
            for r in 0..3 {
                if r != c && m[r][c] != 0 {
                    let f = m[r][c];
                    for col in 0..4 {
                        m[r][col] = gf_add(m[r][col], gf_mul(f, m[c][col]));
                    }
                }
            }
        }
        if !ok {
            continue;
        }
        let lam = [m[0][3], m[1][3], m[2][3]];
        // Verify with the remaining column.
        let check = gf_add(
            gf_add(
                gf_mul(lam[0], d[0][check_col]),
                gf_mul(lam[1], d[1][check_col]),
            ),
            gf_mul(lam[2], d[2][check_col]),
        );
        if check == target[check_col] {
            return Some(lam);
        }
    }
    None
}

/// Exact repair: the dead node `f` is restored from the combinations of 3
/// helpers, each sending beta = 1 packet.
///
/// The combination coefficients `(u, v)` belong to the caller in the general
/// setting; here the verified constant set is used, found by brute force.
pub fn msr_repair(f: usize, all_nodes: &[[u8; 2]; N]) -> Option<[u8; 2]> {
    if f >= N {
        return None;
    }
    // The verified helper combinations, in node order.
    let combos: [[(u8, u8); 3]; N] = [
        [(1, 0), (1, 0), (1, 0)], // f=0: helpers 1,2,3
        [(1, 0), (1, 1), (1, 3)], // f=1: helpers 0,2,3
        [(1, 0), (0, 1), (2, 1)], // f=2: helpers 0,1,3
        [(1, 1), (1, 1), (1, 1)], // f=3: helpers 0,1,2
    ];
    let helpers: [usize; 3] = match f {
        0 => [1, 2, 3],
        1 => [0, 2, 3],
        2 => [0, 1, 3],
        3 => [0, 1, 2],
        _ => return None,
    };
    // Downloaded values: L_j = u*p0 + v*p1.
    let mut d = [[0u8; 4]; 3]; // coefficient matrix
    let mut dl = [0u8; 3]; // downloaded values
    for (k, &hj) in helpers.iter().enumerate() {
        let (u, v) = combos[f][k];
        let p = all_nodes[hj];
        dl[k] = gf_add(gf_mul(u, p[0]), gf_mul(v, p[1]));
        d[k] = combo_coeffs(&PSI[hj], u, v);
    }
    let (cx, cy) = packet_coeffs(&PSI[f]);
    let lx = solve_lambda(&d, &cx)?;
    let ly = solve_lambda(&d, &cy)?;
    let x = gf_add(
        gf_add(gf_mul(lx[0], dl[0]), gf_mul(lx[1], dl[1])),
        gf_mul(lx[2], dl[2]),
    );
    let y = gf_add(
        gf_add(gf_mul(ly[0], dl[0]), gf_mul(ly[1], dl[1])),
        gf_mul(ly[2], dl[2]),
    );
    Some([x, y])
}

/// Repair bandwidth: beta * d is 3 packets, against plain erasure's
/// k * alpha = 4.
pub fn repair_band_packets() -> (usize, usize) {
    (BETA * (N - 1), K * ALPHA)
}

pub fn msr_digest(nodes: &[[u8; 2]; N]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(MSR_MAGIC);
    for n in nodes {
        h.update(n);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn any_two_nodes_decode_all_four_symbols() {
        // Any 2 nodes yield all 4 symbols, across all 6 pairs.
        let mut rng = rand_core::OsRng;
        for _ in 0..20 {
            let s = [
                rng.next_u32() as u8,
                rng.next_u32() as u8,
                rng.next_u32() as u8,
                rng.next_u32() as u8,
            ];
            let nodes = msr_encode(&s);
            for i in 0..4 {
                for j in (i + 1)..4 {
                    let dec = msr_decode(&[(i, nodes[i]), (j, nodes[j])]).expect("decode");
                    assert_eq!(dec, s, "MDS decode from nodes {i},{j}");
                }
            }
        }
    }

    #[test]
    fn every_node_is_repaired_exactly() {
        // A dead node is restored bit for bit from 3 helpers at beta = 1, so 3
        // packets.
        let mut rng = rand_core::OsRng;
        for _ in 0..20 {
            let s = [
                rng.next_u32() as u8,
                rng.next_u32() as u8,
                rng.next_u32() as u8,
                rng.next_u32() as u8,
            ];
            let nodes = msr_encode(&s);
            for f in 0..4 {
                let repaired = msr_repair(f, &nodes).expect("repair");
                assert_eq!(repaired, nodes[f], "exact repair of node {f}");
            }
        }
    }

    #[test]
    fn repair_bandwidth_is_lower_than_a_full_decode() {
        let (repair, full) = repair_band_packets();
        assert_eq!(repair, 3);
        assert_eq!(full, 4);
        assert!(repair < full, "MSR repair bandwidth: {repair} < {full}");
    }

    #[test]
    fn encoding_is_deterministic() {
        let s = [10, 20, 30, 40];
        assert_eq!(msr_digest(&msr_encode(&s)), msr_digest(&msr_encode(&s)));
    }

    #[test]
    fn invalid_input_is_refused() {
        assert!(msr_repair(4, &[[0; 2]; 4]).is_none());
        assert!(msr_decode(&[]).is_none());
        assert!(msr_decode(&[(0, [1, 2]), (1, [3, 4]), (2, [5, 6])]).is_none());
    }
}
