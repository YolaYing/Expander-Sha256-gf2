use expander_compiler::frontend::{Config, RootAPI, Variable};

pub type Sha256Word = [Variable; 32];

// parse the u32 into 32 bits, big-endian
pub fn u32_to_bit<C: Config, Builder: RootAPI<C>>(api: &mut Builder, value: u32) -> [Variable; 32] {
    (0..32)
        .map(|i| api.constant((value >> (31 - i)) & 1))
        .collect::<Vec<Variable>>()
        .try_into()
        .expect("Iterator should have exactly 32 elements")
}

pub fn u64_to_bit<C: Config, Builder: RootAPI<C>>(api: &mut Builder, value: u64) -> [Variable; 64] {
    (0..64)
        .map(|i| api.constant(((value >> (63 - i)) & 1) as u32))
        .collect::<Vec<Variable>>()
        .try_into()
        .expect("Iterator should have exactly 64 elements")
}

pub fn rotate_right(bits: &Sha256Word, k: usize) -> Sha256Word {
    assert!(bits.len() & (bits.len() - 1) == 0);
    let n = bits.len();
    let s = n - k;
    let mut new_bits = bits[s..].to_vec();
    new_bits.append(&mut bits[0..s].to_vec());
    new_bits.try_into().unwrap()
}

pub fn shift_right<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    bits: &Sha256Word,
    k: usize,
) -> Sha256Word {
    assert!(bits.len() & (bits.len() - 1) == 0);
    let n = bits.len();
    let s = n - k;
    let mut new_bits = vec![api.constant(0); k];
    new_bits.append(&mut bits[0..s].to_vec());
    new_bits.try_into().unwrap()
}

// Ch function: (x AND y) XOR (NOT x AND z)
pub fn ch<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    x: &Sha256Word,
    y: &Sha256Word,
    z: &Sha256Word,
) -> Sha256Word {
    let xy = and(api, x, y);
    let not_x = not(api, x);
    let not_xz = and(api, &not_x, z);

    xor(api, &xy, &not_xz)
}

// Maj function: (x AND y) XOR (x AND z) XOR (y AND z)
pub fn maj<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    x: &Sha256Word,
    y: &Sha256Word,
    z: &Sha256Word,
) -> Sha256Word {
    let xy = and(api, x, y);
    let xz = and(api, x, z);
    let yz = and(api, y, z);
    let tmp = xor(api, &xy, &xz);

    xor(api, &tmp, &yz)
}

// sigma0 function: ROTR(x, 7) XOR ROTR(x, 18) XOR SHR(x, 3)
pub fn lower_case_sigma0<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    word: &Sha256Word,
) -> Sha256Word {
    let rot7 = rotate_right(word, 7);
    let rot18 = rotate_right(word, 18);
    let shft3 = shift_right(api, word, 3);
    let tmp = xor(api, &rot7, &rot18);

    xor(api, &tmp, &shft3)
}

// σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
// sigma1 function: ROTR(x, 17) XOR ROTR(x, 19) XOR SHR(x, 10)
// Input:
//      - word: 32-bit
// Output: 32 bits
// Gate count:
//      - pure boolean gates: 32 bits per word × 2 XOR word gates = 64 XOR gates
//      - word boolean gates(B = 32): 2 XOR word gates
pub fn lower_case_sigma1<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    word: &Sha256Word,
) -> Sha256Word {
    let rot17 = rotate_right(word, 17);
    let rot19 = rotate_right(word, 19);
    let shft10 = shift_right(api, word, 10);
    let tmp = xor(api, &rot17, &rot19);

    xor(api, &tmp, &shft10)
}

// Sigma0 function: ROTR(x, 2) XOR ROTR(x, 13) XOR ROTR(x, 22)
// compare to lower_case_sigma0, shift and rotate same in pure boolean circuit,
// but will be different in word boolean circuit when B < 32
pub fn capital_sigma0<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    x: &Sha256Word,
) -> Sha256Word {
    let rot2 = rotate_right(x, 2);
    let rot13 = rotate_right(x, 13);
    let rot22 = rotate_right(x, 22);
    let tmp = xor(api, &rot2, &rot13);

    xor(api, &tmp, &rot22)
}

// Sigma1 function: ROTR(x, 6) XOR ROTR(x, 11) XOR ROTR(x, 25)
pub fn capital_sigma1<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    x: &Sha256Word,
) -> Sha256Word {
    let rot6 = rotate_right(x, 6);
    let rot11 = rotate_right(x, 11);
    let rot25 = rotate_right(x, 25);
    let tmp = xor(api, &rot6, &rot11);

    xor(api, &tmp, &rot25)
}

// It computes: a + b with carry, one bit at a time, using Boolean gates.
// Brent-Kung GF(2) addition
pub fn add_const<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word, // 32 bits
    b: u32,         // constant u32
) -> Sha256Word {
    let n = a.len();
    let mut c = *a;
    // We track a carry bit ci, initialized as 0.
    let mut ci = api.constant(0);
    // The loop goes from the least significant bit (bit 31) down to the most significant (bit 0)
    // loop has 32 rounds, for each round:
    // 1. If b[i] = 1, we use 3 XOR gates and 1 AND gate to compute the sum bit and carry out.
    // 2. If b[i] = 0, we use 1 XOR gate and 1 AND gate to compute the sum bit and carry out.
    for i in (0..n).rev() {
        if (b >> (31 - i)) & 1 == 1 {
            // Case 1: Bit b[i] = 1
            // sum_bit = a[i] ⊕ 1 ⊕ carry
            // carry_out = (¬a[i] ∧ carry) ⊕ a[i]

            // p = a[i] ⊕ 1 = ¬a[i]
            let p = api.add(a[i], 1);
            // c[i] = sum_bit = a[i] ⊕ 1 ⊕ carry
            c[i] = api.add(p, ci);
            // ¬a[i] ∧ carry
            ci = api.mul(ci, p);
            // ci = carry_out = (¬a[i] ∧ carry) ⊕ a[i]
            ci = api.add(ci, a[i]);
        } else {
            // Case 2: Bit b[i] = 0
            // sum_bit = a[i] ⊕ carry
            // carry_out = a[i] ∧ carry
            c[i] = api.add(c[i], ci);
            ci = api.mul(ci, a[i]);
        }
    }
    c
}

// The brentkung addition algorithm, recommended
// This code implements 32-bit addition with carry using the Brent-Kung parallel prefix adder structure — fully adapted to Boolean circuits over GF(2).
// key idea of this function is to divide the 32-bit addition into 8 groups of 4 bits each and call the 4-bit Brent-Kung adder for each group.
// The carry-out from one group flows into the next group
// Gate count:
//     - pure boolean gates:
//          8 groups × 15 XOR gates per Brent-Kung adder = 120 XOR gates
//          8 groups × 15 AND gates per Brent-Kung adder = 120 AND gates
pub fn add_brentkung<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    // temporary solution to change endianness, big -> little
    // Endian Fix (big-endian → little-endian)
    // Brent-Kung logic is naturally little-endian (carry flows from low bits to high bits).
    // SHA-256 bit order is big-endian, so this is just temporary reversal.
    let mut a = *a;
    let mut b = *b;
    a.reverse();
    b.reverse();

    let mut c = vec![api.constant(0); 32];
    let mut ci = api.constant(0);

    for i in 0..8 {
        // Break into 4-bit blocks
        let start = i * 4;
        let end = start + 4;

        // Divide 32 bits into 8 groups of 4 bits and use a 4-bit Brent-Kung adder for each group
        // Carry-out from one group flows into the next (serially)
        let (sum, ci_next) = brent_kung_adder_4_bits(api, &a[start..end], &b[start..end], ci);
        ci = ci_next;

        c[start..end].copy_from_slice(&sum);
    }

    // temporary solution to change endianness, little -> big
    // After addition is done, the word is reversed back to big-endian.
    c.reverse();
    c.try_into().unwrap()
}

// Objective: 4-bit Brent-Kung adder
// Adds a + b + carry_in for 4-bit inputs
// Input: 4 bits of input A, 4 bits of input B, carry-in to bit 0
// Output: a 4-bit sum and a final carry-out

// Key idea: compute all carries for each bit position and then compute the sum
// Generate (g[i] = a[i] ∧ b[i]): whether current bit position can generate a carry
// Propagate (p[i] = a[i] ⊕ b[i]): whether current bit position can allow an incoming carry passing to the next position
// Gate count:
//     - pure boolean gates:
//          4 XOR gates(generate and propagate) + 3 XOR gates(prefix computation) + 4 XOR gates(final carry evaluation) + 4 XOR gates(sum) = 15 XOR gates
//          4 AND gates(generate and propagate) + 5 AND gates(prefix computation) + 6 AND gates(final carry evaluation) = 15 AND gates

fn brent_kung_adder_4_bits<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &[Variable],     // 4 bits of input A
    b: &[Variable],     // 4 bits of input B
    carry_in: Variable, // carry-in to bit 0
) -> ([Variable; 4], Variable) {
    let mut g = [api.constant(0); 4];
    let mut p = [api.constant(0); 4];

    // Step 1: Generate and propagate
    // gate count:
    //     - pure boolean gates:
    //          4 bits × 1 XOR gates = 4 XOR gates
    //          4 bits × 1 AND gates = 4 AND gates
    for i in 0..4 {
        g[i] = api.mul(a[i], b[i]);
        p[i] = api.add(a[i], b[i]);
    }

    // Step 2: Prefix computation
    // Gate count:
    //     - pure boolean gates:
    //          1 bits × 3 XOR gates = 3 XOR gates
    //          1 bits × 5 AND gates = 5 AND gates
    // compute prefix generate expressions
    // do not consider the original carry_in, only consider generated carries

    // Each g[i:0] represents whether any bit in [0, i] can generate a carry that reaches bit i+1
    // g[1:0] = g[1] + p[1] ⋅ g[0]
    // g[2:0] = g[2] + p[2] ⋅ g[1:0]
    // ...
    // (generated carry either from current bit or from previous bits)
    // ？？should be tree structure:
    //   Inputs:   g0     g1     g2     g3
    //    Layer 1:    g[1:0]          g[3:2]
    //                  \               /
    //    Layer 2:        ← g[3:0] →
    //
    //   Step 1: Pairwise (parallel)
    //      g10 = g1 + p1 ⋅ g0
    //      g32 = g3 + p3 ⋅ g2

    //   Step 2: Merge tree
    //      g30 = g32 + (p2 ⋅ p3) ⋅ g10

    let p1g0 = api.mul(p[1], g[0]);
    let p0p1 = api.mul(p[0], p[1]);
    let p2p3 = api.mul(p[2], p[3]);

    let g10 = api.add(g[1], p1g0);
    let g20 = api.mul(p[2], g10);
    let g20 = api.add(g[2], g20);
    let g30 = api.mul(p[3], g20);
    let g30 = api.add(g[3], g30);

    // Step 3: Calculate carries
    // Gate count:
    //     - pure boolean gates:
    //          1 bits × 4 XOR gates = 4 XOR gates
    //          1 bits × 6 AND gates = 6 AND gates

    // Final Carry Evaluation
    // considering the original carry_in, we determine the actual carry-in at each bit using:
    // carry[i] = g[0..i-1] + (p[0] ⋅ p[1] ⋯ p[i-1] ⋅ carry_in)
    // This checks:
    //      Whether the prefix segment itself generated a carry (g[0..i-1])
    //      or whether the prefix segment allowed the original carry to pass through (p[0] ⋅ p[1] ⋯ p[i-1])
    let mut c = [api.constant(0); 5];
    c[0] = carry_in;
    let tmp = api.mul(p[0], c[0]);
    c[1] = api.add(g[0], tmp);
    let tmp = api.mul(p0p1, c[0]);
    c[2] = api.add(g10, tmp);
    let tmp = api.mul(p[2], c[0]);
    let tmp = api.mul(p0p1, tmp);
    c[3] = api.add(g20, tmp);
    let tmp = api.mul(p0p1, p2p3);
    let tmp = api.mul(tmp, c[0]);
    c[4] = api.add(g30, tmp);

    // Step 4: Calculate sum
    // Gate count:
    //     - pure boolean gates:
    //          4 bits × 1 XOR gates = 4 XOR gates
    // sum[i] = p[i] ⊕ carry[i]
    let mut sum = [api.constant(0); 4];
    for i in 0..4 {
        sum[i] = api.add(p[i], c[i]);
    }

    (sum, c[4])
}

pub fn add_koggestone_32_bits<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    // Kogge–Stone adder: fully parallel prefix tree
    let mut a = *a;
    let mut b = *b;
    a.reverse();
    b.reverse();

    let mut g = [api.constant(0); 32]; // generate: g[i] = a[i] & b[i]
    let mut p = [api.constant(0); 32]; // propagate: p[i] = a[i] ^ b[i]

    for i in 0..32 {
        g[i] = api.mul(a[i], b[i]);
        p[i] = api.add(a[i], b[i]);
    }
    // let mut p = xor(api, &a, &b);
    // let mut g = and(api, &a, &b);

    let mut g_prefix = g;
    let mut p_prefix = p;

    let mut gap = 1;
    while gap < 32 {
        let mut g_next = g_prefix;
        let mut p_next = p_prefix;
        for i in 0..32 {
            if i >= gap {
                let g_prev = g_prefix[i - gap];
                let p_cur = p_prefix[i];
                let p_prev = p_prefix[i - gap];

                let and = api.mul(p_cur, g_prev);
                g_next[i] = api.add(g_prefix[i], and);
                p_next[i] = api.mul(p_cur, p_prev);
            }
        }
        g_prefix = g_next;
        p_prefix = p_next;
        gap *= 2;
    }

    // Carry computation (carry[0] = 0)
    let mut carry = [api.constant(0); 33];
    carry[0] = api.constant(0);
    for i in 0..32 {
        // carry[i+1] = g_prefix[i] + p_prefix[i] * carry[0]
        // in Kogge–Stone, carry[i+1] = G[0..i] + P[0..i] * carry_in
        let and = api.mul(p_prefix[i], carry[0]);
        carry[i + 1] = api.add(g_prefix[i], and);
    }

    // Sum bits
    let mut sum = [api.constant(0); 32];
    for i in 0..32 {
        sum[i] = api.add(p[i], carry[i]);
    }
    // let mut sum = xor(api, &p, &carry[..32].try_into().unwrap());

    sum.reverse(); // convert back to big-endian
    sum
}

// parallel version
pub fn shift_left<C: Config, Builder: RootAPI<C>>(
    input: &Sha256Word,
    shift: usize,
    api: &mut Builder,
) -> Sha256Word {
    let mut output = [api.constant(0); 32];
    for i in 0..32 {
        output[i] = if i >= shift {
            input[i - shift]
        } else {
            api.constant(0)
        };
    }
    output
}

pub fn prefix_step<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    g: &Sha256Word,
    p: &Sha256Word,
    shift: usize,
) -> (Sha256Word, Sha256Word) {
    // new g: new_G = G ^ (P & (G << shift))
    let g_shift = shift_left(g, shift, api);
    let p_and_gshift = and(api, p, &g_shift);
    let g_next = xor(api, g, &p_and_gshift);

    // new_P = P & (P << shift)
    let p_shift = shift_left(p, shift, api);
    let p_next = and(api, p, &p_shift);

    (g_next, p_next)
}

pub fn add_koggestone_32_bits_prallel<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut a = *a;
    let mut b = *b;
    a.reverse();
    b.reverse();

    let mut p = xor(api, &a, &b);
    let mut g = and(api, &a, &b);

    let mut g_prefix = g.clone();
    let mut p_prefix = p.clone();
    for &shift in [1, 2, 4, 8, 16].iter() {
        let (g_next, p_next) = prefix_step(api, &g_prefix, &p_prefix, shift);
        g_prefix = g_next;
        p_prefix = p_next;
    }

    let carry = shift_left(&g_prefix, 1, api);

    let mut sum = xor(api, &p, &carry);
    sum.reverse();
    sum
}

pub fn add_hancarlson_32_bits<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    // Han–Carlson adder operates on little-endian bit order
    let mut a = *a;
    let mut b = *b;
    a.reverse();
    b.reverse();

    let mut g = [api.constant(0); 32]; // generate
    let mut p = [api.constant(0); 32]; // propagate

    // Step 1: compute generate and propagate
    for i in 0..32 {
        g[i] = api.mul(a[i], b[i]); // g[i] = a[i] & b[i]
        p[i] = api.add(a[i], b[i]); // p[i] = a[i] ^ b[i]
    }

    let mut g_prefix = g.clone();
    let mut p_prefix = p.clone();

    // Step 2: build prefix tree for even indices
    let mut gap = 1;
    while gap < 32 {
        let mut g_next = g_prefix.clone();
        let mut p_next = p_prefix.clone();

        for i in 0..32 {
            if i >= gap && i % 2 == 0 {
                let and = api.mul(p_prefix[i], g_prefix[i - gap]);
                g_next[i] = api.add(g_prefix[i], and);
                p_next[i] = api.mul(p_prefix[i], p_prefix[i - gap]);
            }
        }

        g_prefix = g_next;
        p_prefix = p_next;
        gap *= 2;
    }

    // Step 3: compute carry chain
    let mut carry = [api.constant(0); 33];
    carry[0] = api.constant(0);

    for i in 1..=32 {
        if (i - 1) % 2 == 0 {
            carry[i] = g_prefix[i - 1];
        } else {
            let and = api.mul(p[i - 1], carry[i - 1]);
            carry[i] = api.add(g[i - 1], and);
        }
    }

    // Step 4: final summation
    let mut sum = [api.constant(0); 32];
    for i in 0..32 {
        sum[i] = api.add(p[i], carry[i]);
    }

    sum.reverse(); // convert back to big-endian
    sum
}

// pub fn han_carlson_adder_4_bits<C: Config, Builder: RootAPI<C>>(
//     api: &mut Builder,
//     a: &[Variable],
//     b: &[Variable],
//     carry_in: Variable,
// ) -> ([Variable; 4], Variable) {
//     let mut g = [api.constant(0); 4];
//     let mut p = [api.constant(0); 4];

//     for i in 0..4 {
//         g[i] = api.mul(a[i], b[i]);
//         p[i] = api.add(a[i], b[i]);
//     }

//     // Prefix tree emulation for even bits (bit 0 and 2)
//     let g_prefix_0 = g[0];
//     let p2_and_g1 = api.mul(p[2], g[1]);
//     let g_prefix_2 = api.add(g[2], p2_and_g1);

//     let mut carry = [api.constant(0); 5];
//     carry[0] = carry_in;

//     // Carry computation using correct HC logic:
//     // Even indices use prefix tree result
//     // Odd indices use local computation from prior carry
//     carry[1] = g_prefix_0;

//     let p1_and_c1 = api.mul(p[1], carry[1]);
//     carry[2] = api.add(g[1], p1_and_c1);
//     carry[3] = g_prefix_2;
//     let p3_and_c3 = api.mul(p[3], carry[3]);
//     carry[4] = api.add(g[3], p3_and_c3);

//     let mut sum = [api.constant(0); 4];
//     for i in 0..4 {
//         sum[i] = api.add(p[i], carry[i]);
//     }

//     (sum, carry[4])
// }

pub fn han_carlson_adder_4_bits<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &[Variable], // length = 4
    b: &[Variable], // length = 4
    carry_in: Variable,
) -> ([Variable; 4], Variable) {
    let mut g = [api.constant(0); 4];
    let mut p = [api.constant(0); 4];

    // Step 1: Generate and Propagate

    for i in 0..4 {
        g[i] = api.mul(a[i], b[i]); // g[i] = a[i] & b[i]
        p[i] = api.add(a[i], b[i]); // p[i] = a[i] ^ b[i]
    }

    // Step 2: Prefix tree only on even indices
    let mut g_prefix = g;
    let mut p_prefix = p;

    // round 1: gap = 1, i = 2
    // g_prefix[2] = g[2] + p[2]*g[1]
    let p2_and_g1 = api.mul(p[2], g[1]);
    g_prefix[2] = api.add(g[2], p2_and_g1);
    // p_prefix[2] = p[2]*p[1]
    p_prefix[2] = api.mul(p[2], p[1]);

    // round 2: gap = 2, i = 2
    // g_prefix[2] = g_prefix[2] + p_prefix[2]*g[0]
    // p_prefix[2] = p_prefix[2]*p[0]
    let p2_and_g0 = api.mul(p_prefix[2], g[0]);
    g_prefix[2] = api.add(g_prefix[2], p2_and_g0);
    p_prefix[2] = api.mul(p_prefix[2], p[0]);

    // Step 3: Carry computation
    let mut carry = [api.constant(0); 5];
    carry[0] = carry_in;

    // for i in 1..=4 {
    //     if (i - 1) % 2 == 0 {
    //         carry[i] = g_prefix[i - 1]; // even: use prefix
    //     } else {
    //         let t = api.mul(p[i - 1], carry[i - 1]);
    //         carry[i] = api.add(g[i - 1], t); // odd: local
    //     }
    // }
    carry[1] = g_prefix[0]; // g[0]
    let p1_and_c1 = api.mul(p[1], carry[1]);
    carry[2] = api.add(g[1], p1_and_c1); // g[1] + p[1]*carry[1]
    carry[3] = g_prefix[2]; // g[2]
    let p3_and_c3 = api.mul(p[3], carry[3]);
    carry[4] = api.add(g[3], p3_and_c3); // g[3] + p[3]*carry[3]

    // Step 4: Final sum
    let mut sum = [api.constant(0); 4];
    for i in 0..4 {
        sum[i] = api.add(p[i], carry[i]);
    }

    (sum, carry[4]) // return final carry-out
}

pub fn add_hancarlson<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &[Variable],
    b: &[Variable],
) -> [Variable; 32] {
    // Han–Carlson adder operates on little-endian bit order
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.reverse();
    b.reverse();

    let mut c = vec![api.constant(0); 32];
    let mut ci = api.constant(0);

    for i in 0..8 {
        let start = i * 4;
        let end = start + 4;
        let (sum, ci_next) = han_carlson_adder_4_bits(api, &a[start..end], &b[start..end], ci);
        ci = ci_next;
        c[start..end].copy_from_slice(&sum);
    }

    c.reverse();
    c.try_into().unwrap()
}

pub fn add<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    // add_brentkung(api, a, b)
    // add_hancarlson(api, a, b)
    // add_koggestone_32_bits(api, a, b)
    add_koggestone_32_bits_prallel(api, a, b)
}

// Goal: Return sums of a list of u32 using GF(2) full addition with carry
// Input: A list of n 32-bit words (vs)
// Binary Tree Summation
// Instead of adding the values linearly: ((v₀ + v₁) + v₂) + v₃ ...
// which has linear depth, we reduce the depth by using: sum = ((v₀ + v₁), (v₂ + v₃), ...) → pairwise reduce
pub fn sum_all<C: Config, Builder: RootAPI<C>>(api: &mut Builder, vs: &[Sha256Word]) -> Sha256Word {
    let mut n_values_to_sum = vs.len();
    let mut vvs = vs.to_vec();

    // Sum all values in a binary tree fashion to produce fewer layers in the circuit
    // Each round does:
    //      Add pairs: v[i] = v[i] + v[i + half]
    //      If odd number of inputs, carry the last one up unchanged
    //      Halve the number of active values
    // Repeat until only one result remains.
    // This is a binary tree reduction, sometimes called pairwise folding.

    while n_values_to_sum > 1 {
        let half_size_floor = n_values_to_sum / 2;

        for i in 0..half_size_floor {
            vvs[i] = add(api, &vvs[i], &vvs[i + half_size_floor])
        }

        if n_values_to_sum & 1 != 0 {
            vvs[half_size_floor] = vvs[n_values_to_sum - 1];
        }

        n_values_to_sum = (n_values_to_sum + 1) / 2;
    }

    vvs[0]
}

// 1-bit full adder
// Input: a, b, carry_in
// Output:
//      sum: a⊕b⊕c
//      carry_out: ab+bc+ac
// Gate count:
//     - pure boolean gates:
//          1 bits × 4 XOR gates = 4 XOR gates
//          1 bits × 3 AND gates = 3 AND gates
fn bit_add_with_carry<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: Variable,
    b: Variable,
    carry: Variable,
) -> (Variable, Variable) {
    // compute sum
    // (a ⊕ b) ⊕ carry = a ⊕ b ⊕ c
    let sum = api.add(a, b);
    let sum = api.add(sum, carry);

    // a * (b + (b + 1) * carry) + (a + 1) * b * carry
    // = a * b + a * b * carry + a * b * carry + a * carry + b * carry
    // explain: a⋅(b+(b+1)⋅c) → if b == 1: then result = 1, if b == 0: then result = c → b OR c
    // carry=a⋅(b+¬b⋅c)+¬a⋅b⋅c = ab+a⋅¬b⋅c+¬a⋅b⋅c

    // ?? a * b * carry + a * b * carry = 0??
    // Optimized version:
    // let ab = api.mul(a, b);
    // let ac = api.mul(a, carry);
    // let bc = api.mul(b, carry);

    // // abc not needed

    // let carry_next = api.add(ab, ac);
    // let carry_next = api.add(carry_next, bc);

    let ab = api.mul(a, b);
    let ac = api.mul(a, carry);
    let bc = api.mul(b, carry);
    let abc = api.mul(ab, carry);

    let carry_next = api.add(ab, abc);
    let carry_next = api.add(carry_next, abc);
    let carry_next = api.add(carry_next, ac);
    let carry_next = api.add(carry_next, bc);

    (sum, carry_next)
}

// The vanilla addition algorithm, not recommended
pub fn add_vanilla<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut c = vec![api.constant(0); 32];

    let mut carry = api.constant(0);
    // run bit_add_with_carry 32 times (once per bit)
    for i in (0..32).rev() {
        (c[i], carry) = bit_add_with_carry(api, a[i], b[i], carry);
    }
    c.try_into().unwrap()
}

pub fn xor<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut bits_res = [api.constant(0); 32];
    for i in 0..32 {
        bits_res[i] = api.add(a[i], b[i]);
    }
    bits_res
}

pub fn and<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut bits_res = [api.constant(0); 32];
    for i in 0..32 {
        bits_res[i] = api.mul(a[i], b[i]);
    }
    bits_res
}

pub fn not<C: Config, Builder: RootAPI<C>>(api: &mut Builder, a: &Sha256Word) -> Sha256Word {
    let mut bits_res = [api.constant(0); 32];
    for i in 0..32 {
        bits_res[i] = api.sub(1, a[i]);
    }
    bits_res
}
