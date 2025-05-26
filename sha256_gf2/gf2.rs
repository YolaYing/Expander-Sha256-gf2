use expander_compiler::frontend::{GF2Config, RootAPI, Variable};

use super::gf2_utils::{
    add, add_const, add_csa3, capital_sigma0, capital_sigma1, ch, lower_case_sigma0,
    lower_case_sigma1, maj, sum_all, u32_to_bit, u64_to_bit, Sha256Word,
};

#[derive(Clone, Debug, Default)]
pub struct SHA256GF2 {
    data: Vec<Variable>,
}

// Initial values of H0..H7, used to initialize a..h per block
//  a..h: temporary working variables for compression
//  H0..H7: global hash state, accumulated across all message blocks
//  for each message block, H0..H7 are initialized to a..h, and after the compression, a..h are added to H0..H7
// Each element is a 32-bit constant derived from the fractional parts of the square roots of the first 8 prime numbers (2..19).
const SHA256_INIT_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// This array contains 64 round constants, one for each compression round.
// These values are derived from the fractional parts of the cube roots of the first 64 primes (2..311).
// During each round of the compression loop, a new constant K[i] is added to the round mix.
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl SHA256GF2 {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    // data can have arbitrary length, do not have to be aligned to 512 bits
    pub fn update(&mut self, data: &[Variable]) {
        self.data.extend(data);
    }

    // main interface to finish hashing the input data and return the digest.
    // finalize the hash, return the hash value
    pub fn finalize(&mut self, api: &mut impl RootAPI<GF2Config>) -> Vec<Variable> {
        let data_len = self.data.len();

        // ----------------------------- Prepossing -----------------------------
        // ------------------ Padding -----------------
        // original_bits || 1 || 0* || [len]_64bit

        // padding according to the sha256 padding rule: https://helix.stormhub.org/papers/SHA-256.pdf
        // append a bit '1' first
        self.data.push(api.constant(1));
        // append '0' bits to make the length of data congruent to 448 mod 512
        let zero_padding_len = 448 - ((data_len + 1) % 512);
        self.data
            .extend((0..zero_padding_len).map(|_| api.constant(0)));
        // append the length of the data in 64 bits
        self.data.extend(u64_to_bit(api, data_len as u64));

        // ---------- Initialize Hash State -----------
        // state: [ [bit;32]; 8 ] → H0..H7
        let mut state = SHA256_INIT_STATE
            .iter()
            .map(|x| u32_to_bit(api, *x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        // ---------------- Chunking ------------------
        // ------------------- Processing Message in 512-bit Chunks --------------------
        self.data.chunks_exact(512).for_each(|chunk| {
            self.sha256_compress(api, &mut state, chunk.try_into().unwrap());
        });

        // ---------------------------- Return Final Digest ----------------------------
        // H[0] || H[1] || ... || H[7]
        // Each H[i] is 32 bits
        // Total: 8 × 32 = 256 bits
        state.iter().flatten().cloned().collect()
    }

    // The compress function, usually not used directly
    pub fn sha256_compress(
        &self,
        api: &mut impl RootAPI<GF2Config>,
        state: &mut [Sha256Word; 8],
        input: &[Variable; 512],
    ) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        // self.display_state(api, state);

        // ----------------------------- Message Schedule -----------------------------
        let mut w = [[api.constant(0); 32]; 64];
        // Step 1: Load W[0..15] from input, each W[i] is 32 bits
        for i in 0..16 {
            w[i] = input[(i * 32)..((i + 1) * 32)].try_into().unwrap();
        }
        // Step 2: Expand W[16..63]
        // This loop computes W[i] = σ₁(W[i-2]) + W[i-7] + σ₀(W[i-15]) + W[i-16]
        // There are 48 rounds of iteration, so we need to compute W[16..63]
        for i in 16..64 {
            // σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
            // lower_sigma1 = σ₁(W[i-2])
            // Gate Count:
            //     - pure boolean gate: 48 rounds × 32 bits per word × 2 XOR word gates = 3,072 XOR gates
            //     - 32-bit word boolean gate: 48 rounds × 2 XOR 32-bit word gates = 96 XOR 32-bit word gates
            //     - 8-bit word boolean gate: TBD
            let lower_sigma1 = lower_case_sigma1(api, &w[i - 2]);
            // s0 = σ₁(W[i-2]) + W[i-7]
            let s0 = add(api, &lower_sigma1, &w[i - 7]);

            // σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
            // lower_sigma0 = σ₀(W[i-15])
            let lower_sigma0 = lower_case_sigma0(api, &w[i - 15]);
            // s1 = σ₀(W[i-15]) + W[i-16]
            let s1 = add(api, &lower_sigma0, &w[i - 16]);

            // w[i] = s0+s1 = σ₁(W[i-2]) + W[i-7] + σ₀(W[i-15]) + W[i-16]
            // Gate Count:
            //    - pure boolean gate: 48 rounds × 32 bits per word × 3 XOR word gates = 4,608 XOR gates
            //    - 32-bit word boolean gate: 48 rounds × 3 XOR 32-bit word gates = 144 XOR 32-bit word gates
            w[i] = add(api, &s0, &s1);
        }

        // ----------------------------- Compression Loop -----------------------------
        //========================= original code =========================
        // for i in 0..64 {
        //     // T₁ = h + Σ₁(e) + Ch(e, f, g) + K[i] + W[i]
        //     // K[i] + W[i]
        //     // Brent-Kung GF(2) addition: The Brent-Kung adder is a type of parallel prefix adder.
        //     //                            It is optimized to compute binary addition with carry using a logarithmic-depth tree of prefix operations
        //     let w_plus_k = add_const(api, &w[i], SHA256_K[i]);

        //     // Σ₁(e) = ROTR⁶(e) ⊕ ROTR¹¹(e) ⊕ ROTR²⁵(e)
        //     // Gate Count:
        //     //     - pure boolean gate: 64 rounds × 32 bits per word × 2 XOR word gates = 4,096 XOR gates
        //     //     - 32-bit word boolean gate: 64 rounds × 2 XOR 32-bit word gates = 128 XOR 32-bit word gates
        //     let capital_sigma_1_e = capital_sigma1(api, &e);
        //     // Ch(e,f,g) = (e ∧ f) ⊕ ((¬e) ∧ g)
        //     let ch_e_f_g = ch(api, &e, &f, &g);
        //     let t_1 = sum_all(api, &[h, capital_sigma_1_e, ch_e_f_g, w_plus_k]);

        //     // T₂ = Σ₀(a) + Maj(a, b, c)
        //     // Σ₀(a) = ROTR²(a) ⊕ ROTR¹³(a) ⊕ ROTR²²(a)
        //     let capital_sigma_0_a = capital_sigma0(api, &a);
        //     // Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)
        //     let maj_a_b_c = maj(api, &a, &b, &c);
        //     let t_2 = add(api, &capital_sigma_0_a, &maj_a_b_c);

        //     // (a, b, ..., h) ← state rotation + update:
        //     h = g;
        //     g = f;
        //     f = e;
        //     e = add(api, &d, &t_1);
        //     d = c;
        //     c = b;
        //     b = a;
        //     a = add(api, &t_1, &t_2);
        // }
        // ========================= end of original code =========================

        // ========================== optimized code =========================
        for i in 0..64 {
            // === 构建输入 ===
            let w_plus_k = add_const(api, &w[i], SHA256_K[i]); // b
            let capital_sigma_1_e = capital_sigma1(api, &e); // c
            let ch_e_f_g = ch(api, &e, &f, &g); // d
            let capital_sigma_0_a = capital_sigma0(api, &a); // e
            let maj_a_b_c = maj(api, &a, &b, &c); // f

            // === 第一阶段 Wallace Tree 加法链 ===
            // sum1 = a + b + c = h + w_plus_k + capital_sigma_1_e
            let (sum1, carry1) = add_csa3(api, &h, &w_plus_k, &capital_sigma_1_e);
            // sum2 = d + e + f = ch + sigma0(a) + maj
            let (sum2, carry2) = add_csa3(api, &ch_e_f_g, &capital_sigma_0_a, &maj_a_b_c);

            // sum3 = sum1 + carry1 + sum2
            let (sum3, carry3) = add_csa3(api, &sum1, &carry1, &sum2);
            // sum4 = sum3 + carry3 + carry2
            let (sum4, carry4) = add_csa3(api, &sum3, &carry3, &carry2);
            let t_2 = add(api, &sum4, &carry4); // output2 = updated_a

            // === 第二阶段 Wallace Tree 加法链 ===
            // sum5a = g + d + sum1 = input_g + input_d + sum1
            let (sum5a, carry5) = add_csa3(api, &d, &ch_e_f_g, &sum1);
            // sum5b = carry1 + sum5a + carry5
            let (sum5b, carry6) = add_csa3(api, &carry1, &sum5a, &carry5);
            let t_1 = add(api, &sum5b, &carry6); // output1 = updated_e

            // === 更新状态变量 ===
            h = g;
            g = f;
            f = e;
            e = t_1; // e = add(d, t₁)
            d = c;
            c = b;
            b = a;
            a = t_2; // a = add(t₁, t₂)
        }
        // ========================= end of optimized code =========================

        state[0] = add(api, &state[0], &a);
        state[1] = add(api, &state[1], &b);
        state[2] = add(api, &state[2], &c);
        state[3] = add(api, &state[3], &d);
        state[4] = add(api, &state[4], &e);
        state[5] = add(api, &state[5], &f);
        state[6] = add(api, &state[6], &g);
        state[7] = add(api, &state[7], &h);
    }

    #[allow(dead_code)]
    fn display_state(&self, api: &mut impl RootAPI<GF2Config>, state: &[Sha256Word; 8]) {
        for (i, s) in state.iter().enumerate() {
            api.display(&format!("{}", i), s[30]);
        }
    }
}
