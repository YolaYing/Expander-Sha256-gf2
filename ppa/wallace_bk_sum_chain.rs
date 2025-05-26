use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// === Carry-Save Adder ===
pub fn add_csa3<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
    c: &Sha256Word,
) -> (Sha256Word, Sha256Word) {
    let mut a = *a;
    let mut b = *b;
    let mut c = *c;
    a.reverse();
    b.reverse();
    c.reverse();

    let mut sum = [api.constant(0); 32];
    let mut carry = [api.constant(0); 33]; // carry[0] 是初始进位

    let mut ab = [api.constant(0); 32];
    let mut bc = [api.constant(0); 32];
    let mut ac = [api.constant(0); 32];
    let mut tmp = [api.constant(0); 32];

    for i in 0..32 {
        let a_add_b = api.add(a[i], b[i]);
        sum[i] = api.add(a_add_b, c[i]); // sum[i] = a[i] + b[i] + c[i]

        ab[i] = api.mul(a[i], b[i]);
        bc[i] = api.mul(b[i], c[i]);
        ac[i] = api.mul(a[i], c[i]); // carry[i + 1] = a[i] * b[i] + b[i] * c[i] + a[i] * c[i]
        tmp[i] = api.add(ab[i], bc[i]);
        carry[i + 1] = api.add(tmp[i], ac[i]);
    }

    let mut out_carry = [api.constant(0); 32];
    for i in 0..32 {
        out_carry[i] = carry[i]; // carry[0] 是初始进位，所以从 carry[1] 开始
    }

    sum.reverse();
    out_carry.reverse();

    (sum.try_into().unwrap(), out_carry.try_into().unwrap())
}

// === adder selector ===
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

// === Kogge–Stone Parallel Adder ===
fn xor<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut out = [api.constant(0); 32];
    for i in 0..32 {
        out[i] = api.add(a[i], b[i]);
    }
    out
}

fn and<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut out = [api.constant(0); 32];
    for i in 0..32 {
        out[i] = api.mul(a[i], b[i]);
    }
    out
}

fn shift_left<C: Config, Builder: RootAPI<C>>(
    input: &Sha256Word,
    shift: usize,
    api: &mut Builder,
) -> Sha256Word {
    let mut out = [api.constant(0); 32];
    for i in 0..32 {
        out[i] = if i >= shift {
            input[i - shift]
        } else {
            api.constant(0)
        };
    }
    out
}

fn prefix_step<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    g: &Sha256Word,
    p: &Sha256Word,
    shift: usize,
) -> (Sha256Word, Sha256Word) {
    let g_shift = shift_left(g, shift, api);
    let p_and_gshift = and(api, p, &g_shift);
    let g_next = xor(api, g, &p_and_gshift);

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

// === Brent–Kung Adder ===
pub fn add_brentkung<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut a = *a;
    let mut b = *b;
    a.reverse();
    b.reverse();

    let mut c = vec![api.constant(0); 32];
    let mut ci = api.constant(0);

    for i in 0..8 {
        let start = i * 4;
        let end = start + 4;
        let (sum, ci_next) = brent_kung_adder_4_bits(api, &a[start..end], &b[start..end], ci);
        ci = ci_next;
        c[start..end].copy_from_slice(&sum);
    }

    c.reverse();
    c.try_into().unwrap()
}

fn brent_kung_adder_4_bits<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &[Variable],
    b: &[Variable],
    carry_in: Variable,
) -> ([Variable; 4], Variable) {
    let mut g = [api.constant(0); 4];
    let mut p = [api.constant(0); 4];

    for i in 0..4 {
        g[i] = api.mul(a[i], b[i]);
        p[i] = api.add(a[i], b[i]);
    }

    let p1g0 = api.mul(p[1], g[0]);
    let p0p1 = api.mul(p[0], p[1]);
    let p2p3 = api.mul(p[2], p[3]);

    let g10 = api.add(g[1], p1g0);
    let g20 = api.mul(p[2], g10);
    let g20 = api.add(g[2], g20);
    let g30 = api.mul(p[3], g20);
    let g30 = api.add(g[3], g30);

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

    let mut sum = [api.constant(0); 4];
    for i in 0..4 {
        sum[i] = api.add(p[i], c[i]);
    }

    (sum, c[4])
}

// === Final Sum Chain Circuit ===
declare_circuit!(WallaceBKSumChainCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    d: [Variable; 32],
    e: [Variable; 32],
    f: [Variable; 32],
    g: [Variable; 32],
    out1: [PublicVariable; 32], // sum5 = sum3 + g
    out2: [PublicVariable; 32], // sum6 = sum3 + sum4
});

impl Define<GF2Config> for WallaceBKSumChainCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        // 第一阶段加法链
        let (sum1, carry1) = add_csa3(api, &self.a, &self.b, &self.c);
        let (sum2, carry2) = add_csa3(api, &self.d, &self.e, &self.f);

        let (sum3, carry3) = add_csa3(api, &sum1, &carry1, &sum2);
        let (sum4, carry4) = add_csa3(api, &sum3, &carry3, &carry2);
        let sum6 = add(api, &sum4, &carry4); // out2

        // 第二条加法链
        let (sum5a, carry5) = add_csa3(api, &self.g, &self.d, &sum1);
        let (sum5b, carry6) = add_csa3(api, &carry1, &sum5a, &carry5);
        let sum5 = add(api, &sum5b, &carry6); // out1

        for i in 0..32 {
            api.assert_is_equal(sum5[i], self.out1[i]);
            api.assert_is_equal(sum6[i], self.out2[i]);
        }
    }
}

#[test]
fn test_wallace_bk_sum_chain() {
    let compile_result = compile(
        &WallaceBKSumChainCircuit::default(),
        CompileOptions::default(),
    )
    .unwrap();

    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let a: u32 = rng.gen();
        let b: u32 = rng.gen();
        let c: u32 = rng.gen();
        let d: u32 = rng.gen();
        let e: u32 = rng.gen();
        let f: u32 = rng.gen();
        let g: u32 = rng.gen();

        let sum1 = a.wrapping_add(b);
        let sum2 = c.wrapping_add(d);
        let sum3 = sum1.wrapping_add(sum2);
        let sum4 = e.wrapping_add(f);
        let sum5 = sum3.wrapping_add(g);
        let sum6 = sum3.wrapping_add(sum4);

        let mut assignment = WallaceBKSumChainCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.d[i] = ((d >> (31 - i)) & 1).into();
            assignment.e[i] = ((e >> (31 - i)) & 1).into();
            assignment.f[i] = ((f >> (31 - i)) & 1).into();
            assignment.g[i] = ((g >> (31 - i)) & 1).into();
            assignment.out1[i] = ((sum5 >> (31 - i)) & 1).into();
            assignment.out2[i] = ((sum6 >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ WallaceBKSumChain test passed with original sumchain logic.");
}

// === test add_csa3 ===
declare_circuit!(CSA3TestCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    sum_out: [PublicVariable; 32],
    carry_out: [PublicVariable; 32],
});

impl Define<GF2Config> for CSA3TestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let (sum, carry) = add_csa3(api, &self.a, &self.b, &self.c);

        for i in 0..32 {
            api.assert_is_equal(sum[i], self.sum_out[i]);
            api.assert_is_equal(carry[i], self.carry_out[i]);
        }
    }
}

// === 测试函数 ===
#[test]
fn test_csa3_single() {
    let compile_result = compile(&CSA3TestCircuit::default(), CompileOptions::default()).unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let a: u32 = rng.gen();
        let b: u32 = rng.gen();
        let c: u32 = rng.gen();

        let sum = a ^ b ^ c;
        let carry = ((a & b) ^ (a & c) ^ (b & c)) << 1;

        let mut assignment = CSA3TestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.sum_out[i] = ((sum >> (31 - i)) & 1).into();
            assignment.carry_out[i] = ((carry >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ CSA3 adder passed!");
}
