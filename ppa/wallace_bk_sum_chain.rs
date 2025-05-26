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
    carry[0] = api.constant(0);

    for i in 0..32 {
        let a_add_b = api.add(a[i], b[i]);
        sum[i] = api.add(a_add_b, c[i]); // sum[i] = a[i] + b[i] + c[i]

        let ab = api.mul(a[i], b[i]);
        let bc = api.mul(b[i], c[i]);
        let ac = api.mul(a[i], c[i]);
        let ab_add_bc = api.add(ab, bc);
        carry[i + 1] = api.add(ab_add_bc, ac); // carry[i + 1] = a[i] * b[i] + b[i] * c[i] + a[i] * c[i]
    }

    let mut out_carry = [api.constant(0); 32];
    for i in 0..32 {
        out_carry[i] = carry[i]; // 对齐到下一位：carry[i] 作为第 i 位的 carry-in
    }

    sum.reverse();
    out_carry.reverse();

    (sum.try_into().unwrap(), out_carry.try_into().unwrap())
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
        let sum6 = add_brentkung(api, &sum4, &carry4); // out2

        // 第二条加法链
        let (sum5a, carry5) = add_csa3(api, &self.g, &self.d, &sum1);
        let (sum5b, carry6) = add_csa3(api, &carry1, &sum5a, &carry5);
        let sum5 = add_brentkung(api, &sum5b, &carry6); // out1

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
