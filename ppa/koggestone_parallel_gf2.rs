use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// === 电路定义 ===
declare_circuit!(KoggeStoneParallelCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    out: [PublicVariable; 32],
});

// === 基础操作 ===
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

// === Kogge–Stone Parallel Adder ===
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

// === 电路实现 ===
impl Define<GF2Config> for KoggeStoneParallelCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let sum = add_koggestone_32_bits_prallel(api, &self.a, &self.b);
        for i in 0..32 {
            api.assert_is_equal(sum[i], self.out[i]);
        }
    }
}

// === 测试函数 ===
#[test]
fn test_koggestone_parallel_gf2() {
    let compile_result = compile(
        &KoggeStoneParallelCircuit::default(),
        CompileOptions::default(),
    )
    .unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    let n_tests = 5;
    for _ in 0..n_tests {
        let a_val: u32 = rng.gen();
        let b_val: u32 = rng.gen();
        let expected = a_val.wrapping_add(b_val);

        let mut assignment = KoggeStoneParallelCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a_val >> (31 - i)) & 1).into();
            assignment.b[i] = ((b_val >> (31 - i)) & 1).into();
            assignment.out[i] = ((expected >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ All Kogge–Stone Parallel GF2 adder tests passed.");
}
