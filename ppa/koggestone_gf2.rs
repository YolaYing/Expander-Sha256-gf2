use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// === 电路定义 ===
declare_circuit!(KoggeStoneCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    out: [PublicVariable; 32],
});

// === Kogge–Stone GF(2) Adder ===
pub fn add_koggestone_32_bits<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut a = *a;
    let mut b = *b;
    a.reverse();
    b.reverse();

    let mut g = [api.constant(0); 32];
    let mut p = [api.constant(0); 32];

    for i in 0..32 {
        g[i] = api.mul(a[i], b[i]);
        p[i] = api.add(a[i], b[i]);
    }

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

    let mut carry = [api.constant(0); 33];
    carry[0] = api.constant(0);
    for i in 0..32 {
        let and = api.mul(p_prefix[i], carry[0]);
        carry[i + 1] = api.add(g_prefix[i], and);
    }

    let mut sum = [api.constant(0); 32];
    for i in 0..32 {
        sum[i] = api.add(p[i], carry[i]);
    }

    sum.reverse();
    sum
}

// === 电路定义逻辑 ===
impl Define<GF2Config> for KoggeStoneCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let sum = add_koggestone_32_bits(api, &self.a, &self.b);
        for i in 0..32 {
            api.assert_is_equal(sum[i], self.out[i]);
        }
    }
}

// === 测试函数 ===
#[test]
fn test_koggestone_gf2() {
    let compile_result = compile(&KoggeStoneCircuit::default(), CompileOptions::default()).unwrap();
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

        let mut assignment = KoggeStoneCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a_val >> (31 - i)) & 1).into();
            assignment.b[i] = ((b_val >> (31 - i)) & 1).into();
            assignment.out[i] = ((expected >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ All Kogge–Stone GF2 adder tests passed.");
}
