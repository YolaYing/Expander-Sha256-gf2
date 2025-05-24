use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// === 电路定义 ===
declare_circuit!(HanCarlsonCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    out: [PublicVariable; 32],
});

// === Han–Carlson GF(2) Adder 实现 ===
pub fn add_hancarlson_32_bits<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
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

    // Step 2: prefix tree for even indices
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

    // Step 3: carry propagation
    let mut carry = [api.constant(0); 33];
    carry[0] = api.constant(0);
    for i in 1..=32 {
        if (i - 1) % 2 == 0 {
            carry[i] = g_prefix[i - 1]; // even bits from tree
        } else {
            let and = api.mul(p[i - 1], carry[i - 1]);
            carry[i] = api.add(g[i - 1], and); // odd bits from chain
        }
    }

    // Step 4: final sum = p ^ carry
    let mut sum = [api.constant(0); 32];
    for i in 0..32 {
        sum[i] = api.add(p[i], carry[i]);
    }

    sum.reverse();
    sum
}

// === 电路实现 ===
impl Define<GF2Config> for HanCarlsonCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let sum = add_hancarlson_32_bits(api, &self.a, &self.b);
        for i in 0..32 {
            api.assert_is_equal(sum[i], self.out[i]);
        }
    }
}

// === 测试函数 ===
#[test]
fn test_hancarlson_gf2() {
    let compile_result = compile(&HanCarlsonCircuit::default(), CompileOptions::default()).unwrap();
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

        let mut assignment = HanCarlsonCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a_val >> (31 - i)) & 1).into();
            assignment.b[i] = ((b_val >> (31 - i)) & 1).into();
            assignment.out[i] = ((expected >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ All Han–Carlson GF2 adder tests passed.");
}
