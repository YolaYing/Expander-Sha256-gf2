use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;
use std::sync::OnceLock;
static CONSTS: OnceLock<[u32; 64]> = OnceLock::new();

pub type Sha256Word = [Variable; 32];

// === Kogge–Stone GF(2) Adder 实现 ===

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

// === 电路定义 ===
declare_circuit!(AddConstCircuit {
    a: [Variable; 32],
    out: [PublicVariable; 32],
});

// === 布尔域下的 a + const_b 加法 ===
pub fn add_const<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: u32,
) -> Sha256Word {
    let n = a.len();
    let mut c = *a;
    let mut ci = api.constant(0);

    for i in (0..n).rev() {
        if (b >> (31 - i)) & 1 == 1 {
            let p = api.add(a[i], 1);
            c[i] = api.add(p, ci);
            ci = api.mul(ci, p);
            ci = api.add(ci, a[i]);
        } else {
            c[i] = api.add(c[i], ci);
            ci = api.mul(ci, a[i]);
        }
    }

    c
}

// === 电路逻辑 ===
impl Define<GF2Config> for AddConstCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let b_const: u32 = 0x12345678;

        let mut const_bits = [api.constant(0); 32];
        for j in 0..32 {
            const_bits[j] = api.constant((b_const >> (31 - j)) & 1);
        }

        let sum = add_koggestone_32_bits_prallel(api, &self.a, &const_bits);

        for i in 0..32 {
            api.assert_is_equal(sum[i], self.out[i]);
        }
    }
}

// === 测试函数 ===
#[test]
fn test_add_const_gf2() {
    let compile_result = compile(&AddConstCircuit::default(), CompileOptions::default()).unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    let b_const: u32 = 0x12345678;
    let n_tests = 5;

    for _ in 0..n_tests {
        let a_val: u32 = rng.gen();
        let expected = a_val.wrapping_add(b_const);

        let mut assignment = AddConstCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a_val >> (31 - i)) & 1).into();
            assignment.out[i] = ((expected >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ All add_const GF2 adder tests passed.");
}

// === 每轮输入一个 word，与提前固定的 const 相加后累加 ===
declare_circuit!(SumInputPlusConst64Circuit {
    inputs: [[Variable; 32]; 64], // 每轮一个输入 word
    output: [PublicVariable; 32], // 输出最终累加结果
});

impl Define<GF2Config> for SumInputPlusConst64Circuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let mut acc = [api.constant(0); 32];

        for i in 0..64 {
            let round_input = self.inputs[i];
            let round_const = Self::round_consts()[i];
            // let sum = add_const(api, &round_input, round_const); // input + const[i]
            // 将 u32 常数转换为 Sha256Word 形式
            let mut const_bits = [api.constant(0); 32];
            for j in 0..32 {
                const_bits[j] = api.constant((round_const >> (31 - j)) & 1);
            }
            let sum = add_koggestone_32_bits_prallel(api, &round_input, &const_bits); // input + const[i]

            acc = add_koggestone_32_bits_prallel(api, &acc, &sum); // acc += sum
        }

        for i in 0..32 {
            api.assert_is_equal(acc[i], self.output[i]);
        }
    }
}

impl SumInputPlusConst64Circuit<Variable> {
    pub fn round_consts() -> &'static [u32; 64] {
        &CONSTS.get().expect("round_consts not initialized")
    }
}

#[test]
fn test_sum_input_plus_const_64() {
    // 固定常量数组（非随机）
    let consts: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    CONSTS.set(consts).unwrap();

    // 生成随机输入 + 手动模拟结果
    let mut rng = rand::thread_rng();
    let mut inputs = [0u32; 64];
    let mut acc = 0u32;

    for i in 0..64 {
        inputs[i] = rng.gen();
        let sum = inputs[i].wrapping_add(consts[i]);
        acc = acc.wrapping_add(sum);
    }

    let compile_result = compile(
        &SumInputPlusConst64Circuit::default(),
        CompileOptions::default(),
    )
    .unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut assignment = SumInputPlusConst64Circuit::<GF2>::default();
    for i in 0..64 {
        let word = inputs[i];
        for b in 0..32 {
            assignment.inputs[i][b] = ((word >> (31 - b)) & 1).into();
        }
    }
    for b in 0..32 {
        assignment.output[b] = ((acc >> (31 - b)) & 1).into();
    }

    let witness = witness_solver.solve_witness(&assignment).unwrap();
    let result = layered_circuit.run(&witness);
    assert_eq!(result, vec![true]);

    println!("✅ 每轮 input + const 再累加的测试通过！");
}
