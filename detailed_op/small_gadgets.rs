// 结论：xor and和not的写法用循环还是vector并不会影响电路层数和gates数
// 结果：
// 06:10:34 INF built hint normalized ir numInputs=64 numConstraints=32 numInsns=64 numVars=64 numTerms=96
// Layer 0: 64 adds, 0 muls, 32 consts
// Layer 1: 64 adds, 0 muls, 0 consts
// Layer 2: 32 adds, 0 muls, 0 consts
// Layer 3: 32 adds, 0 muls, 0 consts
// 06:10:34 INF built layered circuit numSegment=5 numLayer=4 numUsedInputs=64 numUsedVariables=160 numVariables=160 numAdd=192 numCst=32 numMul=0 totalCost=80672

// | 层数      | 作用             | 内容                             |
// | ------- | -------------- | ------------------------------ |
// | Layer 0 | 加载变量和常量        | 创建输入变量和 `const 1` 等常量          |
// | Layer 1 | 复制变量防止 fan-out | 为后续计算生成变量副本（copy gates）        |
// | Layer 2 | 执行 `xor` 运算    | 计算每位 `a[i] + b[i]`             |
// | Layer 3 | 断言输出正确性        | 约束 `xor[i] == out[i]`（用 `sub`） |

// === 引入必要模块 ===
use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// === 实现1：Vec版本 ===
pub fn xor_vec<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: Vec<Variable>,
    b: Vec<Variable>,
) -> Vec<Variable> {
    a.iter()
        .zip(b.iter())
        .map(|(ai, bi)| api.add(*ai, *bi))
        .collect()
}

pub fn and_vec<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: Vec<Variable>,
    b: Vec<Variable>,
) -> Vec<Variable> {
    a.iter()
        .zip(b.iter())
        .map(|(ai, bi)| api.mul(*ai, *bi))
        .collect()
}

pub fn not_vec<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: Vec<Variable>,
) -> Vec<Variable> {
    a.iter().map(|ai| api.sub(1, *ai)).collect()
}

// === 实现2：Array版本 ===
pub fn xor_array<C: Config, Builder: RootAPI<C>>(
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

pub fn and_array<C: Config, Builder: RootAPI<C>>(
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

pub fn not_array<C: Config, Builder: RootAPI<C>>(api: &mut Builder, a: &Sha256Word) -> Sha256Word {
    let mut bits_res = [api.constant(0); 32];
    for i in 0..32 {
        bits_res[i] = api.sub(1, a[i]);
    }
    bits_res
}

// === Circuit 1: Vec 实现 ===
declare_circuit!(VecLogicCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    out_xor: [PublicVariable; 32],
    // out_and: [PublicVariable; 32],
    // out_not: [PublicVariable; 32],
});

impl Define<GF2Config> for VecLogicCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let a_vec: Vec<Variable> = self.a.to_vec();
        let b_vec: Vec<Variable> = self.b.to_vec();

        let xor_res = xor_vec(api, a_vec.clone(), b_vec.clone());
        // let and_res = and_vec(api, a_vec.clone(), b_vec.clone());
        // let not_res = not_vec(api, a_vec);

        for i in 0..32 {
            api.assert_is_equal(xor_res[i], self.out_xor[i]);
            // api.assert_is_equal(and_res[i], self.out_and[i]);
            // api.assert_is_equal(not_res[i], self.out_not[i]);
        }
    }
}

// === Circuit 2: Array 实现 ===
declare_circuit!(ArrayLogicCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    out_xor: [PublicVariable; 32],
    out_and: [PublicVariable; 32],
    out_not: [PublicVariable; 32],
});

impl Define<GF2Config> for ArrayLogicCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let xor_res = xor_array(api, &self.a, &self.b);
        let and_res = and_array(api, &self.a, &self.b);
        let not_res = not_array(api, &self.a);

        for i in 0..32 {
            api.assert_is_equal(xor_res[i], self.out_xor[i]);
            api.assert_is_equal(and_res[i], self.out_and[i]);
            api.assert_is_equal(not_res[i], self.out_not[i]);
        }
    }
}

// === 测试 Vec 实现 ===
#[test]
fn test_vec_logic_circuit() {
    let compile_result = compile(&VecLogicCircuit::default(), CompileOptions::default()).unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let a_val: u32 = rng.gen();
        let b_val: u32 = rng.gen();

        let mut assignment = VecLogicCircuit::<GF2>::default();
        for i in 0..32 {
            let bit_a = ((a_val >> (31 - i)) & 1).into();
            let bit_b = ((b_val >> (31 - i)) & 1).into();
            assignment.a[i] = bit_a;
            assignment.b[i] = bit_b;

            let ai = (a_val >> (31 - i)) & 1;
            let bi = (b_val >> (31 - i)) & 1;
            assignment.out_xor[i] = (ai ^ bi).into();
            // assignment.out_and[i] = (ai & bi).into();
            // assignment.out_not[i] = (1 - ai).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }
    println!("✅ VecLogicCircuit passed.");
}

// // === 测试 Array 实现 ===
// #[test]
// fn test_array_logic_circuit() {
//     let compile_result = compile(&ArrayLogicCircuit::default(), CompileOptions::default()).unwrap();
//     let CompileResult {
//         witness_solver,
//         layered_circuit,
//     } = compile_result;

//     let mut rng = rand::thread_rng();
//     for _ in 0..5 {
//         let a_val: u32 = rng.gen();
//         let b_val: u32 = rng.gen();

//         let mut assignment = ArrayLogicCircuit::<GF2>::default();
//         for i in 0..32 {
//             let bit_a = ((a_val >> (31 - i)) & 1).into();
//             let bit_b = ((b_val >> (31 - i)) & 1).into();
//             assignment.a[i] = bit_a;
//             assignment.b[i] = bit_b;

//             let ai = (a_val >> (31 - i)) & 1;
//             let bi = (b_val >> (31 - i)) & 1;
//             assignment.out_xor[i] = (ai ^ bi).into();
//             assignment.out_and[i] = (ai & bi).into();
//             assignment.out_not[i] = (1 - ai).into();
//         }

//         let witness = witness_solver.solve_witness(&assignment).unwrap();
//         let result = layered_circuit.run(&witness);
//         assert_eq!(result, vec![true]);
//     }
//     println!("✅ ArrayLogicCircuit passed.");
// }
