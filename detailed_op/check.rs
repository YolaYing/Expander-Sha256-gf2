// === 引入必要模块 ===
use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// === XOR Vec 实现 ===
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

// === 最小 XOR 电路：无 assert，只计算 xor 结果 ===
declare_circuit!(MinimalXorCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
});

impl Define<GF2Config> for MinimalXorCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let a_vec = self.a.to_vec();
        let b_vec = self.b.to_vec();
        let _xor_res = xor_vec(api, a_vec, b_vec);
        // 不加 assert_is_equal
    }
}

// === 测试 MinimalXorCircuit 并输出层数 ===
#[test]
fn test_minimal_xor_circuit() {
    let compile_result = compile(&MinimalXorCircuit::default(), CompileOptions::default()).unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    println!("Minimal XOR 层数: {}", layered_circuit.num_layers());

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let a_val: u32 = rng.gen();
        let b_val: u32 = rng.gen();

        let mut assignment = MinimalXorCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a_val >> (31 - i)) & 1).into();
            assignment.b[i] = ((b_val >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }
    println!("✅ MinimalXorCircuit passed.");
}
