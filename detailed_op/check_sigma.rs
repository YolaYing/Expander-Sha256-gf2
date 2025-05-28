use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;

pub type Sha256Word = [Variable; 32];

// pub fn rotate_right(bits: &Sha256Word, k: usize) -> Sha256Word {
//     let n = bits.len();
//     let s = n - k;
//     let mut new_bits = bits[s..].to_vec();
//     new_bits.append(&mut bits[0..s].to_vec());
//     new_bits.try_into().unwrap()
// }
// 尝试：不重新分配，只用引用或 clone
pub fn rotate_right(bits: &Sha256Word, k: usize) -> Sha256Word {
    let n = bits.len();
    let s = n - k;
    let mut new_bits = [bits[0]; 32]; // init
    for i in 0..n {
        new_bits[i] = bits[(i + s) % n]; // pure index mapping
    }
    new_bits
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

// === 定义电路 ===
declare_circuit!(Sigma0TestCircuit {
    x: [Variable; 32],
    sigma0_out: [PublicVariable; 32],
});

impl Define<GF2Config> for Sigma0TestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let result = capital_sigma0(api, &self.x);
        for i in 0..32 {
            api.assert_is_equal(result[i], self.sigma0_out[i]);
        }
    }
}

#[test]
fn test_sigma0_single_layer() {
    let compile_result = compile(&Sigma0TestCircuit::default(), CompileOptions::default()).unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let x: u32 = rng.gen();
        let rot2 = x.rotate_right(2);
        let rot13 = x.rotate_right(13);
        let rot22 = x.rotate_right(22);
        let sigma = rot2 ^ rot13 ^ rot22;

        let mut assignment = Sigma0TestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.x[i] = ((x >> (31 - i)) & 1).into();
            assignment.sigma0_out[i] = ((sigma >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }
    println!("✅ Sigma0TestCircuit test passed.");
}
