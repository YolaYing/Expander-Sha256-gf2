use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;

pub type Sha256Word = [Variable; 32];

pub fn xor<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut res = [api.constant(0); 32];
    for i in 0..32 {
        res[i] = api.add(a[i], b[i]);
    }
    res
}

pub fn and<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut res = [api.constant(0); 32];
    for i in 0..32 {
        res[i] = api.mul(a[i], b[i]);
    }
    res
}

pub fn not<C: Config, Builder: RootAPI<C>>(api: &mut Builder, a: &Sha256Word) -> Sha256Word {
    let mut res = [api.constant(0); 32];
    for i in 0..32 {
        res[i] = api.sub(1, a[i]);
    }
    res
}

pub fn ch<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    x: &Sha256Word,
    y: &Sha256Word,
    z: &Sha256Word,
) -> Sha256Word {
    let xy = and(api, x, y);
    let not_x = not(api, x);
    let not_xz = and(api, &not_x, z);
    xor(api, &xy, &not_xz)
}

// === Declare circuit ===
declare_circuit!(ChTestCircuit {
    x: [Variable; 32],
    y: [Variable; 32],
    z: [Variable; 32],
    out: [PublicVariable; 32],
});

impl Define<GF2Config> for ChTestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let result = ch(api, &self.x, &self.y, &self.z);
        for i in 0..32 {
            api.assert_is_equal(result[i], self.out[i]);
        }
    }
}

#[test]
fn test_ch_function_correctness() {
    let compile_result = compile(&ChTestCircuit::default(), CompileOptions::default()).unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let x: u32 = rng.gen();
        let y: u32 = rng.gen();
        let z: u32 = rng.gen();
        let ch = (x & y) ^ ((!x) & z);

        let mut assignment = ChTestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.x[i] = ((x >> (31 - i)) & 1).into();
            assignment.y[i] = ((y >> (31 - i)) & 1).into();
            assignment.z[i] = ((z >> (31 - i)) & 1).into();
            assignment.out[i] = ((ch >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ ChTestCircuit test passed.");
}
