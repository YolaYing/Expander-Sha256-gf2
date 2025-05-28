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

pub fn maj<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    x: &Sha256Word,
    y: &Sha256Word,
    z: &Sha256Word,
) -> Sha256Word {
    let xy = and(api, x, y);
    let xz = and(api, x, z);
    let yz = and(api, y, z);
    let tmp = xor(api, &xy, &xz);
    xor(api, &tmp, &yz)
}

// === Declare circuit ===
declare_circuit!(MajTestCircuit {
    x: [Variable; 32],
    y: [Variable; 32],
    z: [Variable; 32],
    out: [PublicVariable; 32],
});

impl Define<GF2Config> for MajTestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let result = maj(api, &self.x, &self.y, &self.z);
        for i in 0..32 {
            api.assert_is_equal(result[i], self.out[i]);
        }
    }
}

#[test]
fn test_maj_correctness() {
    let compile_result = compile(&MajTestCircuit::default(), CompileOptions::default()).unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let x: u32 = rng.gen();
        let y: u32 = rng.gen();
        let z: u32 = rng.gen();
        let maj = (x & y) ^ (x & z) ^ (y & z); // same as maj(x,y,z)

        let mut assignment = MajTestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.x[i] = ((x >> (31 - i)) & 1).into();
            assignment.y[i] = ((y >> (31 - i)) & 1).into();
            assignment.z[i] = ((z >> (31 - i)) & 1).into();
            assignment.out[i] = ((maj >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ MajTestCircuit test passed.");
}
