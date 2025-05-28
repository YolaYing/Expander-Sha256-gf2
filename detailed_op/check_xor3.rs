use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// ==== 3 number XOR ====
declare_circuit!(Xor3TestCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    xor_out: [PublicVariable; 32],
});

impl Define<GF2Config> for Xor3TestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        for i in 0..32 {
            let tmp = api.add(self.a[i], self.b[i]);
            let t = api.add(tmp, self.c[i]);
            api.assert_is_equal(t, self.xor_out[i]);
        }
    }
}

#[test]
fn test_xor3_single_layer() {
    let compile_result = compile(&Xor3TestCircuit::default(), CompileOptions::default()).unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let a: u32 = rng.gen();
        let b: u32 = rng.gen();
        let c: u32 = rng.gen();
        let xor = a ^ b ^ c;

        let mut assignment = Xor3TestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.xor_out[i] = ((xor >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }
    println!("✅ Xor3TestCircuit test passed.");
}

// ==== XOR 4 number ====
declare_circuit!(Xor4TestCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    d: [Variable; 32],
    xor_out: [PublicVariable; 32],
});
impl Define<GF2Config> for Xor4TestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        for i in 0..32 {
            let tmp1 = api.add(self.a[i], self.b[i]);
            let tmp2 = api.add(self.c[i], self.d[i]);
            let t = api.add(tmp1, tmp2);
            api.assert_is_equal(t, self.xor_out[i]);
        }
    }
}
#[test]
fn test_xor4_single_layer() {
    let compile_result = compile(&Xor4TestCircuit::default(), CompileOptions::default()).unwrap();
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
        let xor = a ^ b ^ c ^ d;

        let mut assignment = Xor4TestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.d[i] = ((d >> (31 - i)) & 1).into();
            assignment.xor_out[i] = ((xor >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }
    println!("✅ Xor4TestCircuit test passed.");
}
// ==== XOR 5 number ====
declare_circuit!(Xor5TestCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    d: [Variable; 32],
    e: [Variable; 32],
    xor_out: [PublicVariable; 32],
});
impl Define<GF2Config> for Xor5TestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        for i in 0..32 {
            let tmp1 = api.add(self.a[i], self.b[i]);
            let tmp2 = api.add(self.c[i], self.d[i]);
            let tmp3 = api.add(tmp1, tmp2);
            let t = api.add(tmp3, self.e[i]);
            api.assert_is_equal(t, self.xor_out[i]);
        }
    }
}
#[test]
fn test_xor5_single_layer() {
    let compile_result = compile(&Xor5TestCircuit::default(), CompileOptions::default()).unwrap();
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
        let xor = a ^ b ^ c ^ d ^ e;

        let mut assignment = Xor5TestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.d[i] = ((d >> (31 - i)) & 1).into();
            assignment.e[i] = ((e >> (31 - i)) & 1).into();
            assignment.xor_out[i] = ((xor >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }
    println!("✅ Xor5TestCircuit test passed.");
}
