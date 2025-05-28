use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// ==== 3-number AND ====
declare_circuit!(And3TestCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    and_out: [PublicVariable; 32],
});

impl Define<GF2Config> for And3TestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        for i in 0..32 {
            let tmp = api.mul(self.a[i], self.b[i]);
            let t = api.mul(tmp, self.c[i]);
            api.assert_is_equal(t, self.and_out[i]);
        }
    }
}

#[test]
fn test_and3_layer() {
    let compile_result = compile(&And3TestCircuit::default(), CompileOptions::default()).unwrap();
    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let a: u32 = rng.gen();
        let b: u32 = rng.gen();
        let c: u32 = rng.gen();
        let and = a & b & c;

        let mut assignment = And3TestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.and_out[i] = ((and >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }
    println!("And3TestCircuit test passed.");
}

// ==== 4-number AND ====
declare_circuit!(And4TestCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    d: [Variable; 32],
    and_out: [PublicVariable; 32],
});

impl Define<GF2Config> for And4TestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        for i in 0..32 {
            let tmp1 = api.mul(self.a[i], self.b[i]);
            let tmp2 = api.mul(self.c[i], self.d[i]);
            let t = api.mul(tmp1, tmp2);
            api.assert_is_equal(t, self.and_out[i]);
        }
    }
}

#[test]
fn test_and4_layer() {
    let compile_result = compile(&And4TestCircuit::default(), CompileOptions::default()).unwrap();
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
        let and = a & b & c & d;

        let mut assignment = And4TestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.d[i] = ((d >> (31 - i)) & 1).into();
            assignment.and_out[i] = ((and >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }
    println!("And4TestCircuit test passed.");
}

// ==== 5-number AND ====
declare_circuit!(And5TestCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    d: [Variable; 32],
    e: [Variable; 32],
    and_out: [PublicVariable; 32],
});

impl Define<GF2Config> for And5TestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        for i in 0..32 {
            let tmp1 = api.mul(self.a[i], self.b[i]);
            let tmp2 = api.mul(self.c[i], self.d[i]);
            let tmp3 = api.mul(tmp1, tmp2);
            let t = api.mul(tmp3, self.e[i]);
            api.assert_is_equal(t, self.and_out[i]);
        }
    }
}

#[test]
fn test_and5_layer() {
    let compile_result = compile(&And5TestCircuit::default(), CompileOptions::default()).unwrap();
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
        let and = a & b & c & d & e;

        let mut assignment = And5TestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.d[i] = ((d >> (31 - i)) & 1).into();
            assignment.e[i] = ((e >> (31 - i)) & 1).into();
            assignment.and_out[i] = ((and >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }
    println!("And5TestCircuit test passed.");
}
