use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// === Carry-Save Adder ===
pub fn add_csa3<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
    c: &Sha256Word,
) -> (Sha256Word, Sha256Word) {
    let mut a = *a;
    let mut b = *b;
    let mut c = *c;
    a.reverse();
    b.reverse();
    c.reverse();

    let mut sum = [api.constant(0); 32];
    let mut carry = [api.constant(0); 33]; // carry[0] 是初始进位

    let mut ab = [api.constant(0); 32];
    let mut bc = [api.constant(0); 32];
    let mut ac = [api.constant(0); 32];
    let mut tmp = [api.constant(0); 32];

    for i in 0..32 {
        let a_add_b = api.add(a[i], b[i]);
        sum[i] = api.add(a_add_b, c[i]); // sum[i] = a[i] + b[i] + c[i]

        ab[i] = api.mul(a[i], b[i]);
        bc[i] = api.mul(b[i], c[i]);
        ac[i] = api.mul(a[i], c[i]); // carry[i + 1] = a[i] * b[i] + b[i] * c[i] + a[i] * c[i]
        tmp[i] = api.add(ab[i], bc[i]);
        carry[i + 1] = api.add(tmp[i], ac[i]);
    }

    let mut out_carry = [api.constant(0); 32];
    for i in 0..32 {
        out_carry[i] = carry[i]; // carry[0] 是初始进位，所以从 carry[1] 开始
    }

    sum.reverse();
    out_carry.reverse();

    (sum.try_into().unwrap(), out_carry.try_into().unwrap())
}

declare_circuit!(CSA3ChainTestCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    d: [Variable; 32],
    e: [Variable; 32],
    f: [Variable; 32],
    sum_out: [PublicVariable; 32],
    carry_out: [PublicVariable; 32],
});

impl Define<GF2Config> for CSA3ChainTestCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let (sum1, carry1) = add_csa3(api, &self.a, &self.b, &self.c);
        let (sum2, carry2) = add_csa3(api, &self.d, &self.e, &self.f);
        let (sum3, carry3) = add_csa3(api, &sum1, &carry1, &sum2);
        let (sum4, carry4) = add_csa3(api, &sum3, &carry3, &carry2);

        for i in 0..32 {
            api.assert_is_equal(sum4[i], self.sum_out[i]);
            api.assert_is_equal(carry4[i], self.carry_out[i]);
        }
    }
}

#[test]
fn test_csa3_chain() {
    let compile_result =
        compile(&CSA3ChainTestCircuit::default(), CompileOptions::default()).unwrap();

    let CompileResult {
        witness_solver,
        layered_circuit,
    } = compile_result;

    use rand::Rng;
    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let a: u32 = rng.gen();
        let b: u32 = rng.gen();
        let c: u32 = rng.gen();
        let d: u32 = rng.gen();
        let e: u32 = rng.gen();
        let f: u32 = rng.gen();

        let sum1 = a ^ b ^ c;
        let carry1 = ((a & b) ^ (a & c) ^ (b & c)) << 1;
        let sum2 = d ^ e ^ f;
        let carry2 = ((d & e) ^ (d & f) ^ (e & f)) << 1;

        let sum3 = sum1 ^ carry1 ^ sum2;
        let carry3 = ((sum1 & carry1) ^ (sum1 & sum2) ^ (carry1 & sum2)) << 1;

        let sum4 = sum3 ^ carry3 ^ carry2;
        let carry4 = ((sum3 & carry3) ^ (sum3 & carry2) ^ (carry3 & carry2)) << 1;

        let mut assignment = CSA3ChainTestCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.d[i] = ((d >> (31 - i)) & 1).into();
            assignment.e[i] = ((e >> (31 - i)) & 1).into();
            assignment.f[i] = ((f >> (31 - i)) & 1).into();
            assignment.sum_out[i] = ((sum4 >> (31 - i)) & 1).into();
            assignment.carry_out[i] = ((carry4 >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ CSA3 chain test passed!");
}
