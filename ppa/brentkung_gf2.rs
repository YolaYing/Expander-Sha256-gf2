use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

// === 电路定义 ===
declare_circuit!(BrentKungCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    out: [PublicVariable; 32],
});

// === Brent–Kung GF(2) Adder ===
pub fn add_brentkung<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &Sha256Word,
    b: &Sha256Word,
) -> Sha256Word {
    let mut a = *a;
    let mut b = *b;
    a.reverse();
    b.reverse();

    let mut c = vec![api.constant(0); 32];
    let mut ci = api.constant(0);

    for i in 0..8 {
        let start = i * 4;
        let end = start + 4;
        let (sum, ci_next) = brent_kung_adder_4_bits(api, &a[start..end], &b[start..end], ci);
        ci = ci_next;
        c[start..end].copy_from_slice(&sum);
    }

    c.reverse();
    c.try_into().unwrap()
}

fn brent_kung_adder_4_bits<C: Config, Builder: RootAPI<C>>(
    api: &mut Builder,
    a: &[Variable],
    b: &[Variable],
    carry_in: Variable,
) -> ([Variable; 4], Variable) {
    let mut g = [api.constant(0); 4];
    let mut p = [api.constant(0); 4];

    for i in 0..4 {
        g[i] = api.mul(a[i], b[i]);
        p[i] = api.add(a[i], b[i]);
    }

    let p1g0 = api.mul(p[1], g[0]);
    let p0p1 = api.mul(p[0], p[1]);
    let p2p3 = api.mul(p[2], p[3]);

    let g10 = api.add(g[1], p1g0);
    let g20 = api.mul(p[2], g10);
    let g20 = api.add(g[2], g20);
    let g30 = api.mul(p[3], g20);
    let g30 = api.add(g[3], g30);

    let mut c = [api.constant(0); 5];
    c[0] = carry_in;
    let tmp = api.mul(p[0], c[0]);
    c[1] = api.add(g[0], tmp);
    let tmp = api.mul(p0p1, c[0]);
    c[2] = api.add(g10, tmp);
    let tmp = api.mul(p[2], c[0]);
    let tmp = api.mul(p0p1, tmp);
    c[3] = api.add(g20, tmp);
    let tmp = api.mul(p0p1, p2p3);
    let tmp = api.mul(tmp, c[0]);
    c[4] = api.add(g30, tmp);

    let mut sum = [api.constant(0); 4];
    for i in 0..4 {
        sum[i] = api.add(p[i], c[i]);
    }

    (sum, c[4])
}

// === 电路逻辑实现 ===
impl Define<GF2Config> for BrentKungCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let sum = add_brentkung(api, &self.a, &self.b);
        for i in 0..32 {
            api.assert_is_equal(sum[i], self.out[i]);
        }
    }
}

// === 测试函数 ===
#[test]
fn test_brentkung_gf2() {
    let compile_result = compile(&BrentKungCircuit::default(), CompileOptions::default()).unwrap();
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

        let mut assignment = BrentKungCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a_val >> (31 - i)) & 1).into();
            assignment.b[i] = ((b_val >> (31 - i)) & 1).into();
            assignment.out[i] = ((expected >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ All Brent–Kung GF2 adder tests passed.");
}

// // === sum_chain ===
// // a + b = sum1
// // c + d = sum2
// // sum1 + sum2 = sum3
// // e + f = sum4
// // sum3 + g = sum5
// // sum3 + sum4 = sum6
// // output = (sum5, sum6)

// declare_circuit!(BrentKungSumChainCircuit {
//     a: [Variable; 32],
//     b: [Variable; 32],
//     c: [Variable; 32],
//     d: [Variable; 32],
//     e: [Variable; 32],
//     f: [Variable; 32],
//     g: [Variable; 32],
//     out1: [PublicVariable; 32], // sum5
//     out2: [PublicVariable; 32], // sum6
// });

// impl Define<GF2Config> for BrentKungSumChainCircuit<Variable> {
//     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
//         let sum1 = add_brentkung(api, &self.a, &self.b);
//         let sum2 = add_brentkung(api, &self.c, &self.d);
//         let sum3 = add_brentkung(api, &sum1, &sum2);
//         let sum4 = add_brentkung(api, &self.e, &self.f);
//         let sum5 = add_brentkung(api, &sum3, &self.g);
//         let sum6 = add_brentkung(api, &sum3, &sum4);

//         for i in 0..32 {
//             api.assert_is_equal(sum5[i], self.out1[i]);
//             api.assert_is_equal(sum6[i], self.out2[i]);
//         }
//     }
// }

// #[test]
// fn test_brentkung_sum_chain() {
//     let compile_result = compile(
//         &BrentKungSumChainCircuit::default(),
//         CompileOptions::default(),
//     )
//     .unwrap();

//     let CompileResult {
//         witness_solver,
//         layered_circuit,
//     } = compile_result;

//     use rand::Rng;
//     let mut rng = rand::thread_rng();
//     for _ in 0..5 {
//         let a: u32 = rng.gen();
//         let b: u32 = rng.gen();
//         let c: u32 = rng.gen();
//         let d: u32 = rng.gen();
//         let e: u32 = rng.gen();
//         let f: u32 = rng.gen();
//         let g: u32 = rng.gen();

//         let sum1 = a.wrapping_add(b);
//         let sum2 = c.wrapping_add(d);
//         let sum3 = sum1.wrapping_add(sum2);
//         let sum4 = e.wrapping_add(f);
//         let sum5 = sum3.wrapping_add(g);
//         let sum6 = sum3.wrapping_add(sum4);

//         let mut assignment = BrentKungSumChainCircuit::<GF2>::default();
//         for i in 0..32 {
//             assignment.a[i] = ((a >> (31 - i)) & 1).into();
//             assignment.b[i] = ((b >> (31 - i)) & 1).into();
//             assignment.c[i] = ((c >> (31 - i)) & 1).into();
//             assignment.d[i] = ((d >> (31 - i)) & 1).into();
//             assignment.e[i] = ((e >> (31 - i)) & 1).into();
//             assignment.f[i] = ((f >> (31 - i)) & 1).into();
//             assignment.g[i] = ((g >> (31 - i)) & 1).into();
//             assignment.out1[i] = ((sum5 >> (31 - i)) & 1).into();
//             assignment.out2[i] = ((sum6 >> (31 - i)) & 1).into();
//         }

//         let witness = witness_solver.solve_witness(&assignment).unwrap();
//         let result = layered_circuit.run(&witness);
//         assert_eq!(result, vec![true]);
//     }

//     println!("✅ Brent–Kung Sum Chain test passed.");
// }

// // === 4-bit Brent–Kung GF(2) Adder ===
// declare_circuit!(BrentKung4BitCircuit {
//     a: [Variable; 4],
//     b: [Variable; 4],
//     cin: Variable,
//     out: [PublicVariable; 4],
//     cout: PublicVariable,
// });

// // Define 4-bit BK Adder inside the circuit
// impl Define<GF2Config> for BrentKung4BitCircuit<Variable> {
//     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
//         let (sum, carry_out) = brent_kung_adder_4_bits(api, &self.a, &self.b, self.cin);
//         for i in 0..4 {
//             api.assert_is_equal(sum[i], self.out[i]);
//         }
//         api.assert_is_equal(carry_out, self.cout);
//     }
// }
// #[test]
// fn test_brentkung_4bit() {
//     let compile_result =
//         compile(&BrentKung4BitCircuit::default(), CompileOptions::default()).unwrap();
//     let CompileResult {
//         witness_solver,
//         layered_circuit,
//     } = compile_result;

//     // 正确性验证
//     let mut rng = rand::thread_rng();
//     for _ in 0..5 {
//         let a: u8 = rng.gen::<u8>() & 0b1111;
//         let b: u8 = rng.gen::<u8>() & 0b1111;
//         let cin: u8 = rng.gen::<u8>() & 1;
//         let expected = a as u16 + b as u16 + cin as u16;

//         let mut assignment = BrentKung4BitCircuit::<GF2>::default();

//         // a、b 小端位赋值
//         for i in 0..4 {
//             assignment.a[i] = (((a >> i) & 1) != 0).into(); // 小端位序
//             assignment.b[i] = (((b >> i) & 1) != 0).into(); // 小端位序
//             assignment.out[i] = (((expected >> i) & 1) != 0).into(); // 小端输出匹配
//         }

//         assignment.cin = (cin != 0).into();
//         assignment.cout = (((expected >> 4) & 1) != 0).into(); // 第 5 位是 carry out

//         let witness = witness_solver.solve_witness(&assignment).unwrap();
//         let result = layered_circuit.run(&witness);

//         assert_eq!(
//             result,
//             vec![true],
//             "Failed for a = {a}, b = {b}, cin = {cin}"
//         );
//     }

//     println!("✅ Brent–Kung 4-bit test passed.");
// }

// === 3 step Brent–Kung GF(2) Adder ===
// a + b = sum1
// c + d = sum2
// sum1 + sum2 = sum3
// output = sum3

declare_circuit!(BrentKungSumChain4Circuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    d: [Variable; 32],
    out: [PublicVariable; 32], // sum3
});

impl Define<GF2Config> for BrentKungSumChain4Circuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let sum1 = add_brentkung(api, &self.a, &self.b);
        let sum2 = add_brentkung(api, &self.c, &self.d);
        let sum3 = add_brentkung(api, &sum1, &sum2);

        for i in 0..32 {
            api.assert_is_equal(sum3[i], self.out[i]);
        }
    }
}

#[test]
fn test_brentkung_sum_chain4() {
    let compile_result = compile(
        &BrentKungSumChain4Circuit::default(),
        CompileOptions::default(),
    )
    .unwrap();

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

        let sum1 = a.wrapping_add(b);
        let sum2 = c.wrapping_add(d);
        let sum3 = sum1.wrapping_add(sum2);

        let mut assignment = BrentKungSumChain4Circuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.d[i] = ((d >> (31 - i)) & 1).into();
            assignment.out[i] = ((sum3 >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ Brent–Kung 4-input Sum Chain test passed.");
}
