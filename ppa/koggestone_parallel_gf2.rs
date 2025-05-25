use expander_compiler::frontend::*;
use expander_compiler::frontend::{Config, RootAPI, Variable};
use rand::Rng;
use serdes::ExpSerde;

pub type Sha256Word = [Variable; 32];

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

// === 电路实现 ===
impl Define<GF2Config> for KoggeStoneParallelCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let sum = add_koggestone_32_bits_prallel(api, &self.a, &self.b);
        for i in 0..32 {
            api.assert_is_equal(sum[i], self.out[i]);
        }
    }
}

// === 测试函数 ===
#[test]
fn test_koggestone_parallel_gf2() {
    let compile_result = compile(
        &KoggeStoneParallelCircuit::default(),
        CompileOptions::default(),
    )
    .unwrap();
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

        let mut assignment = KoggeStoneParallelCircuit::<GF2>::default();
        for i in 0..32 {
            assignment.a[i] = ((a_val >> (31 - i)) & 1).into();
            assignment.b[i] = ((b_val >> (31 - i)) & 1).into();
            assignment.out[i] = ((expected >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ All Kogge–Stone Parallel GF2 adder tests passed.");
}

// // === add 8 times to check if the word gate size = 1 time bit gate size ===
// declare_circuit!(KoggeStoneParallelSum8Circuit {
//     inputs: [[Variable; 32]; 8],
//     output: [PublicVariable; 32],
// });

// impl Define<GF2Config> for KoggeStoneParallelSum8Circuit<Variable> {
//     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
//         let mut acc = self.inputs[0];
//         for i in 1..8 {
//             acc = add_koggestone_32_bits_prallel(api, &acc, &self.inputs[i]);
//         }
//         for i in 0..32 {
//             api.assert_is_equal(acc[i], self.output[i]);
//         }
//     }
// }

// #[test]
// fn test_koggestone_parallel_sum_8() {
//     let compile_result = compile(
//         &KoggeStoneParallelSum8Circuit::default(),
//         CompileOptions::default(),
//     )
//     .unwrap();
//     let CompileResult {
//         witness_solver,
//         layered_circuit,
//     } = compile_result;

//     let mut rng = rand::thread_rng();
//     let n_tests = 5;
//     for _ in 0..n_tests {
//         let mut inputs_val = [0u32; 8];
//         let mut expected = 0u32;

//         for i in 0..8 {
//             inputs_val[i] = rng.gen();
//             expected = expected.wrapping_add(inputs_val[i]);
//         }

//         let mut assignment = KoggeStoneParallelSum8Circuit::<GF2>::default();
//         for i in 0..8 {
//             for j in 0..32 {
//                 assignment.inputs[i][j] = ((inputs_val[i] >> (31 - j)) & 1).into();
//             }
//         }
//         for i in 0..32 {
//             assignment.output[i] = ((expected >> (31 - i)) & 1).into();
//         }

//         let witness = witness_solver.solve_witness(&assignment).unwrap();
//         let result = layered_circuit.run(&witness);
//         assert_eq!(result, vec![true]);
//     }

//     println!("✅ Kogge–Stone 8-input sum GF2 adder test passed.");
// }

// // === 8组adder同时跑 ===
// declare_circuit!(KoggeStoneParallelBatch8Circuit {
//     a: [[Variable; 32]; 8],
//     b: [[Variable; 32]; 8],
//     out: [[PublicVariable; 32]; 8],
// });

// impl Define<GF2Config> for KoggeStoneParallelBatch8Circuit<Variable> {
//     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
//         for i in 0..8 {
//             let sum = add_koggestone_32_bits_prallel(api, &self.a[i], &self.b[i]);
//             for j in 0..32 {
//                 api.assert_is_equal(sum[j], self.out[i][j]);
//             }
//         }
//     }
// }

// #[test]
// fn test_koggestone_parallel_batch_8() {
//     let compile_result = compile(
//         &KoggeStoneParallelBatch8Circuit::default(),
//         CompileOptions::default(),
//     )
//     .unwrap();
//     let CompileResult {
//         witness_solver,
//         layered_circuit,
//     } = compile_result;

//     let mut rng = rand::thread_rng();
//     let n_tests = 5;
//     for _ in 0..n_tests {
//         let mut a_vals = [0u32; 8];
//         let mut b_vals = [0u32; 8];
//         let mut expected = [0u32; 8];

//         for i in 0..8 {
//             a_vals[i] = rng.gen();
//             b_vals[i] = rng.gen();
//             expected[i] = a_vals[i].wrapping_add(b_vals[i]);
//         }

//         let mut assignment = KoggeStoneParallelBatch8Circuit::<GF2>::default();
//         for i in 0..8 {
//             for j in 0..32 {
//                 assignment.a[i][j] = ((a_vals[i] >> (31 - j)) & 1).into();
//                 assignment.b[i][j] = ((b_vals[i] >> (31 - j)) & 1).into();
//                 assignment.out[i][j] = ((expected[i] >> (31 - j)) & 1).into();
//             }
//         }

//         let witness = witness_solver.solve_witness(&assignment).unwrap();
//         let result = layered_circuit.run(&witness);
//         assert_eq!(result, vec![true]);
//     }

//     println!("✅ All 8-group Kogge–Stone GF2 adder tests passed.");
// }

// // === sum_all 模拟电路：4个 GF(2) u32 加法 ===
// declare_circuit!(SumAllKoggeStoneTest {
//     a: [Variable; 32],
//     b: [Variable; 32],
//     c: [Variable; 32],
//     d: [Variable; 32],
//     out: [PublicVariable; 32],
// });

// // impl Define<GF2Config> for SumAllKoggeStoneTest<Variable> {
// //     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
// //         let mut vals = vec![self.a, self.b, self.c, self.d];

// //         while vals.len() > 1 {
// //             let n = vals.len();
// //             for i in (0..n).step_by(2) {
// //                 let j = i / 2;
// //                 if i + 1 < n {
// //                     vals[j] = add_koggestone_32_bits_prallel(api, &vals[i], &vals[i + 1]);
// //                 } else {
// //                     vals[j] = vals[i];
// //                 }
// //             }
// //             vals.truncate((n + 1) / 2);
// //         }

// //         let sum = vals[0];
// //         for i in 0..32 {
// //             api.assert_is_equal(sum[i], self.out[i]);
// //         }
// //     }
// // }

// impl Define<GF2Config> for SumAllKoggeStoneTest<Variable> {
//     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
//         let group: [Sha256Word; 4] = [self.a, self.b, self.c, self.d];
//         let t0 = add_koggestone_32_bits_prallel(api, &group[0], &group[1]);
//         let t1 = add_koggestone_32_bits_prallel(api, &group[2], &group[3]);
//         let sum = add_koggestone_32_bits_prallel(api, &t0, &t1);

//         for i in 0..32 {
//             api.assert_is_equal(sum[i], self.out[i]);
//         }
//     }
// }

// #[test]
// fn test_sum_all_koggestone_gf2() {
//     let compile_result =
//         compile(&SumAllKoggeStoneTest::default(), CompileOptions::default()).unwrap();
//     let CompileResult {
//         witness_solver,
//         layered_circuit,
//     } = compile_result;

//     let mut rng = rand::thread_rng();
//     for _ in 0..5 {
//         let a: u32 = rng.gen();
//         let b: u32 = rng.gen();
//         let c: u32 = rng.gen();
//         let d: u32 = rng.gen();
//         let expected = a.wrapping_add(b).wrapping_add(c).wrapping_add(d);

//         let mut assignment = SumAllKoggeStoneTest::<GF2>::default();
//         for i in 0..32 {
//             assignment.a[i] = ((a >> (31 - i)) & 1).into();
//             assignment.b[i] = ((b >> (31 - i)) & 1).into();
//             assignment.c[i] = ((c >> (31 - i)) & 1).into();
//             assignment.d[i] = ((d >> (31 - i)) & 1).into();
//             assignment.out[i] = ((expected >> (31 - i)) & 1).into();
//         }

//         let witness = witness_solver.solve_witness(&assignment).unwrap();
//         let result = layered_circuit.run(&witness);
//         assert_eq!(result, vec![true]);
//     }

//     println!("✅ sum_all GF(2) test passed for 4 inputs.");
// }

// === a + b = sum1
// c + d = sum2
// sum1 + sum2 = sum3
// e + f = sum4
// sum3 + g = sum5
// sum3 + sum4 = sum6
// output = (sum5, sum6) === //
declare_circuit!(KoggeStoneSumChainCircuit {
    a: [Variable; 32],
    b: [Variable; 32],
    c: [Variable; 32],
    d: [Variable; 32],
    e: [Variable; 32],
    f: [Variable; 32],
    g: [Variable; 32],
    out1: [PublicVariable; 32], // sum5
    out2: [PublicVariable; 32], // sum6
});

impl Define<GF2Config> for KoggeStoneSumChainCircuit<Variable> {
    fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
        let sum1 = add_koggestone_32_bits_prallel(api, &self.a, &self.b);
        let sum2 = add_koggestone_32_bits_prallel(api, &self.c, &self.d);
        let sum3 = add_koggestone_32_bits_prallel(api, &sum1, &sum2);
        let sum4 = add_koggestone_32_bits_prallel(api, &self.e, &self.f);
        let sum5 = add_koggestone_32_bits_prallel(api, &sum3, &self.g);
        let sum6 = add_koggestone_32_bits_prallel(api, &sum3, &sum4);

        for i in 0..32 {
            api.assert_is_equal(sum5[i], self.out1[i]);
            api.assert_is_equal(sum6[i], self.out2[i]);
        }
    }
}

#[test]
fn test_koggestone_sum_chain() {
    let compile_result = compile(
        &KoggeStoneSumChainCircuit::default(),
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
        let e: u32 = rng.gen();
        let f: u32 = rng.gen();
        let g: u32 = rng.gen();

        let sum1 = a.wrapping_add(b);
        let sum2 = c.wrapping_add(d);
        let sum3 = sum1.wrapping_add(sum2);
        let sum4 = e.wrapping_add(f);
        let sum5 = sum3.wrapping_add(g);
        let sum6 = sum3.wrapping_add(sum4);

        let mut assignment = KoggeStoneSumChainCircuit::<GF2>::default();

        for i in 0..32 {
            assignment.a[i] = ((a >> (31 - i)) & 1).into();
            assignment.b[i] = ((b >> (31 - i)) & 1).into();
            assignment.c[i] = ((c >> (31 - i)) & 1).into();
            assignment.d[i] = ((d >> (31 - i)) & 1).into();
            assignment.e[i] = ((e >> (31 - i)) & 1).into();
            assignment.f[i] = ((f >> (31 - i)) & 1).into();
            assignment.g[i] = ((g >> (31 - i)) & 1).into();
            assignment.out1[i] = ((sum5 >> (31 - i)) & 1).into();
            assignment.out2[i] = ((sum6 >> (31 - i)) & 1).into();
        }

        let witness = witness_solver.solve_witness(&assignment).unwrap();
        let result = layered_circuit.run(&witness);
        assert_eq!(result, vec![true]);
    }

    println!("✅ Sum chain test passed (sum5 and sum6 computed correctly).");
}

// // === sum_all 64轮模拟电路（带累加） ===
// declare_circuit!(SumAll64RoundsCircuit {
//     inputs: [[Variable; 32]; 256], // 64 × 4 = 256 个 32-bit u32
//     output: [PublicVariable; 32],  // 累加后输出
// });

// impl Define<GF2Config> for SumAll64RoundsCircuit<Variable> {
//     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
//         let mut acc = [api.constant(0); 32];

//         for round in 0..64 {
//             let base = round * 4;
//             let group: [Sha256Word; 4] = [
//                 self.inputs[base + 0],
//                 self.inputs[base + 1],
//                 self.inputs[base + 2],
//                 self.inputs[base + 3],
//             ];
//             let t0 = add_koggestone_32_bits_prallel(api, &group[0], &group[1]);
//             let t1 = add_koggestone_32_bits_prallel(api, &group[2], &group[3]);
//             let round_sum = add_koggestone_32_bits_prallel(api, &t0, &t1);

//             acc = add_koggestone_32_bits_prallel(api, &acc, &round_sum);
//         }

//         for i in 0..32 {
//             api.assert_is_equal(acc[i], self.output[i]);
//         }
//     }
// }

// #[test]
// fn test_sum_all_64_rounds() {
//     let compile_result =
//         compile(&SumAll64RoundsCircuit::default(), CompileOptions::default()).unwrap();
//     let CompileResult {
//         witness_solver,
//         layered_circuit,
//     } = compile_result;

//     let mut rng = rand::thread_rng();
//     let mut inputs = [[0u32; 4]; 64];
//     let mut acc: u32 = 0;

//     for round in 0..64 {
//         for i in 0..4 {
//             let val: u32 = rng.gen();
//             inputs[round][i] = val;
//         }
//     }

//     for round in 0..64 {
//         let a = inputs[round][0];
//         let b = inputs[round][1];
//         let c = inputs[round][2];
//         let d = inputs[round][3];

//         let tmp0 = a.wrapping_add(b);
//         let tmp1 = c.wrapping_add(d);
//         let round_sum = tmp0.wrapping_add(tmp1);
//         acc = acc.wrapping_add(round_sum);
//     }

//     let mut assignment = SumAll64RoundsCircuit::<GF2>::default();
//     for round in 0..64 {
//         for i in 0..4 {
//             let word = inputs[round][i];
//             for b in 0..32 {
//                 assignment.inputs[round * 4 + i][b] = ((word >> (31 - b)) & 1).into();
//             }
//         }
//     }
//     for b in 0..32 {
//         assignment.output[b] = ((acc >> (31 - b)) & 1).into();
//     }

//     let witness = witness_solver.solve_witness(&assignment).unwrap();
//     let result = layered_circuit.run(&witness);
//     assert_eq!(result, vec![true]);
//     println!("✅ 64轮 sum_all 累加测试通过。");
// }

// // simulate sha256 circuit with 64 rounds
// declare_circuit!(FinalRoundAandBCircuit {
//     inputs: [[Variable; 32]; 384],     // 64 rounds × 6 words
//     output: [[PublicVariable; 32]; 2], // output[0] = a, output[1] = b
// });

// impl Define<GF2Config> for FinalRoundAandBCircuit<Variable> {
//     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
//         let mut a = [api.constant(0); 32];
//         let mut b = [api.constant(0); 32];
//         let mut a_final = [api.constant(0); 32];
//         let mut b_final = [api.constant(0); 32];

//         for round in 0..64 {
//             let base = round * 6;
//             let group: [Sha256Word; 6] = [
//                 self.inputs[base + 0],
//                 self.inputs[base + 1],
//                 self.inputs[base + 2],
//                 self.inputs[base + 3],
//                 self.inputs[base + 4],
//                 self.inputs[base + 5],
//             ];

//             let t1_ab = add_koggestone_32_bits_prallel(api, &group[0], &group[1]);
//             let t1_cd = add_koggestone_32_bits_prallel(api, &group[2], &group[3]);
//             let t1 = add_koggestone_32_bits_prallel(api, &t1_ab, &t1_cd);
//             let t2 = add_koggestone_32_bits_prallel(api, &group[4], &group[5]);

//             let b = add_koggestone_32_bits_prallel(api, &t1, &a);
//             let a = add_koggestone_32_bits_prallel(api, &t1, &t2);

//             if round == 63 {
//                 a_final = a;
//                 b_final = b;
//             }
//         }

//         for i in 0..32 {
//             api.assert_is_equal(a_final[i], self.output[0][i]);
//             api.assert_is_equal(b_final[i], self.output[1][i]);
//         }
//     }
// }

// #[test]
// fn test_final_round_a_and_b_output() {
//     let compile_result = compile(
//         &FinalRoundAandBCircuit::default(),
//         CompileOptions::default(),
//     )
//     .unwrap();
//     let CompileResult {
//         witness_solver,
//         layered_circuit,
//     } = compile_result;

//     use rand::Rng;
//     let mut rng = rand::thread_rng();
//     let mut inputs = [[0u32; 6]; 64];
//     let (mut final_a, mut final_b) = (0u32, 0u32);
//     let (mut a_val, mut b_val) = (0u32, 0u32);

//     for round in 0..64 {
//         for i in 0..6 {
//             inputs[round][i] = rng.gen();
//         }
//     }

//     for round in 0..64 {
//         let [a, b, c, d, e, f] = inputs[round];
//         let t1 = a.wrapping_add(b).wrapping_add(c.wrapping_add(d));
//         let t2 = e.wrapping_add(f);
//         let b_val = t1.wrapping_add(a_val);
//         let a_val = t1.wrapping_add(t2);
//         if round == 63 {
//             final_a = a_val;
//             final_b = b_val;
//         }
//     }

//     let mut assignment = FinalRoundAandBCircuit::<GF2>::default();
//     for round in 0..64 {
//         for i in 0..6 {
//             let word = inputs[round][i];
//             for b in 0..32 {
//                 assignment.inputs[round * 6 + i][b] = ((word >> (31 - b)) & 1).into();
//             }
//         }
//     }

//     for b in 0..32 {
//         assignment.output[0][b] = ((final_a >> (31 - b)) & 1).into();
//         assignment.output[1][b] = ((final_b >> (31 - b)) & 1).into();
//     }

//     let witness = witness_solver.solve_witness(&assignment).unwrap();
//     let result = layered_circuit.run(&witness);
//     assert_eq!(result, vec![true]);
//     println!("✅ 最后一轮 a 与 b 分别输出测试通过。");
// }

// // // === sum_all 32轮模拟电路（带累加） ===
// // declare_circuit!(SumAll32RoundsCircuit {
// //     inputs: [[Variable; 32]; 128], // 32 × 4 = 256 个 32-bit u32
// //     output: [PublicVariable; 32],  // 累加后输出
// // });

// // impl Define<GF2Config> for SumAll32RoundsCircuit<Variable> {
// //     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
// //         let mut acc = [api.constant(0); 32];

// //         for round in 0..32 {
// //             let base = round * 4;
// //             let group: [Sha256Word; 4] = [
// //                 self.inputs[base + 0],
// //                 self.inputs[base + 1],
// //                 self.inputs[base + 2],
// //                 self.inputs[base + 3],
// //             ];
// //             let t0 = add_koggestone_32_bits_prallel(api, &group[0], &group[1]);
// //             let t1 = add_koggestone_32_bits_prallel(api, &group[2], &group[3]);
// //             let round_sum = add_koggestone_32_bits_prallel(api, &t0, &t1);

// //             acc = add_koggestone_32_bits_prallel(api, &acc, &round_sum);
// //         }

// //         for i in 0..32 {
// //             api.assert_is_equal(acc[i], self.output[i]);
// //         }
// //     }
// // }

// // #[test]
// // fn test_sum_all_32_rounds() {
// //     let compile_result =
// //         compile(&SumAll32RoundsCircuit::default(), CompileOptions::default()).unwrap();
// //     let CompileResult {
// //         witness_solver,
// //         layered_circuit,
// //     } = compile_result;

// //     let mut rng = rand::thread_rng();
// //     let mut inputs = [[0u32; 4]; 32];
// //     let mut acc: u32 = 0;

// //     for round in 0..32 {
// //         for i in 0..4 {
// //             let val: u32 = rng.gen();
// //             inputs[round][i] = val;
// //         }
// //     }

// //     for round in 0..32 {
// //         let a = inputs[round][0];
// //         let b = inputs[round][1];
// //         let c = inputs[round][2];
// //         let d = inputs[round][3];

// //         let tmp0 = a.wrapping_add(b);
// //         let tmp1 = c.wrapping_add(d);
// //         let round_sum = tmp0.wrapping_add(tmp1);
// //         acc = acc.wrapping_add(round_sum);
// //     }

// //     let mut assignment = SumAll32RoundsCircuit::<GF2>::default();
// //     for round in 0..32 {
// //         for i in 0..4 {
// //             let word = inputs[round][i];
// //             for b in 0..32 {
// //                 assignment.inputs[round * 4 + i][b] = ((word >> (31 - b)) & 1).into();
// //             }
// //         }
// //     }
// //     for b in 0..32 {
// //         assignment.output[b] = ((acc >> (31 - b)) & 1).into();
// //     }

// //     let witness = witness_solver.solve_witness(&assignment).unwrap();
// //     let result = layered_circuit.run(&witness);
// //     assert_eq!(result, vec![true]);
// //     println!("✅ 32轮 sum_all 累加测试通过。");
// // }

// // // === sum_all 16轮模拟电路（带累加） ===
// // declare_circuit!(SumAll16RoundsCircuit {
// //     inputs: [[Variable; 32]; 64], // 16 × 4 = 64 个 32-bit u32
// //     output: [PublicVariable; 32], // 累加后输出
// // });

// // impl Define<GF2Config> for SumAll16RoundsCircuit<Variable> {
// //     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
// //         let mut acc = [api.constant(0); 32];

// //         for round in 0..16 {
// //             let base = round * 4;
// //             let group: [Sha256Word; 4] = [
// //                 self.inputs[base + 0],
// //                 self.inputs[base + 1],
// //                 self.inputs[base + 2],
// //                 self.inputs[base + 3],
// //             ];
// //             let t0 = add_koggestone_32_bits_prallel(api, &group[0], &group[1]);
// //             let t1 = add_koggestone_32_bits_prallel(api, &group[2], &group[3]);
// //             let round_sum = add_koggestone_32_bits_prallel(api, &t0, &t1);

// //             acc = add_koggestone_32_bits_prallel(api, &acc, &round_sum);
// //         }

// //         for i in 0..32 {
// //             api.assert_is_equal(acc[i], self.output[i]);
// //         }
// //     }
// // }

// // #[test]
// // fn test_sum_all_16_rounds() {
// //     let compile_result =
// //         compile(&SumAll16RoundsCircuit::default(), CompileOptions::default()).unwrap();
// //     let CompileResult {
// //         witness_solver,
// //         layered_circuit,
// //     } = compile_result;

// //     let mut rng = rand::thread_rng();
// //     let mut inputs = [[0u32; 4]; 16];
// //     let mut acc: u32 = 0;

// //     for round in 0..16 {
// //         for i in 0..4 {
// //             let val: u32 = rng.gen();
// //             inputs[round][i] = val;
// //         }
// //     }

// //     for round in 0..16 {
// //         let a = inputs[round][0];
// //         let b = inputs[round][1];
// //         let c = inputs[round][2];
// //         let d = inputs[round][3];

// //         let tmp0 = a.wrapping_add(b);
// //         let tmp1 = c.wrapping_add(d);
// //         let round_sum = tmp0.wrapping_add(tmp1);
// //         acc = acc.wrapping_add(round_sum);
// //     }

// //     let mut assignment = SumAll16RoundsCircuit::<GF2>::default();
// //     for round in 0..16 {
// //         for i in 0..4 {
// //             let word = inputs[round][i];
// //             for b in 0..32 {
// //                 assignment.inputs[round * 4 + i][b] = ((word >> (31 - b)) & 1).into();
// //             }
// //         }
// //     }
// //     for b in 0..32 {
// //         assignment.output[b] = ((acc >> (31 - b)) & 1).into();
// //     }

// //     let witness = witness_solver.solve_witness(&assignment).unwrap();
// //     let result = layered_circuit.run(&witness);
// //     assert_eq!(result, vec![true]);
// //     println!("✅ 16轮 sum_all 累加测试通过。");
// // }

// // // === sum_all 8轮模拟电路（带累加） ===
// // declare_circuit!(SumAll8RoundsCircuit {
// //     inputs: [[Variable; 32]; 32], // 8 × 4 = 32 个 32-bit u32
// //     output: [PublicVariable; 32], // 累加后输出
// // });
// // impl Define<GF2Config> for SumAll8RoundsCircuit<Variable> {
// //     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
// //         let mut acc = [api.constant(0); 32];

// //         for round in 0..8 {
// //             let base = round * 4;
// //             let group: [Sha256Word; 4] = [
// //                 self.inputs[base + 0],
// //                 self.inputs[base + 1],
// //                 self.inputs[base + 2],
// //                 self.inputs[base + 3],
// //             ];
// //             let t0 = add_koggestone_32_bits_prallel(api, &group[0], &group[1]);
// //             let t1 = add_koggestone_32_bits_prallel(api, &group[2], &group[3]);
// //             let round_sum = add_koggestone_32_bits_prallel(api, &t0, &t1);

// //             acc = add_koggestone_32_bits_prallel(api, &acc, &round_sum);
// //         }

// //         for i in 0..32 {
// //             api.assert_is_equal(acc[i], self.output[i]);
// //         }
// //     }
// // }
// // #[test]
// // fn test_sum_all_8_rounds() {
// //     let compile_result =
// //         compile(&SumAll8RoundsCircuit::default(), CompileOptions::default()).unwrap();
// //     let CompileResult {
// //         witness_solver,
// //         layered_circuit,
// //     } = compile_result;

// //     let mut rng = rand::thread_rng();
// //     let mut inputs = [[0u32; 4]; 8];
// //     let mut acc: u32 = 0;

// //     for round in 0..8 {
// //         for i in 0..4 {
// //             let val: u32 = rng.gen();
// //             inputs[round][i] = val;
// //         }
// //     }

// //     for round in 0..8 {
// //         let a = inputs[round][0];
// //         let b = inputs[round][1];
// //         let c = inputs[round][2];
// //         let d = inputs[round][3];

// //         let tmp0 = a.wrapping_add(b);
// //         let tmp1 = c.wrapping_add(d);
// //         let round_sum = tmp0.wrapping_add(tmp1);
// //         acc = acc.wrapping_add(round_sum);
// //     }

// //     let mut assignment = SumAll8RoundsCircuit::<GF2>::default();
// //     for round in 0..8 {
// //         for i in 0..4 {
// //             let word = inputs[round][i];
// //             for b in 0..32 {
// //                 assignment.inputs[round * 4 + i][b] = ((word >> (31 - b)) & 1).into();
// //             }
// //         }
// //     }
// //     for b in 0..32 {
// //         assignment.output[b] = ((acc >> (31 - b)) & 1).into();
// //     }

// //     let witness = witness_solver.solve_witness(&assignment).unwrap();
// //     let result = layered_circuit.run(&witness);
// //     assert_eq!(result, vec![true]);
// //     println!("✅ 8轮 sum_all 累加测试通过。");
// // }

// // // === sum_all 4轮模拟电路（带累加） ===
// // declare_circuit!(SumAll4RoundsCircuit {
// //     inputs: [[Variable; 32]; 16], // 4 × 4 = 16 个 32-bit u32
// //     output: [PublicVariable; 32], // 累加后输出
// // });
// // impl Define<GF2Config> for SumAll4RoundsCircuit<Variable> {
// //     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
// //         let mut acc = [api.constant(0); 32];

// //         for round in 0..4 {
// //             let base = round * 4;
// //             let group: [Sha256Word; 4] = [
// //                 self.inputs[base + 0],
// //                 self.inputs[base + 1],
// //                 self.inputs[base + 2],
// //                 self.inputs[base + 3],
// //             ];
// //             let t0 = add_koggestone_32_bits_prallel(api, &group[0], &group[1]);
// //             let t1 = add_koggestone_32_bits_prallel(api, &group[2], &group[3]);
// //             let round_sum = add_koggestone_32_bits_prallel(api, &t0, &t1);

// //             acc = add_koggestone_32_bits_prallel(api, &acc, &round_sum);
// //         }

// //         for i in 0..32 {
// //             api.assert_is_equal(acc[i], self.output[i]);
// //         }
// //     }
// // }
// // #[test]
// // fn test_sum_all_4_rounds() {
// //     let compile_result =
// //         compile(&SumAll4RoundsCircuit::default(), CompileOptions::default()).unwrap();
// //     let CompileResult {
// //         witness_solver,
// //         layered_circuit,
// //     } = compile_result;

// //     let mut rng = rand::thread_rng();
// //     let mut inputs = [[0u32; 4]; 4];
// //     let mut acc: u32 = 0;

// //     for round in 0..4 {
// //         for i in 0..4 {
// //             let val: u32 = rng.gen();
// //             inputs[round][i] = val;
// //         }
// //     }

// //     for round in 0..4 {
// //         let a = inputs[round][0];
// //         let b = inputs[round][1];
// //         let c = inputs[round][2];
// //         let d = inputs[round][3];

// //         let tmp0 = a.wrapping_add(b);
// //         let tmp1 = c.wrapping_add(d);
// //         let round_sum = tmp0.wrapping_add(tmp1);
// //         acc = acc.wrapping_add(round_sum);
// //     }

// //     let mut assignment = SumAll4RoundsCircuit::<GF2>::default();
// //     for round in 0..4 {
// //         for i in 0..4 {
// //             let word = inputs[round][i];
// //             for b in 0..32 {
// //                 assignment.inputs[round * 4 + i][b] = ((word >> (31 - b)) & 1).into();
// //             }
// //         }
// //     }
// //     for b in 0..32 {
// //         assignment.output[b] = ((acc >> (31 - b)) & 1).into();
// //     }

// //     let witness = witness_solver.solve_witness(&assignment).unwrap();
// //     let result = layered_circuit.run(&witness);
// //     assert_eq!(result, vec![true]);
// //     println!("✅ 4轮 sum_all 累加测试通过。");
// // }

// // // === sum_all 2轮模拟电路（带累加） ===
// // declare_circuit!(SumAll2RoundsCircuit {
// //     inputs: [[Variable; 32]; 8],  // 2 × 4 = 8 个 32-bit u32
// //     output: [PublicVariable; 32], // 累加后输出
// // });
// // impl Define<GF2Config> for SumAll2RoundsCircuit<Variable> {
// //     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
// //         let mut acc = [api.constant(0); 32];

// //         for round in 0..2 {
// //             let base = round * 4;
// //             let group: [Sha256Word; 4] = [
// //                 self.inputs[base + 0],
// //                 self.inputs[base + 1],
// //                 self.inputs[base + 2],
// //                 self.inputs[base + 3],
// //             ];
// //             let t0 = add_koggestone_32_bits_prallel(api, &group[0], &group[1]);
// //             let t1 = add_koggestone_32_bits_prallel(api, &group[2], &group[3]);
// //             let round_sum = add_koggestone_32_bits_prallel(api, &t0, &t1);

// //             acc = add_koggestone_32_bits_prallel(api, &acc, &round_sum);
// //         }

// //         for i in 0..32 {
// //             api.assert_is_equal(acc[i], self.output[i]);
// //         }
// //     }
// // }
// // #[test]
// // fn test_sum_all_2_rounds() {
// //     let compile_result =
// //         compile(&SumAll2RoundsCircuit::default(), CompileOptions::default()).unwrap();
// //     let CompileResult {
// //         witness_solver,
// //         layered_circuit,
// //     } = compile_result;

// //     let mut rng = rand::thread_rng();
// //     let mut inputs = [[0u32; 4]; 2];
// //     let mut acc: u32 = 0;

// //     for round in 0..2 {
// //         for i in 0..4 {
// //             let val: u32 = rng.gen();
// //             inputs[round][i] = val;
// //         }
// //     }

// //     for round in 0..2 {
// //         let a = inputs[round][0];
// //         let b = inputs[round][1];
// //         let c = inputs[round][2];
// //         let d = inputs[round][3];

// //         let tmp0 = a.wrapping_add(b);
// //         let tmp1 = c.wrapping_add(d);
// //         let round_sum = tmp0.wrapping_add(tmp1);
// //         acc = acc.wrapping_add(round_sum);
// //     }

// //     let mut assignment = SumAll2RoundsCircuit::<GF2>::default();
// //     for round in 0..2 {
// //         for i in 0..4 {
// //             let word = inputs[round][i];
// //             for b in 0..32 {
// //                 assignment.inputs[round * 4 + i][b] = ((word >> (31 - b)) & 1).into();
// //             }
// //         }
// //     }
// //     for b in 0..32 {
// //         assignment.output[b] = ((acc >> (31 - b)) & 1).into();
// //     }

// //     let witness = witness_solver.solve_witness(&assignment).unwrap();
// //     let result = layered_circuit.run(&witness);
// //     assert_eq!(result, vec![true]);
// //     println!("✅ 2轮 sum_all 累加测试通过。");
// // }

// // // === sum_all 1轮模拟电路（带累加） ===
// // declare_circuit!(SumAll1RoundsCircuit {
// //     inputs: [[Variable; 32]; 4],  // 1 × 4 = 4 个 32-bit u32
// //     output: [PublicVariable; 32], // 累加后输出
// // });
// // impl Define<GF2Config> for SumAll1RoundsCircuit<Variable> {
// //     fn define<Builder: RootAPI<GF2Config>>(&self, api: &mut Builder) {
// //         let mut acc = [api.constant(0); 32];

// //         let group: [Sha256Word; 4] = [
// //             self.inputs[0],
// //             self.inputs[1],
// //             self.inputs[2],
// //             self.inputs[3],
// //         ];
// //         let t0 = add_koggestone_32_bits_prallel(api, &group[0], &group[1]);
// //         let t1 = add_koggestone_32_bits_prallel(api, &group[2], &group[3]);
// //         let round_sum = add_koggestone_32_bits_prallel(api, &t0, &t1);

// //         acc = add_koggestone_32_bits_prallel(api, &acc, &round_sum);

// //         for i in 0..32 {
// //             api.assert_is_equal(acc[i], self.output[i]);
// //         }
// //     }
// // }
// // #[test]
// // fn test_sum_all_1_rounds() {
// //     let compile_result =
// //         compile(&SumAll1RoundsCircuit::default(), CompileOptions::default()).unwrap();
// //     let CompileResult {
// //         witness_solver,
// //         layered_circuit,
// //     } = compile_result;

// //     let mut rng = rand::thread_rng();
// //     let mut inputs = [[0u32; 4]; 1];
// //     let mut acc: u32 = 0;

// //     for i in 0..4 {
// //         let val: u32 = rng.gen();
// //         inputs[0][i] = val;
// //     }

// //     let a = inputs[0][0];
// //     let b = inputs[0][1];
// //     let c = inputs[0][2];
// //     let d = inputs[0][3];

// //     let tmp0 = a.wrapping_add(b);
// //     let tmp1 = c.wrapping_add(d);
// //     let round_sum = tmp0.wrapping_add(tmp1);
// //     acc = acc.wrapping_add(round_sum);

// //     let mut assignment = SumAll1RoundsCircuit::<GF2>::default();
// //     for i in 0..4 {
// //         let word = inputs[0][i];
// //         for b in 0..32 {
// //             assignment.inputs[i][b] = ((word >> (31 - b)) & 1).into();
// //         }
// //     }
// //     for b in 0..32 {
// //         assignment.output[b] = ((acc >> (31 - b)) & 1).into();
// //     }

// //     let witness = witness_solver.solve_witness(&assignment).unwrap();
// //     let result = layered_circuit.run(&witness);
// //     assert_eq!(result, vec![true]);
// //     println!("✅ 1轮 sum_all 累加测试通过。");
// // }
