package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"os"

	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/field/gf2"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/test"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto"
)

const NHashes = 8

const CheckBits = 256

var rcs [][]uint

func init() {
	// Each round constant RC[i] is computed using a linear-feedback shift register (LFSR) defined in the spec.
	var rc [24]*big.Int
	rc[0], _ = new(big.Int).SetString("0000000000000001", 16)
	rc[1], _ = new(big.Int).SetString("0000000000008082", 16)
	rc[2], _ = new(big.Int).SetString("800000000000808A", 16)
	rc[3], _ = new(big.Int).SetString("8000000080008000", 16)
	rc[4], _ = new(big.Int).SetString("000000000000808B", 16)
	rc[5], _ = new(big.Int).SetString("0000000080000001", 16)
	rc[6], _ = new(big.Int).SetString("8000000080008081", 16)
	rc[7], _ = new(big.Int).SetString("8000000000008009", 16)
	rc[8], _ = new(big.Int).SetString("000000000000008A", 16)
	rc[9], _ = new(big.Int).SetString("0000000000000088", 16)
	rc[10], _ = new(big.Int).SetString("0000000080008009", 16)
	rc[11], _ = new(big.Int).SetString("000000008000000A", 16)
	rc[12], _ = new(big.Int).SetString("000000008000808B", 16)
	rc[13], _ = new(big.Int).SetString("800000000000008B", 16)
	rc[14], _ = new(big.Int).SetString("8000000000008089", 16)
	rc[15], _ = new(big.Int).SetString("8000000000008003", 16)
	rc[16], _ = new(big.Int).SetString("8000000000008002", 16)
	rc[17], _ = new(big.Int).SetString("8000000000000080", 16)
	rc[18], _ = new(big.Int).SetString("000000000000800A", 16)
	rc[19], _ = new(big.Int).SetString("800000008000000A", 16)
	rc[20], _ = new(big.Int).SetString("8000000080008081", 16)
	rc[21], _ = new(big.Int).SetString("8000000000008080", 16)
	rc[22], _ = new(big.Int).SetString("0000000080000001", 16)
	rc[23], _ = new(big.Int).SetString("8000000080008008", 16)

	rcs = make([][]uint, 24)
	for i := 0; i < 24; i++ {
		rcs[i] = make([]uint, 64)
		for j := 0; j < 64; j++ {
			rcs[i][j] = rc[i].Bit(j)
		}
	}
}
// Function Purpose:
	// This function models the absorb phase in the Keccak sponge construction.
	// For each message block 𝑀𝑖,
	// XOR it into the first r/w lanes of the Keccak state 𝑆[𝑥,𝑦],
	// where 𝑟 = 1088, 𝑤 = 64 → 𝑟/𝑤 = 17 lanes.
// Inputs:
	// - `api`: the constraint system builder
	// - `s`: The Keccak state A[x,y], as a flattened 1D array of 25 lanes (each lane is 64 bits)
	// - `buf`: The current message block, also as [][]frontend.Variable (17 lanes × 64 bits)
// Outputs:
	// - `s`: The updated Keccak state after XORing the message block into the first r/w lanes
// Gate Count:
	// pure binary circuits: 17 lanes × 64 bits = 1,088 XOR gates
	// word-boolean-circuits: 17 lanes × 8 words = 136 XOR word gates
func xorIn(api frontend.API, s [][]frontend.Variable, buf [][]frontend.Variable) [][]frontend.Variable {
	// Traverses each lane in order: (x, y) → 5*x + y
	// For the first 17 lanes (< len(buf)), applies: s[5*x + y] = s[5*x + y] XOR buf[x + 5*y]
	for y := 0; y < 5; y++ {
		for x := 0; x < 5; x++ {
			if x+5*y < len(buf) {
				// xor: lane level in code
				// in circuit level: for each bit in the 64-bit lane, 1 Add gate is emitted (XOR in GF(2)), Therefore: 64 gates per lane
				s[5*x+y] = xor(api, s[5*x+y], buf[x+5*y])
			}
		}
	}
	return s
}

// Function Purpose:
	// full implementation of the Keccak-f[1600] permutation applied 24 times inside a zk circuit over GF(2)
// Inputs:
	// - `api`: the constraint system builder
	// - `a`: the state array (25 lanes, each 64 bits), laid out as a[0] to a[24]
	//        The state corresponds to the 5×5 Keccak matrix A[x][y], flattened row-major
	// 	      Each round modifies a in place using Keccak's 5 round steps
// Outputs:
	// - `a`: the modified state array after 24 rounds of Keccak-f[1600]
func keccakF(api frontend.API, a [][]frontend.Variable) [][]frontend.Variable {
	// It preallocates storage for temporary Keccak lanes used during each round.
	// | Variable    | Size                | Purpose                                                                                 |
	// | ----------- | ------------------- | --------------------------------------------------------------------------------------- |
	// | `b[25][64]` | 25 lanes × 64 bits  | Stores intermediate results after ρ and π steps (rotated & permuted lanes)              |
	// | `c[5][64]`  | 5 columns × 64 bits | Stores column parity for θ step                                                         |
	// | `d[5][64]`  | 5 columns × 64 bits | Stores θ diffusion terms: $D[x] = C[x−1] ⊕ rot(C[x+1], 1)$                              |
	// | `da[5][64]` | 5 lanes × 64 bits   | Similar to `d`, but uses direct lanes from `a` instead of `c` (optimizing lane-based θ) |
	var b [25][]frontend.Variable
	for i := 0; i < len(b); i++ {
		b[i] = make([]frontend.Variable, 64)
		for j := 0; j < 64; j++ {
			b[i][j] = 0
		}
	}
	var c [5][]frontend.Variable
	for i := 0; i < len(c); i++ {
		c[i] = make([]frontend.Variable, 64)
		for j := 0; j < 64; j++ {
			c[i][j] = 0
		}
	}
	var d [5][]frontend.Variable
	for i := 0; i < len(d); i++ {
		d[i] = make([]frontend.Variable, 64)
		for j := 0; j < 64; j++ {
			d[i][j] = 0
		}
	}
	var da [5][]frontend.Variable
	for i := 0; i < len(d); i++ {
		da[i] = make([]frontend.Variable, 64)
		for j := 0; j < 64; j++ {
			da[i][j] = 0
		}
	}

	// Loop: 24 rounds: 
	// Each round performs the full sequence: θ → ρ → π → χ → ι
	for i := 0; i < 24; i++ {
		// -------------------------------- θ step --------------------------------
		// θ step computes:
		// C[x]=A[x,0]⊕A[x,1]⊕A[x,2]⊕A[x,3]⊕A[x,4] → column parity
		// D[x]=C[x−1]⊕ROT(C[x+1],1) → mixes across columns
		// A[x,y]=A[x,y]⊕D[x] → apply this to all lanes in column x

		// This computes: C[x]=A[x,0]⊕A[x,1]⊕A[x,2]⊕A[x,3]⊕A[x,4] for x in 0..4
		// assumes a[x+5*y] instead of a[5x+y], which suggests it's using column-major layout
		// vanilla implementation would be: c[x] = a[x][0] ⊕ a[x][1] ⊕ a[x][2] ⊕ a[x][3] ⊕ a[x][4]
			// Gate count: 
				// pure binary circuits: 5 columns × 4 xor calls × 64 bits = 1280 XOR gates
				// word-boolean-circuits: 5 columns × 4 xor calls × 8 words = 160 gates
		c[0] = xor(api, xor(api, a[1], a[2]), xor(api, a[3], a[4]))
		c[1] = xor(api, xor(api, a[6], a[7]), xor(api, a[8], a[9]))
		c[2] = xor(api, xor(api, a[11], a[12]), xor(api, a[13], a[14]))
		c[3] = xor(api, xor(api, a[16], a[17]), xor(api, a[18], a[19]))
		c[4] = xor(api, xor(api, a[21], a[22]), xor(api, a[23], a[24]))

		// This gives: D[x]=C[x−1]⊕ROT(C[x+1],1)
		// each C[i] is 64 bits
		// vanilla implementation would be: D[x] = C[x-1] ⊕ ROT(C[x+1], 1)
		// Gate count:
			// pure binary circuits: 5 columns × 1 xor call × 64 bits = 320 XOR gates
			// word-boolean-circuits: 5 columns × 1 xor call × 8 words = 40 gates(XOR with rotate)
		for j := 0; j < 5; j++ {
			d[j] = xor(api, c[(j+4)%5], rotateLeft(c[(j+1)%5], 1))
			// da[j]=A[j−1,0]⊕ROT(A[j+1,0],1)
			da[j] = xor(api, a[((j+4)%5)*5], rotateLeft(a[((j+1)%5)*5], 1))
		}
		// A[x,y]=A[x,y]⊕D[x]
		// Gate count:
			// pure binary circuits: 5 columns × 5 rows × 64 bits = 1600 XOR gates
			// word-boolean-circuits: 5 columns × 5 rows × 8 words = 200 gates
		for j := 0; j < 25; j++ {
			tmp := xor(api, da[j/5], a[j])
			a[j] = xor(api, tmp, d[j/5])
		}

		// Case 1: Pure Keccak-style θ (Spec-Aligned)
		// | Step                 | Calls  | Bits per call | Total XOR Gates (bit-level) | Total Word Gates (8-bit) |
		// | -------------------- | ------ | ------------- | --------------------------- | ------------------------ |
		// | `C[x]`: 5-input XOR  | 5 × 4  | 64            | 1280                        | 160                      |
		// | `D[x]` (with rotate) | 5 × 1  | 64            | 320                         | 40 *(with rotate)        |
		// | `A[x,y]` update      | 25 × 1 | 64            | 1600                        | 200                      |
		// | **Total**            |        |               | **3200**                    | **400** ✅               |
		
		// Case 2: Implementation (with da[x])
		// | Step                                 | Calls  | Bits per call | Total XOR Gates (bit-level) | Total Word Gates (8-bit) |
		// | ------------------------------------ | ------ | ------------- | --------------------------- | ------------------------ |
		// | `C[x]`: 4-input XOR (misses A\[x,0]) | 5 × 3  | 64            | 960                         | 120                      |
		// | `D[x]` (with rotate)                 | 5 × 1  | 64            | 320                         | 40  *(with rotate)       |
		// | `da[x]` (with rotate)                | 5 × 1  | 64            | 320                         | 40  *(with rotate)       |
		// | `A[x,y]` update (2× XOR per lane)    | 25 × 2 | 64            | 3200                        | 400                      |
		// | **Total**                            |        |               | **4800** ❌                  | **600** ❌                |
		// This style of optimization comes from word-oriented ZK systems (e.g., Groth16, Halo2), where reducing logic depth or reusing intermediate wires (like da[x]) can help. 

		// --------------------------- ρ and π step --------------------------------
		/*Rho and pi steps*/
		// ρ (Rho): Bitwise rotation of each lane (64-bit)
		// π (Pi): Permutation of lane positions in the state
		
		// Purpose of this Code Block: b[...] = rotateLeft(a[...], ...)
		// This entire block transforms the Keccak state a[0..24] into b[0..24], where:
		// a[i] represents the lane A[x,y]
		// b[i] is the rotated and permuted version B[y,(2x+3y)]
		// ρ Step: Bit Rotation
			// Each lane in the state is rotated left by a constant (different for each position), defined by Keccak-f's spec. For example:
			// rotateLeft(a[1], 36) means the lane a[1] is rotated left by 36 bits.
			// The constants (like 36, 3, 41, ...) come from the Keccak rotation offset table.
			// These offsets are fixed for each position (x, y) in the Keccak 5×5 grid.
		// π Step: Permutation
			// B[y][(2x+3y)mod5]=ROT(A[x][y],r[x][y])
		b[0] = a[0]

		b[8] = rotateLeft(a[1], 36)
		b[11] = rotateLeft(a[2], 3)
		b[19] = rotateLeft(a[3], 41)
		b[22] = rotateLeft(a[4], 18)

		b[2] = rotateLeft(a[5], 1)
		b[5] = rotateLeft(a[6], 44)
		b[13] = rotateLeft(a[7], 10)
		b[16] = rotateLeft(a[8], 45)
		b[24] = rotateLeft(a[9], 2)

		b[4] = rotateLeft(a[10], 62)
		b[7] = rotateLeft(a[11], 6)
		b[10] = rotateLeft(a[12], 43)
		b[18] = rotateLeft(a[13], 15)
		b[21] = rotateLeft(a[14], 61)

		b[1] = rotateLeft(a[15], 28)
		b[9] = rotateLeft(a[16], 55)
		b[12] = rotateLeft(a[17], 25)
		b[15] = rotateLeft(a[18], 21)
		b[23] = rotateLeft(a[19], 56)

		b[3] = rotateLeft(a[20], 27)
		b[6] = rotateLeft(a[21], 20)
		b[14] = rotateLeft(a[22], 39)
		b[17] = rotateLeft(a[23], 8)
		b[20] = rotateLeft(a[24], 14)

		// gate count: Pure wire routing (no API ops)
		// !! will meet problems if B = 8, cross-word rotations

		// --------------------------- χ step --------------------------------
		// A[x,y]=B[x,y]⊕(¬B[x+1,y]∧B[x+2,y])
		// Each row (5 lanes) is updated using its neighbors
		// This is the only nonlinear step in Keccak
		/*Xi state*/
		// a[x + 5*y] = b[x + 5*y] ⊕ (¬b[(x+1)%5 + 5*y] ∧ b[(x+2)%5 + 5*y])
		// for each update, consists of:
			// NOT (per bit): ¬b[i+1]
			// 1 AND: (¬b[i+1]) ∧ b[i+2]
            // 1 XOR: with b[i]
		// gate count:
			// pure binary circuits: 5 rows × 5 lanes × 64 bits = 1600 AND gates + 1600 XOR gates + 1600 NOT gates(equivalent to AND gates)
			// word-boolean-circuits: 5 rows × 5 lanes × 8 words = 200 AND gates + 200 XOR gates + 200 NOT gates
		a[0] = xor(api, b[0], and(api, not(api, b[5]), b[10]))
		a[1] = xor(api, b[1], and(api, not(api, b[6]), b[11]))
		a[2] = xor(api, b[2], and(api, not(api, b[7]), b[12]))
		a[3] = xor(api, b[3], and(api, not(api, b[8]), b[13]))
		a[4] = xor(api, b[4], and(api, not(api, b[9]), b[14]))

		a[5] = xor(api, b[5], and(api, not(api, b[10]), b[15]))
		a[6] = xor(api, b[6], and(api, not(api, b[11]), b[16]))
		a[7] = xor(api, b[7], and(api, not(api, b[12]), b[17]))
		a[8] = xor(api, b[8], and(api, not(api, b[13]), b[18]))
		a[9] = xor(api, b[9], and(api, not(api, b[14]), b[19]))

		a[10] = xor(api, b[10], and(api, not(api, b[15]), b[20]))
		a[11] = xor(api, b[11], and(api, not(api, b[16]), b[21]))
		a[12] = xor(api, b[12], and(api, not(api, b[17]), b[22]))
		a[13] = xor(api, b[13], and(api, not(api, b[18]), b[23]))
		a[14] = xor(api, b[14], and(api, not(api, b[19]), b[24]))

		a[15] = xor(api, b[15], and(api, not(api, b[20]), b[0]))
		a[16] = xor(api, b[16], and(api, not(api, b[21]), b[1]))
		a[17] = xor(api, b[17], and(api, not(api, b[22]), b[2]))
		a[18] = xor(api, b[18], and(api, not(api, b[23]), b[3]))
		a[19] = xor(api, b[19], and(api, not(api, b[24]), b[4]))

		a[20] = xor(api, b[20], and(api, not(api, b[0]), b[5]))
		a[21] = xor(api, b[21], and(api, not(api, b[1]), b[6]))
		a[22] = xor(api, b[22], and(api, not(api, b[2]), b[7]))
		a[23] = xor(api, b[23], and(api, not(api, b[3]), b[8]))
		a[24] = xor(api, b[24], and(api, not(api, b[4]), b[9]))

		// --------------------------- ι step --------------------------------
		// XOR round constant RC[i] into a[0] (lane A[0,0]), A[0][0]=A[0][0]⊕RC[i]
		// The rcs array stores RC[i] as bits
		// Only bits where rcs[i][j] == 1 are flipped using 1 ⊕ a[0][j] = 1 - a[0][j]
		///*Last step*/
		// For each bit A[0][0],
		// if the round constant RC[i][j]=1,
		// then flip that bit: a[0][j]=1−a[0][j]
		// !! rcs (the round constants used in the ι step) are public, fixed, and universal for all Keccak permutations of a given width.
		for j := 0; j < len(a[0]); j++ {
			if rcs[i][j] == 1 {
				a[0][j] = api.Sub(1, a[0][j])
			}
		}
		// gate count:
			// pure binary circuits: 1 round constant × 64 bits = 64 NOT gates(equivalent to AND gates)
			// word-boolean-circuits: 1 round constant × 8 words = 8 NOT gates(equivalent to AND gates)
	}

	return a
}

func xor(api frontend.API, a []frontend.Variable, b []frontend.Variable) []frontend.Variable {
	nbits := len(a)
	bitsRes := make([]frontend.Variable, nbits)
	for i := 0; i < nbits; i++ {
		bitsRes[i] = api.Add(a[i], b[i])
		//bitsRes[i] = api.(ecgo.API).ToSingleVariable(bitsRes[i])
	}
	return bitsRes
}

func and(api frontend.API, a []frontend.Variable, b []frontend.Variable) []frontend.Variable {
	nbits := len(a)
	bitsRes := make([]frontend.Variable, nbits)
	for i := 0; i < nbits; i++ {
		//x := api.(ecgo.API).ToSingleVariable(a[i])
		//y := api.(ecgo.API).ToSingleVariable(b[i])
		//fmt.Println(api.(ecgo.API).LayerOf(x))
		//bitsRes[i] = api.Mul(x, y)
		//fmt.Println(bitsRes[i])
		bitsRes[i] = api.Mul(a[i], b[i])
		//bitsRes[i] = api.(ecgo.API).ToSingleVariable(bitsRes[i])
		//fmt.Println(bitsRes[i])
	}
	return bitsRes
}

func not(api frontend.API, a []frontend.Variable) []frontend.Variable {
	bitsRes := make([]frontend.Variable, len(a))
	for i := 0; i < len(a); i++ {
		// But subtraction is same cost as addition in GF(2), so this is equivalent to: res[i] = Add(1, a[i])  // modulo 2
		bitsRes[i] = api.Sub(1, a[i])
	}
	return bitsRes
}

// rotateLeft(b,k)[i]=b[(i−k) mod n]
// this is purely a Go-level wire reindexing operation, which just reordering references to existing frontend.Variables, not computing anything new.
// What happens at the circuit level?
// If:
// a := []frontend.Variable{a₀, a₁, a₂, ..., a₆₃}
// b := rotateLeft(a, 1)
// Then:
// b[0] = a[63]
// b[1] = a[0]
// b[2] = a[1]
// ...
// b[63] = a[62]
// These are just wires reused in new places.
// When you later do api.Add(b[i], ...), the constraint will refer to the original wire a[j], just in a different place.
func rotateLeft(bits []frontend.Variable, k int) []frontend.Variable {
	n := uint(len(bits))
	s := uint(k) & (n - 1)
	newBits := bits[n-s:]
	return append(newBits, bits[:n-s]...)
}

func copyOutUnaligned(api frontend.API, s [][]frontend.Variable, rate, outputLen int) []frontend.Variable {
	out := []frontend.Variable{}
	w := 8
	for b := 0; b < outputLen; {
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				if x+5*y < (rate/w) && (b < outputLen) {
					out = append(out, s[5*x+y]...)
					b += 8
				}
			}
		}
	}
	return out
}

type keccak256Circuit struct {
	P   [NHashes][64 * 8]frontend.Variable
	Out [NHashes][CheckBits]frontend.Variable `gnark:",public"`
}

func computeKeccak(api frontend.API, P []frontend.Variable) []frontend.Variable {
	// ----------------------------- Initialize Keccak State: 5×5×64 bits = 1600 bits -----------------------------
	// ss is the Keccak state A[x][y], represented as a 1D array of 25 lanes.
	// Each lane is 64 bits → total 1600 bits
	ss := make([][]frontend.Variable, 25)
	// Initially all set to zero → corresponds to state := zero_state() in Keccak spec.
	for i := 0; i < 25; i++ {
		ss[i] = make([]frontend.Variable, 64)
		for j := 0; j < 64; j++ {
			ss[i][j] = 0
		}
	}

	// ------------------------------------- Copy input P and prepare for padding ----------------------------------
	// P is the 64-byte (512-bit) message input, already bit-decomposed.
	// newP is a flat array to which padding will be appended.
	// It will become the padded message block.
	newP := make([]frontend.Variable, 64*8)
	copy(newP, P)

	// -------------------------------- Apply pad10*1 padding to reach 136 bytes (1088 bits) ------------------------
	// We need to pad from 64 bytes → 136 bytes (rate = 1088 bits = 136 bytes)
	// pad10*1 means: start with 1, add 0s, end with 1, encoded as:
	// - First byte = 0b00000001
	// - Last byte = 0b10000000
	appendData := make([]byte, 136-64) // 72 bytes of padding
	appendData[0] = 1  // binary: 00000001
	appendData[135-64] = 0x80 // binary: 10000000, appendData[71] = 0x80 = 10000000
	// it appears in the MSB of the last byte, but the following code reads it bitwise in little-endian(LSB first)
	// appendData[71] = 0x80 = 10000000
	// ↓
	// bit order in newP: 0 0 0 0 0 0 0 1  ← last bit is a `1` (bit 7)

	// -------------------------------- Append padded bits to the message ----------------------------------------------
	// Each byte of appendData is expanded into 8 bits (little-endian order).
	// Now newP contains 1088 bits (136 × 8).
	for i := 0; i < 136-64; i++ {
		for j := 0; j < 8; j++ {
			newP = append(newP, int((appendData[i]>>j)&1))
		}
	}
	// -------------------------------- Split into 17 lanes of 64 bits ------------------------------------------
	// These 1088 bits are packed into 17 64-bit slices = 17 Keccak lanes.
	p := make([][]frontend.Variable, 17)
	for i := 0; i < 17; i++ {
		p[i] = make([]frontend.Variable, 64)
		for j := 0; j < 64; j++ {
			p[i][j] = newP[i*64+j]
		}
	}

	// -------------------------------- Absorb phase: inject padded message block ----------------------------------
	// p := input (512 bits) + pad10*1 = exactly 1088 bits = 1 block
	// state[0:r] ^= p
	ss = xorIn(api, ss, p)
	// Only the first 17 lanes of the state are XORed with the input block.

	// -------------------------------- Apply Keccak-f permutation (24 rounds) -----------------------------------
	// Applies full Keccak-f[1600], including 24 rounds of: θ → ρ → π → χ → ι
	// Internally uses XOR, AND, NOT, ROTATE — all at bit-level with constraints.
	ss = keccakF(api, ss)

	// ------------------------- Squeeze phase: extract 32-byte = 256-bit digest -----------------------------------
	// Reads the first 256 bits from the rate portion of the state (first 136 bytes).
	// For SHA3-256, 1 extraction round is enough
	out := copyOutUnaligned(api, ss, 136, 32)
	// out is a 256-length []frontend.Variable, representing the final Keccak digest in bit form.
	return out
}

// Define(api frontend.API) is the core interface required by gnark and ecgo circuits. This function builds the constraints of the zk-SNARK circuit.
// It is called by the compiler to generate the circuit. 
// Inputs: 
// - `api`: the constraint system builder — you use this to create gates
// Outputs:
// - `t`: circuit struct, now filled with symbolic variables (t.P[i][j], t.Out[i][j]) 
func (t *keccak256Circuit) Define(api frontend.API) error {
	// You can use builder.MemorizedVoidFunc for sub-circuits
	// f := builder.Memorized1DFunc(computeKeccak)
	f := computeKeccak
	for i := 0; i < NHashes; i++ {
		// This iterates through NHashes = 8 hash computations.
		// For each input block t.P[i] (512 bits), it calls your previously defined function computeKeccak(api, input), which returns []frontend.Variable — the output bits (256-bit hash).
		out := f(api, t.P[i][:])
		for j := 0; j < CheckBits; j++ {
			// Compares each output bit from the internal computation (out[j]) to the expected public output stored in t.Out[i][j].
			api.AssertIsEqual(out[j], t.Out[i][j])
		}
	}
	return nil
}

func main() {
	// ----------------Build and Compile the Keccak-256 circuit over GF(2) using Expander's ecgo frontend----------------
	var circuit keccak256Circuit

	// This compiles the keccak256Circuit struct (which implements Define())
	// cr is the compiled representation, including internal wiring.
	// inputs and outputs of Compile()	:
	// - function signature: func Compile(field *big.Int, circuit frontend.Circuit, opts ...frontend.CompileOption) (*CompileResult, error)
	// - inputs:
	//   | Parameter | Type                        | Meaning                                                                                          |
	//   | --------- | --------------------------- | ------------------------------------------------------------------------------------------------ |
	//   | `field`   | `*big.Int`                  | The finite field over which the circuit is defined (e.g. `gf2.ScalarField`)                      |
	//   | `circuit` | `frontend.Circuit`          | A user-defined circuit struct (e.g. `keccak256Circuit`) that implements the `Define(api)` method |
	//   | `opts`    | variadic `...CompileOption` | Optional configuration flags (e.g. compression thresholds, debug flags, etc.)                    |
	// - outputs:
	//   | Field            | Type           | Meaning                                        |
	//   | ---------------- | -------------- | ---------------------------------------------- |
	//   | `*CompileResult` | Struct pointer | Contains all artifacts of the compiled circuit |
    //   | `error`          | error          | Non-nil if compilation failed                  |

	cr, err := ecgo.Compile(gf2.ScalarField, &circuit)
	if err != nil {
		panic(err)
	}

	// Gets the internal LayeredCircuit (i.e., gate-level logic).
	c := cr.GetLayeredCircuit()
	//c.Print()
	// Writes it to disk for inspection (circuit.txt).
	os.WriteFile("circuit.txt", c.Serialize(), 0o644)
	// Then deserializes it — a safeguard to ensure the circuit is cleanly reconstructed.
	c = ecgo.DeserializeLayeredCircuit(c.Serialize())

	// Loop over NHashes = 8 hash computations
	// Each loop creates a separate Keccak-256 hash task with:
	// 1. Random 512-bit input
	// 2. Corresponding 256-bit Keccak output
	// 3. Populated circuit input/output
	for k := 0; k < NHashes; k++ {
		// -------------------------------- Generating random inputs (64 bytes = 512 bits) ----------------------------------
		// Initialize all bits to zero
		// 64 * 8 = 512 bits of input for each Keccak instance.
		for i := 0; i < 64*8; i++ {
			circuit.P[k][i] = 0
		}

		// Generate random 64-byte(i.e., 512 bits) message
		data := make([]byte, 64)
		rand.Read(data)

		// Convert message into bit-level input
		// Converts the 64-byte message into 512 individual bits (bit 0 is the least significant bit).
		// Stored into circuit.P[k], which is used in the circuit as private input.
		for i := 0; i < 64; i++ {
			for j := 0; j < 8; j++ {
				circuit.P[k][i*8+j] = int((data[i] >> j) & 1)
			}
		}

		// -------------------- Computing the real Keccak-256 hash using Ethereum's reference implementation -------------------
		// Uses the Ethereum-standard Keccak implementation to compute the correct output.
		// Output is 256 bits (32 bytes).
		hash := crypto.Keccak256Hash(data)

		// Convert hash output to bits
		// Converts the 32-byte hash into a 256-bit Boolean array (bit 0 = LSB).
		// This becomes the expected public output for that input.
		outBits := make([]int, 256)
		for i := 0; i < 32; i++ {
			for j := 0; j < 8; j++ {
				outBits[i*8+j] = int((hash[i] >> j) & 1)
			}
		}
		// Store hash output into the circuit’s public output field
		// This is what the circuit must match to pass verification (api.AssertIsEqual() in Define()).
		for i := 0; i < CheckBits; i++ {
			circuit.Out[k][i] = outBits[i]
		}
	}

	// ---------------------------- Performing three different witness checks -------------------------------------------------
	// Shared Setup: Prepare the witness solver
	is := ecgo.DeserializeInputSolver(cr.GetInputSolver().Serialize())

	// Test 1: Solve with correct input and verify
	// 	Given the circuit whose .P and .Out fields have already been populated,
	// 	This line returns the witness, i.e., values for all internal wires (not just the inputs).
	wit, err := is.SolveInput(&circuit, 0)
	if err != nil {
		panic("gg")
	}

	// This line checks that the witness actually satisfies all constraints in the compiled circuit c
	if !test.CheckCircuit(c, wit) {
		panic("should succeed")
	}
	fmt.Println("test 1 passed")

	// Test 2: Flip 1 bit of input and confirm circuit fails
	//  For each Keccak input, you flip the first bit of the input (from 0 → 1 or 1 → 0).
	//  But the circuit.Out[k] hash remains unchanged — meaning it’s now mismatched.
	for k := 0; k < NHashes; k++ {
		circuit.P[k][0] = 1 - circuit.P[k][0].(int)
	}
	// This should now fail because the output no longer matches what the Keccak circuit computes from the modified input.
	wit, err = is.SolveInput(&circuit, 0)
	if err != nil {
		panic("gg")
	}

	if test.CheckCircuit(c, wit) {
		panic("should fail")
	}
	fmt.Println("test 2 passed")

	// Test 3: Batch test 16 random inputs
	// You are preparing 16 new Keccak hash computations.
	assignments := make([]frontend.Circuit, 16)
	for z := 0; z < 16; z++ {
		// Each assignment has the following done:
		// Input P[k] is filled with random 64-byte message (bit-level)
		// Output Out[k] is set to the true Keccak-256 hash of that message
		assignment := &keccak256Circuit{}
		for k := 0; k < NHashes; k++ {
			for i := 0; i < 64*8; i++ {
				assignment.P[k][i] = 0
			}
			data := make([]byte, 64)
			rand.Read(data)
			for i := 0; i < 64; i++ {
				for j := 0; j < 8; j++ {
					assignment.P[k][i*8+j] = int((data[i] >> j) & 1)
				}
			}
			outBits := make([]int, 256)
			hash := crypto.Keccak256Hash(data)
			for i := 0; i < 32; i++ {
				for j := 0; j < 8; j++ {
					outBits[i*8+j] = int((hash[i] >> j) & 1)
				}
			}
			for i := 0; i < CheckBits; i++ {
				assignment.Out[k][i] = outBits[i]
			}
		}
		assignments[z] = assignment
	}
	// This returns a batched witness for all 16 input circuits.
	wit, err = is.SolveInputs(assignments)
	if err != nil {
		panic("gg")
	}
	// Stores the witness on disk for later inspection.
	os.WriteFile("witness.txt", wit.Serialize(), 0o644)
	// This runs all 16 assignments against the compiled circuit and ensures they all pass.
	ss := test.CheckCircuitMultiWitness(c, wit)
	for _, s := range ss {
		if !s {
			panic("should succeed")
		}
	}
	fmt.Println("test 3 passed")
}