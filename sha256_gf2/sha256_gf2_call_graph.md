# Call-Graph

```
main
└── sha256Circuit.Define                          # SHA-256 circuit entrypoint
    └── SHA256GF2::finalize                       # Finalizes hash computation
        ├── [Padding] append '1' + 0s + length    # Pad message to 512-bit blocks
        ├── [Chunking] split into 512-bit blocks  # Each block is hashed sequentially
        ├── [InitState] H[0..7] ← SHA256_INIT     # Initialize internal state
        ├── sha256_compress                       # Compression function per block
        │   ├── [Message Schedule] build W[0..63]
        │   │   ├── W[0..15] ← input              # Raw 32-bit chunks from input
        │   │   ├── W[i] =                        # For i = 16..63
        │   │   │   ├── lower_case_sigma1(W[i-2]) # σ₁: ROTR17, ROTR19, SHR10
        │   │   │   ├── lower_case_sigma0(W[i-15])# σ₀: ROTR7, ROTR18, SHR3
        │   │   │   └── add + add                 # GF(2) Brent-Kung adder
        │   ├── [Compression Loop]Round Loop ×64
        │   │   ├── capital_sigma1(e)             # Σ₁: ROTR6,11,25
        │   │   │   └── rotate_right              # Bit rotation
        │   │   ├── ch(e, f, g)                   # (e ∧ f) ⊕ (¬e ∧ g)
        │   │   │   ├── and                       # ∧ gate = api.mul
        │   │   │   ├── not                       # ¬ gate = api.sub
        │   │   │   └── xor                       # ⊕ gate = api.add
        │   │   ├── sum_all([h, Σ₁, Ch, W+K])     # Add multiple words
        │   │   ├── capital_sigma0(a)             # Σ₀: ROTR2,13,22
        │   │   ├── maj(a, b, c)                  # Majority: 2 of 3 bits = 1
        │   │   │   └── and + xor + xor           # 3 ANDs, 2 XORs
        │   │   └── add temp1 + temp2             # Brent-Kung GF(2) addition
        │   └── [State Update]                    # a..h ← next round state
        └── return 256-bit hash (H[0..7])         # Flattened bit vector as output
```

---

# Round-Level Call Structure (Each of 64 SHA-256 Rounds)

```
Round_i
├── capital_sigma1(e)                             # ROTR^6(e) ⊕ ROTR^11(e) ⊕ ROTR^25(e)
│   └── rotate_right(x, k)                        # (x >> k) | (x << (32 - k))
├── ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)
│   ├── and(e, f)
│   ├── not(e)
│   ├── and(¬e, g)
│   └── xor
├── sum_all(h, Σ₁, Ch, W+K)                        # 4-input tree adder
│   ├── binary-tree of add()
│   └── add (Brent-Kung style)
│       ├── split into 8 × 4-bit segments
│       ├── for each 4-bit group:
│       │   └── brent_kung_adder_4_bits
│       │       ├── generate g[i] = a[i] ∧ b[i]
│       │       ├── generate p[i] = a[i] ⊕ b[i]
│       │       ├── prefix tree: compute g[i:0]
│       │       ├── compute carry[i] from g[..] + p[..]
│       │       └── sum[i] = p[i] ⊕ carry[i]
│       └── carries propagate serially across 4-bit blocks
├── capital_sigma0(a) = ROTR^2(a) ⊕ ROTR^13(a) ⊕ ROTR^22(a)
│   └── rotate_right
├── maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)
│   ├── and
│   └── xor
├── temp1 = h + Σ₁ + ch + W[i] + K[i]               # from sum_all
├── temp2 = Σ₀ + maj                                # one add()
├── [State Rotation]
│   └── a..h ← rotated and updated using temp1 and temp2
│       ├── e = d + temp1     ← add()
│       └── a = temp1 + temp2 ← add()
```
