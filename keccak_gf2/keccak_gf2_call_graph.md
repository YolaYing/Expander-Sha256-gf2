# Call-Graph
```
main
└── keccak256Circuit.Define                    # 8 parallel Keccak hashes
    └── computeKeccak                          # For each input block
        ├── [Padding] pad10*1 (inline)         # Expands 64 bytes → 136 bytes (1088 bits)
        ├── [Absorb] xorIn                     # Inject padded message into state
        │   └── xor                            # 17 lanes × 64-bit XOR
        │       └── api.Add
        ├── [Permutation] keccakF              # Full Keccak-f[1600] permutation (24 rounds)
        │   ├── Round Loop ×24
        │   │   ├── θ (theta) – Column Mixing
        │   │   │   ├── xor                    # Compute C[x], D[x]
        │   │   │   │   └── api.Add
        │   │   │   └── rotateLeft             # C[x+1] << 1
        │   │   ├── ρ + π (rho + pi) – Reorder
        │   │   │   └── rotateLeft             # Rotate and reposition lanes
        │   │   ├── χ (chi) – Non-linear Mix
        │   │   │   ├── not                    # ¬B[x+1][y]
        │   │   │   │   └── api.Sub
        │   │   │   ├── and                    # AND with B[x+2][y]
        │   │   │   │   └── api.Mul
        │   │   │   └── xor                    # XOR with B[x][y]
        │   │   └── ι (iota) – Constant Inject
        │   │       └── api.Sub                # Flip bits if RC[i][j] == 1
        ├── [Squeeze] copyOutUnaligned         # Read first 256 bits from state
        └── return []frontend.Variable         # 256-bit output as public digest
```

# Round-Level Call Structure (Each of 24 Keccak-f Rounds)
```
Round_i
├── Theta
│   ├── compute C[x] = A[x,0..4] ⊕ ...  [5 columns]
│   ├── compute D[x] = C[x-1] ⊕ ROT(C[x+1], 1)
│   └── update A[x,y] = A[x,y] ⊕ D[x]
├── Rho + Pi
│   └── apply rotateLeft(a[i], r[i]) to build b[j]
├── Chi
│   └── a[x,y] = b[x,y] ⊕ (¬b[x+1,y] ∧ b[x+2,y])
├── Iota
│   └── a[0][j] = 1 - a[0][j] if RC[i][j] == 1
```
