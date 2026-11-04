# Quotation KS5595 — implementation map

## Objective

Design, implement, and inspect an AES-128 encryption/decryption architecture using Verilog HDL, with interactive behavioral simulation and source-derived analysis.

## Step-by-step operation

### Encryption

1. Load the 128-bit plaintext and 128-bit cipher key.
2. Select encryption mode (`mode = 0`) and pulse `start`.
3. Apply the initial AddRoundKey with round key 0.
4. Perform rounds 1–9: SubBytes, ShiftRows, MixColumns, and AddRoundKey.
5. Perform round 10: SubBytes, ShiftRows, and AddRoundKey, without MixColumns.
6. Keep `busy` active while processing.
7. Assert `done` and make the 128-bit ciphertext available at `data_out`.

### Decryption

1. Load the 128-bit ciphertext and the same 128-bit cipher key.
2. Select decryption mode (`mode = 1`) and pulse `start`.
3. Apply the initial AddRoundKey with round key 10.
4. Perform inverse rounds 9–1: Inverse ShiftRows, Inverse SubBytes, AddRoundKey, and Inverse MixColumns.
5. Perform the final inverse round with key 0, without Inverse MixColumns.
6. Keep `busy` active while processing.
7. Assert `done` and make the recovered 128-bit plaintext available at `data_out`.

## Scope coverage

| Quoted requirement | Included implementation |
|---|---|
| 128-bit plaintext/ciphertext/key | Python engine, Verilog buses, simulation form, and waveforms |
| AES encryption | `aes_encrypt.v` and `aes_core.encrypt_block` |
| AES decryption | `aes_decrypt.v` and `aes_core.decrypt_block` |
| SubBytes / Inverse SubBytes | Dedicated Verilog modules and Python transformations |
| ShiftRows / Inverse ShiftRows | Dedicated Verilog modules and Python transformations |
| MixColumns / Inverse MixColumns | Dedicated Verilog modules and Python transformations |
| AddRoundKey | Dedicated XOR module and Python transformation |
| Eleven round keys | `key_expansion.v`; Python key schedule returns keys 0–10 |
| Dual-mode top level | `aes_top.v` with `mode`, `start`, `busy`, and `done` |
| Round control | `round_control.v` and visible round-counter waveform |
| Self-checking testbench | `aes_tb.v` checks encryption and decryption against FIPS-197 |
| Functional simulation | AES-128 behavioral model with pass/fail result and testbench vector checks |
| Waveform analysis | Generated behavioral trace: clock, reset, start, mode, input, key, round, state, round key, busy, done, output |
| RTL elaboration | Interactive module hierarchy view |
| Resource analysis | Source-derived estimates for LUT, FF, slice register, BRAM, distributed memory, DSP, clock, and I/O fields |
| Timing analysis | Source-derived critical/data/logic/routing delay, modeled setup, WNS, TNS, period, and frequency fields |
| Power analysis | Source-derived total, dynamic, static, clock, logic, signal, I/O, BRAM, and DSP estimates |
| Optimisation | Area variant shares the encryption AddRoundKey datapath |
| Initial vs optimised | Live comparison of current source and area variant |

## Verification vector

```text
Plaintext : 00112233445566778899AABBCCDDEEFF
Key       : 000102030405060708090A0B0C0D0E0F
Ciphertext: 69C4E0D86A7B0430D8CDB78070B4C55A
```

The Python test suite verifies both directions and the ten-round trace. The Verilog testbench contains the same self-checking vector.

## Tool boundary

The interface is self-contained. AES operations are calculated by the behavioral engine. The resource, timing, and power values are source-derived estimates, not Vivado synthesis or device measurements. The bundled Verilog testbench is editable, and its declared vectors drive the behavioral checks; this does not constitute execution of the Verilog testbench. Real device reports require a target FPGA and vendor toolchain.
