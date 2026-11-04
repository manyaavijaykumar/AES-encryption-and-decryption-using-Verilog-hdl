# Quotation KS5595: Python-only implementation audit

This audit covers the technical scope on pages 2–15 of the supplied quotation. Commercial terms and the optional workshop are outside the software deliverable.

| Quoted item | Current implementation | Status |
|---|---|---|
| AES-128 encryption and decryption of 128-bit blocks with a 128-bit key | `aes_core.py` computes both directions and exposes every round state and key. The data, key, and expected result are editable; Python can generate fresh random data and key for each run. The known-answer vector and round trip are tested. | Working in Python |
| Verilog encryption, decryption, key expansion, AES transforms, and dual-mode top level | Modules are present in `verilog/`; an area variant is in `optimized/`. Start, busy, done, round counter, and key loading are represented in RTL. | Sources present; RTL execution is not independently verified here |
| Self-checking Verilog testbench | `verilog/aes_tb.v` checks both known-answer directions, busy, done, round progression, and timeout. The app reads its vectors and checks them with Python. | Testbench present; its Verilog is not executed |
| Functional simulation and waveforms | The Python engine calculates results and a 10 ns cycle timeline for reset, start, mode, busy, done, round state, round key, input, and output. The waveform is interactive and exports as SVG. | Working Python model; waveform is modeled from Python, not captured from RTL |
| RTL elaboration | The app parses modules and instances from saved Verilog sources. | Working source inspection |
| Resource, timing, and power analysis | `analysis_model.py` recomputes source-dependent estimates for all report fields named in the quotation. The report identifies them as estimates. | Working estimates; no device-specific synthesis, placement, routing, or power measurement |
| One hardware optimization objective | `optimized/aes_encrypt.v` shares an AddRoundKey datapath. Python compares its source estimates with the initial variant. | RTL variant and modeled comparison present; actual FPGA improvement unverified |
| Project documentation and report | `PROJECT_SCOPE.md`, `README.md`, this audit, and the downloadable current-source report cover the workflow and results. | Working |

## Physical-result boundary

Exact LUT, flip-flop, BRAM, DSP, slack, critical-path, frequency, and on-chip power values depend on a chosen FPGA and its implementation tools. A Python-only workspace can calculate estimates and a consistent behavioral trace, but cannot claim those estimates as actual Vivado synthesis or power reports. The interface and downloaded report state this distinction.
