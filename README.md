# AES-128 RTL Workspace

A self-contained desktop-style workspace for the quoted AES-128 encryption and decryption project. It includes editable Verilog sources, behavioral AES simulation, round traces, waveforms, source analysis, and a comparison with an area-optimized RTL variant.

## Run

Python 3.10 or newer is required. No third-party packages are needed.

- Windows: run `run.bat` or `py -3 app.py`.
- Linux/macOS: run `./run.sh` or `python3 app.py`.
- Open `http://127.0.0.1:8765/`.

Use `python3 app.py --port 9000` to change the port.

## Workflow

1. Inspect or edit the AES Verilog modules under **Sources**.
2. Select **Run Behavioral Simulation**. Enter one 128-bit block and one 128-bit key as 32 hexadecimal characters each. The preview, result, round trace, and waveform update from those values.
   The data and key fields are editable. **New random input and key** creates a fresh example; by default, **Run All** also generates fresh inputs each time. Editing a field switches to manual mode, so a run uses exactly the values shown. The computed output is read-only because AES determines it from the selected operation, data, and key. The optional expected output is editable for a pass/fail check. Repeating the same inputs produces the same output.
3. Review the encryption and decryption checks using the vectors currently declared in `verilog/aes_tb.v`.
4. Select **Run RTL Analysis** to compare the initial sources with `optimized/aes_encrypt.v`, which shares the AddRoundKey datapath in the area model.
5. Open the resource, timing, power, and initial-versus-optimized reports. Saving a source refreshes an open analysis. Export the modeled waveform as SVG or download a current-source Markdown project report from **Reports**.

The square-corners button in the waveform toolbar opens a large waveform popup. The same toolbar works there; click the button again, use the popup close button, or press Escape to return to the workspace. The signal names and waveform scroll together.

## What the results mean

AES output, inverse-operation checks, round states, and the 10 ns cycle timeline are calculated by the AES-128 Python engine. The waveform is generated from that Python timeline. The testbench vector checks read `PLAINTEXT`, `AES_KEY`, and `CIPHERTEXT` from `aes_tb.v` and compare them with the Python engine.

Resource, delay, and power fields are **RTL-derived estimates** calculated from the current source structure. They are useful for comparing changes in this workspace. They are not measurements from an FPGA, nor evidence of device synthesis, timing closure, or a completed Verilog testbench run. The model and its terms are defined in `analysis_model.py`. See `QUOTATION_AUDIT.md` for a requirement-by-requirement audit.

Only **area reduction** is implemented as an optimization objective. The RTL variant is in `optimized/aes_encrypt.v`.

## Verify

```bash
python3 -m unittest discover -s tests -v
```

The server binds to `127.0.0.1` by default and stores edited Verilog sources locally.
