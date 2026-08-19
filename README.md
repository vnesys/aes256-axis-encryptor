# AES-256 AXI-Stream Encryptor

This package contains a synthesizable Verilog-2001 AES-256 encryption core with a
128-bit, no-backpressure streaming interface. Each packet begins with two key
beats (`key[255:128]`, then `key[127:0]`) followed by one or more plaintext beats.

## Interface contract

- The input and output widths are 128 bits.
- There is no `TREADY` and no `TKEEP`.
- `TLAST` must be low on both key beats and high on the final plaintext beat.
- The first plaintext beat may immediately follow the second key beat.
- Payload latency is exactly 14 clocks; steady-state throughput is one block per clock.
- The source must not start another key until the prior output `TLAST` is emitted.
- The core performs raw FIPS-197 AES-256 encryption only.

## Files

- `rtl/aes256_axis_encryptor.v`: Verilog-2001 implementation.
- `tb/tb_aes256_axis_encryptor.v`: self-checking FIPS/NIST vector testbench.
- `model/aes256_reference.py`: independent Python semantic model.
- `spec/aes256_stream_key/aes256_axis_encryptor_spec.md`: full interface and timing specification.
- `spec/aes256_stream_key/waveforms/`: WaveDrom source and SVG preview.
- `reports/`: compilation and readable-RTL gate evidence.

## Example simulation

```text
iverilog -g2001 -o aes256_tb rtl/aes256_axis_encryptor.v tb/tb_aes256_axis_encryptor.v
vvp aes256_tb
```

The expected terminal message is:

```text
PASS: 5 AES-256 blocks matched with fixed 14-cycle latency
```

The current environment compiled both Verilog files with Questa without errors or
warnings. Executable Questa simulation was blocked by an unset license environment;
see `reports/validation_summary.md` for the evidence boundary.
