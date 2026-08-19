# Validation Summary

## Completed checks

- Python AES-256 semantic model: passed two published known-answer tests.
- Generated RTL constant audit: all 256 S-box entries match the semantic model.
- Five testbench vectors: match the independent semantic model.
- Questa Verilog-2001 compilation: 0 errors and 0 warnings for the RTL and testbench.
- WaveDrom: the approved timing preview was rendered successfully.
- Readable-Verilog public compile gate: passed.

## Evidence boundaries

- Questa execution did not run because `vsim` reported that its license environment
  was not configured. The open-source simulator installer also could not deploy in
  the restricted session. Therefore, no completed RTL simulation is claimed.
- No synthesis, place-and-route, timing closure, side-channel evaluation, or hardware
  validation was run.
- The strict readable-Verilog profile is not delivery-ready. Its report is retained
  as `deliverable_gate.md`. Major causes are the profile's mandatory bilingual header
  conflicting with the requested English-only output, its tab/annotation conventions,
  and its three-operation combinational-cone limit, which is incompatible with a
  one-round-per-stage AES datapath at the approved fixed 14-cycle latency.

## Public readable-Verilog matrix

| Gate | Status |
| --- | --- |
| compile | passed |
| ast | failed |
| readability | failed |
| comment | failed |
| naming | failed |
| profile | failed |
| testbench | not requested by the static gate; testbench compiled |
| toolchain | not requested by the static gate; Questa compile ran, execution blocked |
