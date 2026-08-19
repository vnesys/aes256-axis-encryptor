# Readable-Verilog Deliverable Gate

The strict generated-deliverable gate ran against the package and reported
`delivery_ready = false`.

| Gate | Result | Notes |
| --- | --- | --- |
| compile | passed | Formatter AST and quality compile checks accepted one module with no parse errors. |
| ast | failed | The strict formatter profile reported three conformance errors. |
| readability | failed | Strict formatting, annotation, literal, and combinational-cone rules were not met. |
| comment | failed | The profile requires more declaration-level annotations. |
| naming | failed | Several AES algorithm identifiers do not match the profile's closed naming rules. |
| profile | failed | The profile requires a bilingual header and tab indentation. |
| testbench | not requested | The gate did not execute the testbench; Questa compiled it separately. |
| toolchain | not requested | External execution is outside this static gate. |

The profile result does not indicate a Verilog syntax failure. The separate Questa
compile completed with 0 errors and 0 warnings. The largest architectural blocker is
the strict three-operation combinational-cone budget: one complete AES round per
registered stage necessarily exceeds that budget. Meeting it would require deeper
round partitioning and would change the user-approved 14-cycle latency. The profile's
mandatory bilingual header also conflicts with the English-only deliverable request.

The complete raw JSON and Markdown reports are retained in the workspace's internal
`work/gate_raw` directory rather than the English-only user deliverable.
