# synthetic-stackalloc — milestone-E regression fixture

`WireProcessor.Process` reads a u16 from a stream and uses it as the size argument to
`stackalloc byte[recordCount]`. The product is a stack buffer whose size is fully
attacker-controlled — the stack-overflow analogue of `new byte[N]`. This fixture exercises
milestone-E's U7 (`Localloc` matcher → `kind: allocation`, `api: stackalloc` sink hop).

The fixture is built outside the main solution by `scripts/build-synthetic-stackalloc.sh`,
producing `artifacts/synthetic-stackalloc/Decoder.dll` (+ `.pdb`).

The ground-truth `trace.yaml` for this fixture lives one level up at
`fixtures/synthetic-stackalloc/trace.yaml` and is authored from the analyzer's own output
(see Task 5 of `docs/superpowers/plans/2026-04-28-milestone-e.md`).
