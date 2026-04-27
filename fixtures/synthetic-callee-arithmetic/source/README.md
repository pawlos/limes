# synthetic-callee-arithmetic — milestone-D regression fixture

`WireDecoder.Decode` reads two u16 fields from a stream and multiplies them via a helper
class (`PayloadSizer.RecordsAreaBytes`). The product is used as the size of a `new byte[N]`
allocation. The multiplication happens inside the helper's return path — a shape that
exposed the milestone-D arithmetic-attribution gap when run blind through the analyzer.

The fixture is built outside the main solution by `scripts/build-synthetic-callee-arithmetic.sh`,
producing `artifacts/synthetic-callee-arithmetic/Decoder.dll` (+ `.pdb`).

The ground-truth `trace.yaml` for this fixture lives one level up at
`fixtures/synthetic-callee-arithmetic/trace.yaml` and is authored from the analyzer's own
output (see Task 7 of `docs/superpowers/plans/2026-04-27-milestone-d.md`).
