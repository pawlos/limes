# scan-nbmp-1.1.25

End-to-end regression fixture for the entry-point enumerator (milestone-Q).
Runs `TaintAnalyzer --scan --emit-rules` over Nerdbank.MessagePack 1.1.25
(`artifacts/nbmp-1.1.25/Nerdbank.MessagePack.dll`) and asserts the generated
rules.yaml matches `rules.yaml.expected`.

The expected output contains `Nerdbank.MessagePack.MessagePackPrimitives::TryRead(...)` —
the entry point class that triggered milestone-O's stack-allocation finding
(GHSA-2cwq-pwfr-wcw3). The enumerator rediscovers it via the **parameter-shape
path** (no `--include-this-field`), matching the `ReadOnlySpan<byte>` parameter
of `TryRead`. This proves the heuristic catches the parameter-shape class of
bug without prior knowledge.

The fixture skips silently when `artifacts/nbmp-1.1.25/` is not materialised
(untracked working-tree artefact). To activate:

1. `cd tools/TaintAnalyzer && dotnet build -c Release`
2. Ensure `artifacts/nbmp-1.1.25/Nerdbank.MessagePack.dll` is in place
3. Run: `fixtures/scan-nbmp-1.1.25/run`
