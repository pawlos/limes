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

Milestone-S1 (family-accessibility relaxation in `VisibilityReject`) added 5
further candidates that were previously rejected by visibility alone, all
`private protected` overrides taking `ReadOnlySpan<byte>` and reachable from
public callers via callvirt:

- `UnusedDataPacket/Map::GetPropertyNameMemory(ReadOnlySpan<byte>)`
- `UnusedDataPacket/Map::Add(ReadOnlySpan<byte>, RawMessagePack&)`
- `SecureHash.SipHash::Compute(ReadOnlySpan<byte>)`
- `Converters.ObjectMapConverter`1::TryMatchPropertyName(ReadOnlySpan<byte>, String)`
- `Converters.ObjectMapWithNonDefaultCtorConverter`2::TryMatchPropertyName(ReadOnlySpan<byte>, String)`

The fixture skips silently when `artifacts/nbmp-1.1.25/` is not materialised
(untracked working-tree artefact). To activate:

1. `cd tools/TaintAnalyzer && dotnet build -c Release`
2. Ensure `artifacts/nbmp-1.1.25/Nerdbank.MessagePack.dll` is in place
3. Run: `fixtures/scan-nbmp-1.1.25/run`
