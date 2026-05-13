# scan-protobuf-net

End-to-end regression fixture for milestone-R (virtual-dispatch resolution
in `ReverseCallGraph`). Runs `TaintAnalyzer --scan --emit-rules` over
protobuf-net.Core 3.2.56
(`artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll`) and asserts the
generated rules.yaml matches `rules.yaml.expected`.

## What the milestone-R change adds

`ReverseCallGraph` now follows `callvirt` edges through every in-assembly
override (skipping `System.Object`'s denylisted virtuals). The reachability
gate inside `EntryPointEnumerator.VisibilityReject` now accepts methods on
internal nested types — like `ProtoBuf.ProtoReader/State` and
`ProtoBuf.ProtoReader/ReadOnlySequenceProtoReader` — when a public caller
reaches them via virtual dispatch.

Concretely, the locked rules.yaml gains 11 source candidates that were
invisible at the pre-milestone-R baseline. Notable additions:

- `ProtoBuf.ProtoReader/State::Init(System.ReadOnlyMemory<byte>)`
- `ProtoBuf.ProtoReader/State::ParseVarintUInt32(System.ReadOnlySpan<byte>, ...)`
- `ProtoBuf.ProtoReader/ReadOnlySequenceProtoReader::TryParseUInt32Varint(...)`
- Several `State::AppendBytes(...)` overloads on internal-typed nested classes

## What this fixture does NOT yet prove

`ProtoReader::ImplReadString` (the abstract dispatcher behind the
`ReadString()` OOM finding) is `IsFamilyAndAssembly` — C# `private protected`
— so the visibility filter rejects it regardless of reachability. Surfacing
it as an enumerator source requires a separate change to
`VisibilityReject`'s accessibility policy, out of scope for milestone-R.
The reachability change here is necessary infrastructure for that future
work.

## Activate

The fixture skips silently when
`artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll` is not
materialised (untracked working-tree artefact). To activate:

1. `cd tools/TaintAnalyzer && dotnet build -c Release`
2. Drop a protobuf-net.Core 3.2.56 build at
   `artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll`
   (any net-standard target — Cecil reads metadata only)
3. Run: `fixtures/scan-protobuf-net/run`
