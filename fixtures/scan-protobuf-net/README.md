# scan-protobuf-net

End-to-end regression fixture for milestones R and S1. Runs
`TaintAnalyzer --scan --emit-rules` over protobuf-net.Core 3.2.56
(`artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll`) and asserts the
generated rules.yaml matches `rules.yaml.expected`.

## What milestone-R added (callvirt expansion in ReverseCallGraph)

`ReverseCallGraph` follows `callvirt` edges through every in-assembly
override (skipping `System.Object`'s denylisted virtuals). The reachability
gate inside `EntryPointEnumerator.VisibilityReject` accepts methods on
internal nested types — like `ProtoBuf.ProtoReader/State` and
`ProtoBuf.ProtoReader/ReadOnlySequenceProtoReader` — when a public caller
reaches them via virtual dispatch.

R surfaced 11 source candidates invisible at the pre-R baseline. Notable:

- `ProtoBuf.ProtoReader/State::Init(System.ReadOnlyMemory<byte>)`
- `ProtoBuf.ProtoReader/State::ParseVarintUInt32(System.ReadOnlySpan<byte>, ...)`
- `ProtoBuf.ProtoReader/ReadOnlySequenceProtoReader::TryParseUInt32Varint(...)`
- Several `State::AppendBytes(...)` overloads on internal-typed nested classes

## What milestone-S1 adds (family-accessibility relaxation)

`VisibilityReject` now defers to `ReverseCallGraph.IsReachableFromPublic`
for the family-accessibility buckets (`IsFamily`, `IsFamilyAndAssembly`,
`IsFamilyOrAssembly`) as well as the previously-handled internal buckets.
Private methods remain rejected without consulting the graph.

S1 surfaces 6 additional candidates on the writer side — `private protected`
overrides of `ProtoWriter`'s abstract `ImplWriteBytes` / `ImplCopyRawFromStream`
dispatchers, each taking a byte-source parameter (`ReadOnlySpan<byte>` or
`Stream`):

- `ProtoBuf.ProtoWriter/BufferWriterProtoWriter::ImplWriteBytes(State&, ReadOnlySpan<byte>)`
- `ProtoBuf.ProtoWriter/BufferWriterProtoWriter::ImplCopyRawFromStream(State&, Stream)`
- `ProtoBuf.ProtoWriter/NullProtoWriter::ImplCopyRawFromStream(State&, Stream)`
- `ProtoBuf.ProtoWriter/NullProtoWriter::ImplWriteBytes(State&, ReadOnlySpan<byte>)`
- `ProtoBuf.ProtoWriter/StreamProtoWriter::ImplWriteBytes(State&, ReadOnlySpan<byte>)`
- `ProtoBuf.ProtoWriter/StreamProtoWriter::ImplCopyRawFromStream(State&, Stream)`

## What this fixture still does NOT prove

`ProtoReader::ImplReadString(ref State, int bytes)` — the abstract reader-side
dispatcher behind the `ReadString()` OOM advisory — has parameters
`(State&, Int32)`. Neither matches `MatchesParameterShape`'s byte-source set,
so the method is rejected before `VisibilityReject` is even consulted.
Surfacing it from cold requires a parameter-shape-orthogonal mechanism — for
example, an opt-in flag that accepts methods overriding a public-reachable
abstract virtual regardless of parameter shape, or a body-scan heuristic
that recognises byte-source-typed values inside the method body. Tracked as
a future milestone.

## Activate

The fixture skips silently when
`artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll` is not
materialised (untracked working-tree artefact). To activate:

1. `cd tools/TaintAnalyzer && dotnet build -c Release`
2. Drop a protobuf-net.Core 3.2.56 build at
   `artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll`
   (any net-standard target — Cecil reads metadata only)
3. Run: `fixtures/scan-protobuf-net/run`
