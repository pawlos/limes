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

## What milestone-S2 adds (--include-virtual-overrides)

`EnumeratorConfig.IncludeVirtualOverrides` (CLI: `--include-virtual-overrides`)
accepts methods that override an abstract virtual whose root is reachable from
public, regardless of parameter shape. The second lock file,
`rules.yaml.expected.with-overrides`, captures the output when the flag is on.

S2 surfaces ~94 additional candidates on protobuf-net.Core 3.2.56 — the full
set of in-assembly `Impl*` overrides on the abstract `ProtoReader` /
`ProtoWriter` dispatcher hierarchies. Notably:

- `ProtoBuf.ProtoReader/ReadOnlySequenceProtoReader::ImplReadString(State&, Int32)`
- `ProtoBuf.ProtoReader/StreamProtoReader::ImplReadString(State&, Int32)`

These are exactly the methods at the head of the `ImplReadString → Ensure →
ResizeAndFlushLeft → new byte[length]` chain documented in the protobuf-net
string-OOM advisory. Feeding the with-overrides rules.yaml back through
`--rules` reproduces the advisory chain from cold without prior knowledge.

## Activate

The fixture skips silently when
`artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll` is not
materialised (untracked working-tree artefact). To activate:

1. `cd tools/TaintAnalyzer && dotnet build -c Release`
2. Drop a protobuf-net.Core 3.2.56 build at
   `artifacts/protobuf-net.Core-3.2.56/protobuf-net.Core.dll`
   (any net-standard target — Cecil reads metadata only)
3. Run: `fixtures/scan-protobuf-net/run`
