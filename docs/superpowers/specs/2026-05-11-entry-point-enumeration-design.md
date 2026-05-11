# Entry-point enumeration — design

**Status:** approved (2026-05-11)
**Author:** Pawel Lukasik
**Target milestone:** next (post-milestone-P)

## Problem

Limes currently requires a hand-written `rules.yaml` per target library naming the source method explicitly (e.g., `MessagePackReader::ReadDateTime(...)`). That assumes the analyst already knows where attacker-controlled data enters. The MessagePack-CSharp finding (2026-05-07) was discovered by human inspection following a known advisory; the analyzer corroborated but did not lead. A true scanner mode must surface candidate entry points from an assembly without prior knowledge of the bug shape.

## Goal

Add a `--scan` mode to `TaintAnalyzer` that enumerates candidate decoder entry points from an assembly using signature-shape and type-name heuristics, then drives the existing `TaintWalker` over each. The user runs one command against a NuGet binary and gets back trace files for any candidate that reaches a sink — no hand-written rules needed.

Non-goals: replacing `--rules` (kept as-is); broadening sink coverage to non-DoS classes (separate effort, planned next); detecting reflection-reachable entry points.

## Decisions

| Decision | Value |
|---|---|
| Output mode | Two flows: `--scan` (auto-walk + traces) and `--scan --emit-rules <path>` (write rules.yaml and exit, no walking). |
| Shape coverage | Parameter-shape always on; this-field shape opt-in via `--include-this-field`. |
| Visibility | Public methods + internal methods reachable from a public method (reverse call graph). Private/protected/PrivateProtected/InternalsOrProtected always rejected. |
| Source-type list | Configurable via `--enumerator-config <yaml>`; sensible defaults baked in. |
| Progress output | Off by default; `--progress` flag enables stderr diagnostics. |
| Empty-scan behaviour | `--emit-rules` with zero candidates writes a YAML file with `source_methods: []` and a comment header. |

## Architecture

### New files

```
tools/TaintAnalyzer/
  EntryPointEnumerator.cs    pure function: (AssemblyContext, EnumeratorConfig) -> IEnumerable<SourceMethodEntry>
  EnumeratorConfig.cs        POCO + YAML loader with Default static + Load(yaml) method
  ReverseCallGraph.cs        one-pass call-edge index with IsReachableFromPublic(method) lookup
```

### Modified files

- `Program.cs` — add `--scan`, `--include-this-field`, `--enumerator-config`, `--emit-rules`, `--progress` flags. Dispatch: `--scan --emit-rules` writes file and exits; `--scan` (no `--emit-rules`) builds the source list via the enumerator and walks; `--rules` reads it from disk and walks. The walking path is shared.
- `RulesDocument.cs` — small relaxation: `RulesDocument.Load` now accepts `source_methods: []` (empty list). Missing key still errors. Reason: round-tripping the enumerator's "no candidates found" output.
- `TraceEmitter.cs` / new `RulesYamlEmitter` — a new helper alongside `TraceEmitter` serialises a `List<SourceMethodEntry>` to YAML for `--emit-rules`.

### Data flow

```
DLL --> AssemblyContext.Load
    --> EntryPointEnumerator.Enumerate(ctx, cfg)
        |                                            (--emit-rules path) --> RulesYamlEmitter --> rules.yaml
        v
        List<SourceMethodEntry>
        |
        v
        TaintWalker (per entry, existing flow)  --> trace YAML
```

### Public API surface

`EntryPointEnumerator` and `EnumeratorConfig` are public on the `TaintAnalyzer` assembly so the test project can drive them without invoking the walker. Nothing else changes.

## Enumeration heuristic

For each `MethodDefinition` in the target assembly, decide candidacy in this order: hard filters → candidate predicates → visibility filter → de-duplication.

### Hard filters (always reject)

- Compiler-generated: `[CompilerGenerated]` attribute, types starting with `<>c__`, `<Name>d__N` async state machines, `<Name>g__*` local functions, `<PrivateImplementationDetails>` types.
- Special methods: `.ctor`, `.cctor`, `op_*` operators, property getters/setters, event accessors.
- Methods with no body: abstract, P/Invoke (`extern`), `runtime` implementations.

### Candidate predicates (a method is a candidate if ANY fires)

1. **Parameter-shape** (always on)
   The method has at least one parameter whose type matches `EnumeratorConfig.ByteSourceTypes`. Matching rules:
   - Direct match against the parameter type's Cecil `FullName`.
   - Base-type walk for `Stream`: a parameter typed `FileStream`/`MemoryStream`/etc. counts because Cecil's `Resolve()` lets us walk the base chain looking for any configured byte-source type.
   - Generic instantiations: `ReadOnlySpan<byte>` matches when the parameter's `FullName == "System.ReadOnlySpan\`1<System.Byte>"`.
   - Modifiers (`out`, `ref`, `in`) are ignored — we check the underlying type only. Mildly over-recalling on `out Stream` is acceptable; the walker won't taint an out-parameter that's never read.

2. **This-field shape** (only with `--include-this-field`)
   The method is an instance method on a type whose name matches `EnumeratorConfig.DecoderTypeNamePatterns` (default: `*Reader`, `*Decoder`, `*Deserializer`, `*Parser`), AND the declaring type has at least one field (including private/internal) whose type matches `ByteSourceTypes`. The matched field names are emitted as `seed_this_fields:` on the entry. **No parameter constraint** — parameterless or state-only methods qualify, which catches the protobuf-net `ImplReadString(State&, Int32)` shape where the source lives on `this._inputStream`.

### Visibility filter (applied after predicates)

| Visibility | Outcome |
|---|---|
| `Public` | Always pass |
| `Assembly` (internal) | Pass if `ReverseCallGraph.IsReachableFromPublic(method) == true` |
| `Family` (protected) | Reject (known gap: subclassable, but rare in decoder libraries) |
| `FamilyOrAssembly` (protected internal) | Reject |
| `FamilyAndAssembly` (private protected) | Reject |
| `Private` | Reject |

### De-duplication

Entries are keyed by `signature` (the Cecil short-signature form `RulesDocument` already uses for lookup). If parameter-shape and this-field-shape both fire for the same method, parameter-shape wins — the entry has no `seed_this_fields:` because the walker can seed taint via the parameter directly.

### Emitted entry shape

- Always: `signature` (Cecil short form).
- This-field branch only: `seed_this_fields:` listing the matching field names.
- Never emitted automatically: `taint_from_external_returns` (no signature-level signal; user hand-edits if needed).

## CLI surface

### New flags

| Flag | Argument | Constraint | Meaning |
|---|---|---|---|
| `--scan` | (none) | Mutually exclusive with `--rules` | Enable enumeration |
| `--include-this-field` | (none) | Requires `--scan` | Enable this-field candidate predicate |
| `--enumerator-config` | path | Requires `--scan` | Override the baked-in defaults |
| `--emit-rules` | path | Requires `--scan` | Write enumerated list to rules.yaml at `path` and exit. Walker is NOT invoked. |
| `--progress` | (none) | Works in both `--scan` and `--rules` modes | Emit stderr diagnostics |

### Existing flags (unchanged)

`--rules`, `--output`, `--no-symbols`.

### Validation rules

- Exactly one of `{--rules, --scan}` must be present.
- `--include-this-field`, `--enumerator-config`, `--emit-rules` without `--scan` → usage error with hint.
- `--emit-rules` is terminal: it writes the rules file and exits. Combining `--emit-rules` with `--output` is a usage error (the walker isn't invoked, so there's no trace to write). User who wants both: `--scan --emit-rules x.yaml`, then re-run with `--rules x.yaml --output trace.yaml`.

### Invocation examples

```sh
# Existing: explicit rules
TaintAnalyzer target.dll --rules rules.yaml --output trace.yaml

# Cold scan — fully automated
TaintAnalyzer target.dll --scan --output trace.yaml --progress

# Cold scan with broader heuristic + audit step
TaintAnalyzer target.dll --scan --include-this-field --emit-rules generated.yaml
# (writes generated.yaml and exits — no walking)
# User reviews / prunes generated.yaml, then:
TaintAnalyzer target.dll --rules generated.yaml --output trace.yaml
```

### Exit codes

- `0` — success (any number of findings or none)
- `1` — runtime error (bad DLL, can't load symbols, walker crash on all candidates)
- `2` — usage error

### `--progress` output format

To stderr, plain text, greppable. Format is diagnostic — not parseable JSON, not an API:

```
[scan] enumerated 127 candidates from 9842 methods (412ms)
[scan] walking 1/127: ProtoBuf.ProtoReader::ReadString() (3ms)
[scan] walking 2/127: ProtoBuf.ProtoReader/State::ReadBytes(System.Int32) (8ms)
...
[scan] complete: 3 findings across 127 candidates (4218ms)
```

## `enumerator-config.yaml` schema

All keys optional. Missing keys → baked-in defaults. Present keys → **replace** (not merge) defaults.

```yaml
# Byte-source types — Cecil FullNames. Base-type walk for Stream is automatic.
byte_source_types:
  - System.IO.Stream
  - System.IO.BinaryReader
  - System.Byte[]
  - System.ReadOnlySpan`1<System.Byte>
  - System.ReadOnlySequence`1<System.Byte>
  - System.Memory`1<System.Byte>
  - System.ReadOnlyMemory`1<System.Byte>

# Type-name patterns for this-field-shape (only consulted with --include-this-field).
decoder_type_name_patterns:
  - "*Reader"
  - "*Decoder"
  - "*Deserializer"
  - "*Parser"

# Glob on declaring type's Namespace. Applied AFTER candidate predicates.
exclude_namespaces:
  - "System.*"
  - "Microsoft.*"

# Glob on declaring type's Name (not FullName).
exclude_type_patterns:
  - "*Test*"
  - "*Mock*"

# Glob on method name.
exclude_method_patterns:
  - "ToString"
  - "GetHashCode"
  - "Equals"
```

### Override examples

```yaml
# Scan into System.* and Microsoft.* (e.g., scanning a custom CoreFX build)
exclude_namespaces: []
```

```yaml
# Allow System.* but strip Microsoft.*
exclude_namespaces:
  - "Microsoft.*"
```

### Glob semantics

Simple `*` wildcard only, matched against the full segment. No `?`, no character classes, no `**`. Keeps the matcher five lines and avoids regex ambiguity. If regex becomes necessary, we add a `regex:` prefix as a separate path.

### Not configurable

- The hard filters — these are correctness invariants, not policy.
- The visibility rule — too foundational; promote to CLI flag if ever needed.
- The candidate-predicate logic itself — config tunes inputs to the algorithm, not the algorithm.

### Loading rules

- `EnumeratorConfig.Default` — static, baked-in.
- `EnumeratorConfig.Load(string yaml)` — parses; raises `EnumeratorConfigException` on malformed input (mirrors `RulesDocumentException`).
- Unknown keys → ignored (forward compatible).
- Empty file → equivalent to `Default`.

## Edge cases

- **Async state machines:** the enumerator emits the user-facing method, never `<Name>d__N::MoveNext`. The existing `AsyncStateMachineResolver` (driven by `Program.cs`) handles bridging when the walker starts. Hard filter rejects compiler-generated types — no other change needed.
- **Generic methods/types:** Cecil's FullName disambiguates them; `RulesDocument.FindMethod` already handles the lookup. No special case.
- **Multiple byte-source parameters:** one candidate per method; the walker seeds all parameters as tainted via the existing `bitmask = (1 << count) - 1`.
- **Reverse call graph cost:** one pass over every method body counting `call`/`callvirt`/`newobj` operands. Built eagerly when `--scan` is used (always needed for internal visibility). Memoised on `AssemblyContext` (lazy-built).
- **`[InternalsVisibleTo]` reachability:** we only scan the target assembly. Methods reached only by a friend assembly will be rejected as unreachable. Documented limitation; workaround is `--scan` the friend assembly too or hand-write a rules.yaml.
- **Call graph cycles:** reachability is the transitive closure from the union of all public methods (single BFS); cycles are handled trivially.
- **Walker errors during scan:** if one candidate's walk throws, log to stderr and continue. Exit code remains 0 if at least one candidate walked successfully.
- **`--emit-rules` round-trip:** the emitted YAML must be parseable by `RulesDocument.Load`. Tested. Requires a small relaxation to `RulesDocument.Load`: an empty `source_methods: []` list must be accepted (today it errors with `"source_methods is empty"`). A missing key is still rejected. Behaviour for hand-written rules with no entries was already a usage error and remains practically useless, but the validator is now liberal in what it accepts.
- **`vuln_id` in emitted rules.yaml:** emit `vuln_id: scan-<assembly-name>` as a structurally-complete placeholder.
- **Empty scan output:** when 0 candidates survive, `--emit-rules` writes a YAML file with `source_methods: []` and a comment header noting the assembly name and scan parameters. The file round-trips through `RulesDocument.Load` (per the relaxation above) but a subsequent `--rules <empty>` run is also a no-op — analyzer walks zero entries and exits 0.

## Testing

### Unit tests (`tools/TaintAnalyzer.Tests/EntryPointEnumeratorTests.cs`)

1. **Hard filters:** synthetic assembly with `<>c__DisplayClass`, `MoveNext` on `<X>d__0`, `.ctor` taking `Stream`, abstract methods, P/Invoke → enumerator emits nothing.
2. **Parameter-shape matching:**
   - `public void Read(Stream s)` → matched
   - `public void Read(FileStream s)` → matched (base-type walk)
   - `public void Read(ReadOnlySpan<byte> s)` → matched
   - `public void Read(string s)` → NOT matched (default config)
   - `public void Read(ReadOnlySpan<int> s)` → NOT matched (generic-arg discriminates)
3. **This-field shape:** synthetic `MyReader` with `Stream _input` field + `public string ReadString()`. With `--include-this-field`: matched, emits `seed_this_fields: [_input]`. Without: not matched.
4. **Visibility filter:**
   - `public void A(Stream)` — emitted
   - `internal void B(Stream)` called by `A` — emitted (reachable)
   - `internal void C(Stream)` called by nothing — rejected
   - `private void D(Stream)` — rejected
   - `protected void E(Stream)` — rejected
5. **De-duplication:** type matching both predicates → one entry, no `seed_this_fields`.
6. **Round-trip:** enumerate → `RulesYamlEmitter` → `RulesDocument.Load` → `SourceMethods` matches.
7. **Reverse call graph:** cycles, virtual dispatch (overrides reachable), no-op assemblies.
8. **Config loading:** empty file = defaults; partial override preserves other defaults; malformed YAML → `EnumeratorConfigException`; unknown keys ignored.

### Fixture-driven validation (`tools/ValidateFixture.Tests/`, extend)

Two existing wins must be replicable without a hand-written rules.yaml — this is the proof the feature works:

1. **protobuf-net** (`experiments/protobuf-net/`) — current rules.yaml targets `ImplReadString` (internal). New fixture `fixtures/scan-protobuf-net/` locks the enumerator output: running `--scan --include-this-field` on protobuf-net.dll must include `ImplReadString` in the emitted source list.
2. **MessagePack-CSharp** (per `docs/nbmp-mpcs-datetime-stackalloc-2026-05-07.md`) — the `MessagePackPrimitives.TryRead` finding. Likely findable by parameter-shape (`ReadOnlySpan<byte>` signature). New fixture `fixtures/scan-mpcs/`.

Both regression-tested via the existing `--compare` mechanism.

### Anchors (per gap-backlog memory)

Must remain green:
- All current unit tests (currently 168)
- All locked fixtures: `imagesharp-307{4,9}-{prefix,postfix}`, `otelcontrib-{55m9,vc24,opamp-w2jh,aws-fp-fixed}-*`, `nbmp-2cwq-pwfr-wcw3-{prefix,postfix}`, synthetic + parquet fixtures.

Nothing in this feature touches `TaintWalker`/`SinkShapes`/`SanitizerShapes`, so anchors should be unaffected by construction.

### Performance baseline (informal)

Capture a wall-clock number for `--scan` on a moderate NuGet binary (e.g., Newtonsoft.Json or System.Text.Json, ~10k methods). No hard threshold — 60s is fine. Profile only if results are surprising (minutes).

## Open questions resolved during brainstorming

- **Should internal methods be enumerated?** Yes, but only when reachable from a public method via a reverse call graph. Captures library-author idiom of "thin public wrapper → internal helper does the work" without producing findings for orphaned internals.
- **Should the enumerator be a sibling tool?** No. Subcommand mode on the existing CLI (one binary, one arg parser). Enumerator code is library-internal but tested as a pure function.
- **Should `enumerator-config.yaml` be optional?** Yes — baked-in defaults; config file overrides.

## Out of scope (future work)

- SQL-injection / path-injection / command-injection sink classes. Planned as the next feature once this is shipped.
- Enumeration across multiple assemblies in one invocation. Today: one `--scan` per DLL.
- Heuristics beyond signature shape (e.g., HTTP attribute detection, MVC controller actions).
