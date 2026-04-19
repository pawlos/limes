# Milestone C — Tech choice + MVP taint analyzer

**Status:** Approved 2026-04-19 (awaiting post-write review before execution).
**Predecessors:**
- Milestone 1 (`2026-04-16-imagesharp-3074-trace-design.md`) — pre-fix #3074 ground-truth trace.
- Milestone B (`2026-04-17-imagesharp-3074-postfix-trace-design.md`) — post-fix #3074 trace, schema v0.1.
- Milestone A (`2026-04-17-imagesharp-3079-trace-design.md`) — pre/post #3079 trace, schema v0.2.
**Successor:** Milestone D and beyond — extending the analyzer to cover #3079, async decoders (O3), Part-2 symbex / PoC-input generation.

## Context

Milestones 1, B, and A produced four ground-truth fixtures (#3074 pre/post, #3079 pre/post) and a fixture validator enforcing schema v0.2. The fixtures define what the analyzer **should** emit; the validator checks conformance. Milestone C is the first time we build the analyzer itself — the artifact that reads a target assembly and produces a trace without human authoring.

The spec covers two coupled decisions:
1. **Tech stack.** Cecil (Mono.Cecil), chosen over Roslyn (source-level, misses IL semantics and async state machines), dnlib (Cecil fork for obfuscated IL, unnecessary robustness for ImageSharp), and ILLink (trimmer API is round-tripping, not read-only analysis). Cecil is MIT, NuGet-stable, ships with PDB support, is the standard .NET binary-analysis library (ILRepack, Fody, decompilers), and keeps the door open for Part-2 symbex integration (IL is what executes; source-level constraints are a lie).
2. **MVP scope.** Analyzer reproduces the #3074 pre-fix and post-fix fixtures end-to-end. Reproducing both proves (a) it finds unsafe paths and (b) it correctly recognises the sanitizer on fixed code. Both are needed for falsifiability.

## Goals

1. New console project `tools/TaintAnalyzer/` that reads a target DLL + PDB + a minimal `rules.yaml` and emits a `trace.yaml` conforming to schema v0.2.
2. Validator extension `ValidateFixture --compare <ground-truth.yaml> <analyzer-output.yaml>` with new diagnostics FX060/FX061/FX062/FX063 for source / sink / sanitizer-absence / sanitizer-hop mismatches.
3. Demonstrate success on the #3074 pre-fix AND post-fix assemblies.
4. Establish the analyzer's tech foundation for future milestones: the Cecil-based loader, call-graph builder, and intra-method taint walker are reusable components.

## Non-goals

- **#3079 reproduction.** `span_access` sink and `return_early` sanitizer are out of scope for C's success criteria. If the analyzer handles them easily, great; if not, they become milestone D.
- **Async / `MoveNext` modelling** (O3). Still unexercised schema-wise. Deferred.
- **NativeAOT specialization** of generics. Target is regular IL.
- **Part-2 symbex / PoC-input generation.** Cecil was chosen partly to accommodate it later; C doesn't start it.
- **Roslyn edit-time wrapper / IDE integration.** Deferred.
- **Rules extensibility beyond `source_methods`.** Sinks and sanitizer shapes are hardcoded for MVP.
- **Analysis of assemblies outside the analyzed set.** Anything crossing into CoreLib is `closure_boundary: true`.

## Architecture

### Project layout

```
tools/
  ValidateFixture/              (existing — validator + --compare mode added)
  ValidateFixture.Tests/        (existing)
  TaintAnalyzer/                (NEW — console app, Cecil-based analyzer)
  TaintAnalyzer.Tests/          (NEW — xUnit + sample-assembly tests)
```

Both new projects target net10.0, align with existing codebase conventions (namespace `TaintAnalyzer.*`), use Mono.Cecil 0.11.x (latest stable NuGet) and YamlDotNet 15.1.6 (matches validator).

### Components (five units, each with one responsibility)

1. **`RulesDocument.cs`** — POCO loaded from `rules.yaml` via YamlDotNet. Fields:
   ```csharp
   public sealed class RulesDocument
   {
       public string? VulnId { get; init; }
       public List<string>? SourceMethods { get; init; }  // FQ method patterns
   }
   ```
   Sink opcodes/targets and sanitizer IL-shape patterns are NOT in the rules file — they live in code (see `SinkShapes.cs`, `SanitizerShapes.cs`).

2. **`AssemblyContext.cs`** — wraps a `Mono.Cecil.AssemblyDefinition` loaded with `ReaderParameters { ReadSymbols = true }` so PDB sequence points are available for file:line emission. Provides lookups by FQ method name.

3. **`CallGraph.cs`** — given an `AssemblyContext` + set of entry methods, builds a direct-call graph. For `callvirt` instructions, compute CHA closure within the analyzed assembly: resolve to every override of the virtual method whose declaring type derives from the static call-site type. Sealed classes resolve to exactly one target (matches the fixture convention from #3074 hop 2). Calls into unanalyzed assemblies (e.g., `System.IO.Stream.Read`) set `closure_boundary: true` with empty `resolved_targets`.

4. **`TaintWalker.cs`** — the core analysis.
   - Intra-method: forward pass over method body instructions. Start with the source's Stream-like parameter marked tainted. Propagate: `stloc` preserves taint, `ldloc` reads it, `ldfld`/`ldsfld` on a tainted struct/object produces a tainted value (`field_load` transformation), arithmetic on tainted + constant produces tainted (`arithmetic` transformation), etc. Stack-slot tracking via a symbolic stack.
   - Sanitizer dispatch: scan instruction windows for `SanitizerShapes` patterns; when matched, record the sanitizer hop and continue propagation with the tainted value marked "post-sanitizer" (the walker doesn't fold-forward bound state; it just records the sanitizer hop for the trace).
   - Sink dispatch: when an instruction is a sink shape AND its critical argument (size for allocation, index/slice-args for span_access) is a tainted stack slot, record as sink.
   - Cross-method: when a tainted value is passed to a callee (argument index tracked), recursively analyze the callee with that parameter tainted. Memoize by `(MethodReference, tainted-param-bitmask)` to avoid re-analysis.
   - Output: an ordered list of `HopRecord`s from source method to sink.

5. **`TraceEmitter.cs`** — converts `HopRecord`s to a `trace.yaml` string via YamlDotNet serializer. Populates `source`, `sink`, `path`, `sanitizer_absence` per schema v0.2. For pre-fix traces (no sanitizers detected), `sanitizer_absence` is synthesized as a single entry pointing at the sink's location with an `expected_check: "<inferred-by-analyzer>"` placeholder; for post-fix traces (sanitizers detected), `sanitizer_absence: []`.

### Hardcoded shape matchers

**`SinkShapes.cs`** — three matchers, one method each:
- `MatchNewArr(Instruction, SymbolicStack)` → allocation / new_array sink when `Instruction.OpCode == OpCodes.Newarr` and the size arg on the stack top is tainted.
- `MatchArrayPoolRent(Instruction, SymbolicStack)` → allocation / array_pool_rent sink when the instruction is `call System.Buffers.ArrayPool<T>::Rent(int)` with the arg tainted.
- `MatchReadOnlySpanSlice(Instruction, SymbolicStack)` → span_access / span_slice sink when the instruction is `call System.ReadOnlySpan<T>::Slice(int, int)` with either arg tainted.

Extending: add a new method to `SinkShapes.cs` when a future fixture requires it.

**`SanitizerShapes.cs`** — two matchers initially (clamp deferred):
- `MatchCompareAndThrow(InstructionWindow)` → the IL sequence `ldarg/ldloc/ldfld on tainted value; ldarg/ldloc/ldfld/ldc; one of {bgt, bgt.un, blt, blt.un, beq, bge, ble, bne}; <body>; call <ThrowHelper>::Throw*; [throw]`. Emits a sanitizer hop with `on_failure: throw`, `exception: <resolved from call>`, and `establishes_bound` inferred from the comparison (operator and the compared expression).
- `MatchCompareAndReturnEarly(InstructionWindow)` → similar but with `ret` instead of `throw`. Emits `on_failure: return_early`.

Bound extraction: inspect the comparison's operands. If the comparison is `left > right` and the branch-to-throw/return means "fail if left > right", then the fall-through establishes `left <= right`. Map:
- `bgt/bgt.un + throw/return` → `relation: "<="`, `upper_bound: right`.
- `blt/blt.un + throw/return` → `relation: ">="`, `lower_bound: right`.
- `bge + throw/return` → `relation: "<"`, `upper_bound: right`.
- `ble + throw/return` → `relation: ">"`, `lower_bound: right`.
- `beq + throw/return` → `relation: "!="`, `upper_bound: right` (or lower — single value).
- `bne + throw/return` → `relation: "=="`, `upper_bound: right`.

Compound conditions (`A < 0 || A + 4 > data.Length` — open question O5) collapse to the second condition's bound; full check text preserved in the hop's `note:`.

### CLI

**TaintAnalyzer:**
```
TaintAnalyzer <target.dll> --rules <rules.yaml> [--output <trace.yaml>]
```
Exit codes: 0 = trace emitted; 1 = IO/parse/analysis error; 2 = usage error.

**ValidateFixture extension:**
```
ValidateFixture --compare <ground-truth.yaml> <analyzer-output.yaml>
```
Exit codes: 0 = equivalence; 1 = mismatch (FX060+ diagnostics printed); 2 = malformed fixture.

### Validator `--compare` semantics

Checks, in order, emitting diagnostics on mismatch:
- **FX060** `source mismatch`: `source.method` and `source.file:line` must be identical across the two fixtures.
- **FX061** `sink mismatch`: `sink.method`, `sink.file:line`, `sink.kind`, `sink.api` must match.
- **FX062** `sanitizer_absence mismatch`: array length must match; each entry's `tainted_value` and `expected_check`-substring (first 40 chars) must match.
- **FX063** `sanitizer hop mismatch`: for each sanitizer hop in the ground truth, the analyzer's output must have a sanitizer hop at the same `file:line` with matching `establishes_bound.target`.

Intermediate propagator hops are NOT compared — reports the count delta as an informational note, never as a failure.

### Success criteria

1. `tools/TaintAnalyzer/` builds clean; xUnit tests at `tools/TaintAnalyzer.Tests/` pass (at least: one test for rules-loader, one for call-graph-builder on a synthetic assembly, one for a sanitizer-shape matcher against a hand-crafted IL snippet).
2. `ValidateFixture --compare` accepts valid input pairs; new tests (FX060/FX061/FX062/FX063) covering mismatch cases all pass.
3. `TaintAnalyzer <ImageSharp.dll-built-from-pre-fix-parent> --rules rules-3074.yaml --output /tmp/out.yaml`, then `ValidateFixture --compare fixtures/imagesharp-3074-prefix/trace.yaml /tmp/out.yaml` → exit 0.
4. Same on post-fix. Compare against `fixtures/imagesharp-3074-postfix/trace.yaml` → exit 0.
5. Existing 34 fixture-validator tests still pass. Build clean.
6. Shared ImageSharp clone untouched; all build artifacts live under isolated `/tmp/` or a new `artifacts/` directory in the analyzer repo.

## Design tradeoffs (explicitly flagged for review)

- **Intra-method state tracking** uses a simple forward pass over instructions with a symbolic stack. Adequate for #3074's straightforward flow (`stream` → `this.fileHeader` → `this.fileHeader.Value.Offset` → subtraction → `new byte[]`). If a future bug fixture has branches where taint diverges and re-converges (join points), we'll upgrade to a worklist algorithm over the method's CFG. Not anticipated for #3074.
- **Sanitizer `establishes_bound` extraction** is done at IL level. For #3074's single sanitizer (`if (this.fileHeader.Value.Offset > stream.Length) throw`), the comparison is `ldarg/ldfld + ldarg/ldlen + bgt.un + ThrowHelper`. Operator mapping above handles this. Complex expressions (`data.Length - 4`) are emitted as concatenated operand names (e.g., `"data.Length - 4"` reconstructed from the IL `sub` preceding the comparison); reasonable for MVP, may be imprecise for more complex bounds.
- **CHA closure scope** matches the fixture convention: closure is within the analyzed assembly set. For MVP we analyze only the single ImageSharp DLL passed on the command line. Transitive dependencies (`SixLabors.ImageSharp.IO`, etc. if ever split into separate assemblies) are treated as `closure_boundary: true`.
- **Line-number fidelity** depends on PDB sequence points, which depend on compilation flags. We will build ImageSharp in `Debug` mode from the pre-fix and post-fix commits; `Release`/`Optimize` removes sequence points for some locals and reorders instructions. If `Debug` builds also differ from our fixture's lines, the fixture was authored against a specific snapshot and may need regeneration. Flag as a risk; mitigate via explicit build-config documentation.

## Operational concerns (not code scope, but affect execution)

- **Building ImageSharp at specific commits.** The analyzer needs a DLL built from each of the pre-fix parent commit (`67bac23cff7c32743d0c8e166e9cccbf567837e0`) and the fix-merge commit (`461c021608802370374afabd5d3c2720b3e46f04`). Proposed mechanism:
  - Create two `git worktree` directories as COPIES of the shared clone (do not modify the shared clone itself; we copy per the existing policy).
  - Check out the respective commits in each copy.
  - Run `dotnet build -c Debug` in each copy's `src/ImageSharp/`.
  - Reference the resulting `bin/Debug/net*/SixLabors.ImageSharp.dll` + `.pdb` from the analyzer invocation.
  - A small PowerShell/Bash script (`scripts/materialize-imagesharp-3074.sh`) automates this; documented but not code-scope of the analyzer itself.
- **PDB availability.** ImageSharp's standard build emits portable PDBs (default for recent .NET SDKs). Cecil reads these via `ReaderParameters { ReadSymbols = true }`. Fallback: if PDBs are absent, the analyzer emits `line: 0` and the validator's `--compare` mode reports mismatch — forces the user to produce PDBs.

## Open questions — carry forward (not blocking C)

- **O2** — aggregate-to-scalar modelling. Analyzer's `field_load` + `arithmetic` split will mirror the fixture's convention. Still marginally clunky.
- **O3** — async / `MoveNext`. Not exercised; if the analyzer encounters an async method in the #3074 call graph (unlikely — BMP decode is sync), we'll abort with a clear error.
- **O4** — `Nullable<T>.Value`. Same as O2. Modelled as `field_load`.
- **O5** — compound sanitizer conditions. Collapse to meaningful single bound.
- **O6 (provisional)** — indirect bound safety for span indexing. Surfaced during A10 review; not formalized. If the analyzer's forward-folding (which we're NOT doing in MVP — the trace just records what the sanitizer establishes) needs to derive `safe(data[zeroIndexKeyword + 1])` from `zeroIndexKeyword <= data.Length - 4`, that's symbolic reasoning beyond our scope. MVP: emit the sanitizer hop, let downstream analysis worry about the implication.

## Execution plan outline

(Full plan authored in the writing-plans step.)

1. Scaffold `tools/TaintAnalyzer/` and `tools/TaintAnalyzer.Tests/` projects; add to solution; pin Mono.Cecil.
2. `RulesDocument.cs` + loader + tests.
3. `AssemblyContext.cs` loader + a synthetic test assembly + tests.
4. `SinkShapes.cs` matchers + tests against hand-crafted IL.
5. `SanitizerShapes.cs` matchers + tests against hand-crafted IL.
6. `CallGraph.cs` builder + tests.
7. `TaintWalker.cs` (the bulk of the work) — intra-method pass, cross-method recursion with memoization, sanitizer dispatch, sink dispatch.
8. `TraceEmitter.cs` + tests.
9. CLI wiring for `TaintAnalyzer`.
10. Validator `--compare` mode + FX060/FX061/FX062/FX063 tests.
11. Build script: `scripts/materialize-imagesharp-3074.{sh,ps1}` — clones/worktrees the shared clone, checks out pre-fix and post-fix commits, builds Debug.
12. End-to-end: run analyzer on both builds; compare against ground-truth fixtures; both exit 0.
13. Final cross-check.
