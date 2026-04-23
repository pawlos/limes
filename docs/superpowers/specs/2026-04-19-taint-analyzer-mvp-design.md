# Milestone C — Tech choice + MVP taint analyzer

**Status:** Approved 2026-04-19; revised 2026-04-23 after design review.
**Revision 2026-04-23:** Design-review findings folded in — flow-type narrowing in CallGraph, `stfld` + object-field-taint in TaintWalker, explicit branch-direction + throw-helper predicate in SanitizerShapes, `sanitizer_absence` synthesis rules clarified, rules-file signature form + rules-file location fixed, `--compare` metadata treatment + diagnostic format specified, shallow-clone-aware materialization via `git archive`, expanded unit-test expectations. See "Revision history" at the bottom.
**Predecessors:**
- Milestone 1 (`2026-04-16-imagesharp-3074-trace-design.md`) — pre-fix #3074 ground-truth trace.
- Milestone B (`2026-04-17-imagesharp-3074-postfix-trace-design.md`) — post-fix #3074 trace, schema v0.1.
- Milestone A (`2026-04-17-imagesharp-3079-trace-design.md`) — pre/post #3079 trace, schema v0.2.
**Successor:** Milestone D and beyond — extending the analyzer to cover #3079 if the C-bonus check fails, async decoders (O3), Part-2 symbex / PoC-input generation.

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

- **#3079 reproduction as a required success criterion.** `span_access` sink and `return_early` sanitizer are out of scope for C's *required* success criteria. The analyzer will be re-run against the #3079 pre-fix fixture unmodified as a bonus check (success criterion 7): if it reproduces the ground truth with no component changes, #3079 is covered. Any component change required to reproduce #3079 defers it to milestone D.
- **Async / `MoveNext` modelling** (O3). Still unexercised schema-wise. Deferred. Rules target the sync `Decode` overload only to avoid accidental entry into async state machines.
- **NativeAOT specialization** of generics. Target is regular IL.
- **Part-2 symbex / PoC-input generation.** Cecil was chosen partly to accommodate it later; C doesn't start it.
- **Roslyn edit-time wrapper / IDE integration.** Deferred.
- **Rules extensibility beyond `source_methods`.** Sinks and sanitizer shapes are hardcoded for MVP.
- **Analysis of assemblies outside the analyzed set.** Anything crossing into CoreLib is `closure_boundary: true`.
- **Points-to analysis for non-`this` object-field taint.** MVP only tracks taint on fields of `this` (cross-method via per-method summaries). Tainting a field on a non-`this` object argument is not supported; anticipated for some future fixture but not #3074 or #3079.

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
       public List<string>? SourceMethods { get; init; }  // FQ method signatures
   }
   ```
   If `VulnId` is omitted from rules, the analyzer emits traces without a `vuln_id` key (YAML-absent, not empty string); `--compare` ignores the field either way (see Validator `--compare` semantics). `SourceMethods` is required — missing or empty is a startup error.

   `SourceMethods` entries use a signature form compatible with Cecil's `MethodReference.FullName`: fully-qualified `Namespace.Type::Method(ParamType1,ParamType2,…)` with no spaces and canonical type names. Generic arity on type names uses Cecil's grave-accent-plus-integer convention before any angle-bracketed type arguments. Primitives are spelled as `System.Int32`, `System.Byte`, etc. This disambiguates overloads; in particular, the sync `Decode(BufferedReadStream,CancellationToken)` and the async `DecodeAsync(...)` must be named explicitly — milestone C rules target the sync overload only (deferring O3). Wildcards are **not** supported in MVP; each source must be listed verbatim. Unknown signatures error out at startup with an actionable message naming the nearest resolved candidates.

   Sink opcodes/targets and sanitizer IL-shape patterns are NOT in the rules file — they live in code (see `SinkShapes.cs`, `SanitizerShapes.cs`).

2. **`AssemblyContext.cs`** — wraps a `Mono.Cecil.AssemblyDefinition` loaded with `ReaderParameters { ReadSymbols = true }` so PDB sequence points are available for file:line emission. Cecil auto-detects portable vs. Windows PDB format. Provides lookups by FQ method name.

3. **`CallGraph.cs`** — given an `AssemblyContext` + set of entry methods, builds a direct-call graph. Two-step virtual resolution:

   **Step 1 — flow-type narrowing.** For each `callvirt`, inspect the receiver on the symbolic stack at that instruction. If the receiver traces back to a local whose `VariableDefinition.VariableType` is more specific than the call-site's declaring type (e.g., `Stream.Read` called on a local typed `BufferedReadStream`), use the local's type as the narrowed receiver type. This is the mechanism that resolves #3074 hop 2 to a single target — the fixture explicitly calls out that `BufferedReadStream` is sealed and defined in ImageSharp.

   **Step 2 — CHA closure.** From the (possibly narrowed) receiver type, resolve to every override of the virtual method defined by a type derived from the receiver type **within the analyzed assembly**. Sealed types with exactly one override resolve to exactly one target (`closure_boundary: false`). Types with overrides outside the analyzed assembly (or a non-sealed receiver whose subclass set isn't closed) set `closure_boundary: true` and emit all in-assembly overrides in `resolved_targets` as best-effort. Calls to methods whose declaring type lives in an unanalyzed assembly (e.g., `System.IO.Stream.Read` with no narrowing possible) set `closure_boundary: true` with empty `resolved_targets`.

4. **`TaintWalker.cs`** — the core analysis.
   - **Intra-method taint.** Forward pass over method body instructions, starting with the source's Stream-like parameter marked tainted. Propagate through a symbolic stack and a local-taint map:
     - `stloc`/`ldloc` preserve taint on the local.
     - `ldfld`/`ldsfld` on a tainted struct/object produces a tainted value (`field_load` transformation).
     - `stfld`/`stsfld` with a tainted value on the stack marks the target field as tainted — both on the owning instance (for `this`-rooted fields) and on the static-field slot (for `stsfld`). This is how `this.fileHeader = BmpFileHeader.Parse(buffer)` in `ReadFileHeader` makes `this.fileHeader` tainted for `ReadImageHeaders` to later read.
     - Arithmetic on tainted + constant or tainted + tainted produces tainted (`arithmetic`).
     - `call`/`callvirt` returning a value where any tainted argument is passed propagates taint to the result slot via cross-method analysis (see below).
   - **Object-field taint model.** Taint on `this`-rooted fields (e.g., `this.fileHeader`) is carried as a per-method summary: "if parameter 0 (`this`) is tainted-receiver, on return these fields of `this` are tainted." The cross-method summary in the memo table records both (a) tainted return value, if any, and (b) set of `this`-field names newly tainted. Callers apply (b) to their receiver's field-taint map.
   - **Sanitizer dispatch.** Scan instruction windows for `SanitizerShapes` patterns; when matched, record the sanitizer hop. The walker does NOT fold bound state forward — it just emits the hop in the trace. Taint on the value continues flowing (a sanitizer that bounds a value doesn't clear taint; the trace records the bound-establishment for a downstream consumer to reason about).
   - **Sink dispatch.** When an instruction is a sink shape AND its critical argument (size for allocation, index/slice-args for span_access) is tainted, record as sink.
   - **Cross-method.** When a tainted value is passed to a callee (argument index tracked), recursively analyze the callee with that parameter tainted. Memoize by `(MethodDefinition.FullName, tainted-param-bitmask)` — using `FullName`, not `MethodReference`, so generic instantiations at different call sites share the same summary.
   - **Sequence-point fallback.** For each recorded hop, the emitter needs a `file:line`. If `method.DebugInformation.GetSequencePoint(instruction)` returns null (common for compiler-generated instructions), walk backward through the method's instruction stream to the nearest preceding instruction with a non-hidden sequence point. If none is found, emit `line: 0` and let `--compare` surface it as a mismatch against the ground truth.
   - **Output.** An ordered list of `HopRecord`s from source method to sink.

5. **`TraceEmitter.cs`** — converts `HopRecord`s to a `trace.yaml` string via YamlDotNet serializer. Populates `source`, `sink`, `path`, `sanitizer_absence` per schema v0.2. `vuln_id` is copied from rules; `fix_commit`, `fix_pr`, `description` are omitted (the `--compare` mode ignores them). For pre-fix traces (no sanitizers on the path to the sink), `sanitizer_absence` synthesis is specified under "Validator `--compare` semantics" below — one entry per unsanitized path, `location` at the propagator hop immediately preceding the sink, `expected_check` a derived summary, `present_pre_fix`/`present_post_fix`/`fix_evidence` omitted. For post-fix traces (sanitizer hops present on every path), `sanitizer_absence: []`.

### Hardcoded shape matchers

**`SinkShapes.cs`** — three matchers, one method each:
- `MatchNewArr(Instruction, SymbolicStack)` → `allocation` / `new_array` sink when `Instruction.OpCode == OpCodes.Newarr` and the size arg on the stack top is tainted.
- `MatchArrayPoolRent(Instruction, SymbolicStack)` → `allocation` / `array_pool_rent` sink when the instruction is a `call` to `ArrayPool<T>::Rent(int)` (matched by declaring type `System.Buffers.ArrayPool<T>` with arity 1, method name `Rent`, single `Int32` parameter) with the arg tainted.
- `MatchReadOnlySpanSlice(Instruction, SymbolicStack)` → `span_access` / `span_slice` sink when the instruction is a `call` to `ReadOnlySpan<T>::Slice(int, int)` with either arg tainted.

Extending: add a new method to `SinkShapes.cs` when a future fixture requires it.

**`SanitizerShapes.cs`** — two matchers initially (clamp deferred):
- `MatchCompareAndThrow(InstructionWindow)` → a comparison-plus-conditional-branch whose one side (the "failure body") contains a call to a throw-helper and exits the method; the other side is the fall-through safe path. Emits a sanitizer hop with `on_failure: throw`, `exception: <resolved from the called throw-helper>`, and `establishes_bound` inferred from the comparison operator, branch direction, and the compared operands.
- `MatchCompareAndReturnEarly(InstructionWindow)` → similar but the failure body is `ret` (possibly preceded by an assignment of a default/error value) instead of a throw. Emits `on_failure: return_early`.

**Throw-helper predicate.** A `call`/`callvirt` is a throw-helper target if **all** of: (a) return type is `void`, (b) method name starts with `Throw` (case-sensitive), (c) the declaration is either marked `[DoesNotReturn]` (System.Diagnostics.CodeAnalysis) or its body ends with an unconditional `throw` on every return path. The resolved `exception` in the hop is the static type of the `newobj` passed to the first `throw` in the helper body (for inline helpers) or, as a last resort, the type suffix encoded in the helper's name (e.g., `ThrowInvalidImageContentException` → `InvalidImageContentException`).

**Branch direction + bound extraction.** IL comparisons' branch targets do not reliably correspond to "failure" — Roslyn often emits the *negated* operator, jumping *over* the throw body. The matcher therefore identifies the failure side by structural inspection: of the two branch destinations (taken vs. fall-through), the "failure" side is the one that either (a) transitively reaches a throw-helper call followed by method exit, or (b) is an unconditional `ret` with no further propagation. The other side is the "safe" fall-through.

Once failure/safe sides are identified, the safe-side condition is read off by applying the conditional-branch opcode's truth predicate and flipping it if the "safe" side is the fall-through (not the branch target). Map (columns: IL opcode, predicate when the branch is taken, emitted bound when branch-taken = safe):
- `bgt`/`bgt.un`: `left > right` → `relation: ">"`, `lower_bound: right` (when taken-side is safe) — otherwise fall-through-safe ⇒ `relation: "<="`, `upper_bound: right`.
- `blt`/`blt.un`: `left < right` → `relation: "<"`, `upper_bound: right` / else `relation: ">="`, `lower_bound: right`.
- `bge`/`bge.un`: `left >= right` → `relation: ">="`, `lower_bound: right` / else `relation: "<"`, `upper_bound: right`.
- `ble`/`ble.un`: `left <= right` → `relation: "<="`, `upper_bound: right` / else `relation: ">"`, `lower_bound: right`.
- `beq`: `left == right` → `relation: "=="`, `upper_bound: right` / else `relation: "!="`.
- `bne.un`: `left != right` → `relation: "!="`, `upper_bound: right` / else `relation: "=="`.

In short: pick the safe side by structure, then read off the bound that's true on that side.

Compound conditions (`A < 0 || A + 4 > data.Length` — open question O5) collapse to the second condition's bound; full check text preserved in the hop's `note:`.

### CLI

**TaintAnalyzer:**
```
TaintAnalyzer <target.dll> --rules <rules.yaml> [--output <trace.yaml>]
```
If `--output` is omitted, the trace is written to stdout so the tool composes with shell pipelines. Exit codes: 0 = trace emitted; 1 = IO/parse/analysis error; 2 = usage error.

**ValidateFixture extension:**
```
ValidateFixture --compare <ground-truth.yaml> <analyzer-output.yaml>
```
Exit codes: 0 = equivalence; 1 = mismatch (FX060+ diagnostics printed); 2 = malformed fixture.

### Validator `--compare` semantics

Metadata fields (`vuln_id`, `fix_commit`, `fix_pr`, `description`) cannot be derived from the target assembly — the analyzer either copies `vuln_id` from rules or leaves them empty. `--compare` **ignores** these four fields entirely; they exist only on the ground-truth side for provenance.

Checks, in order, emitting diagnostics on mismatch:
- **FX060** `source mismatch`: `source.method` and `source.file:line` must be identical across the two fixtures.
- **FX061** `sink mismatch`: `sink.method`, `sink.file:line`, `sink.kind`, `sink.api` must match.
- **FX062** `sanitizer_absence mismatch`: array length must match; each entry's `tainted_value` must match; `location` must match file and be within ±2 lines of the ground-truth (the analyzer synthesizes "immediately before the sink-consuming hop"; the human-authored fixture may pick an adjacent line). `expected_check` is **not** compared — the analyzer emits a derived summary (`"<tainted_value> must be bounded before reaching <sink.api> at <sink.file>:<sink.line>"`), the fixture has author prose, and forcing substring equivalence is unjustified. When other FX062 criteria mismatch, `--compare` prints both `expected_check` values as context.
- **FX063** `sanitizer hop mismatch`: for each sanitizer hop in the ground truth, the analyzer's output must have a sanitizer hop at the same `file:line` (exact, no tolerance — a sanitizer *is* a specific check at a specific line; a shifted match is a real mismatch worth surfacing, unlike `sanitizer_absence.location` which is a synthesized "near the sink" waypoint) with matching `establishes_bound.target`, `establishes_bound.relation`, and whichever of `upper_bound`/`lower_bound` is set on the ground truth. `on_failure.kind` must match; `on_failure.exception` must match when `kind: throw`.

Intermediate propagator hops are NOT compared — `--compare` reports the count delta as an informational note, never as a failure.

**Diagnostic format.** Every `--compare` diagnostic is a single line:
```
FXNNN <short category>: <field> expected=<ground-truth value> actual=<analyzer value> [at <file:line> | for hop <n>]
```
Example: `FX061 sink mismatch: line expected=1600 actual=1602 at src__ImageSharp__Formats__Bmp__BmpDecoderCore.cs`.

**TraceEmitter synthesis for pre-fix `sanitizer_absence`.** The analyzer emits one `sanitizer_absence` entry per taint path that reaches a sink without passing through a sanitizer hop. `location` is set to the `file:line` of the propagator hop immediately preceding the sink (not the sink itself — the check belongs before the unsafe consumer). `tainted_value` is the name used in the last-pre-sink hop's `tainted_value_out`. `expected_check` is the derived summary described under FX062. `present_pre_fix`/`present_post_fix`/`fix_evidence` are omitted — those are human-annotation concerns outside the analyzer's knowledge; `--compare` tolerates their absence on the analyzer side.

### Success criteria

1. `tools/TaintAnalyzer/` builds clean. Unit tests at `tools/TaintAnalyzer.Tests/` pass with at least:
   - `RulesDocumentLoaderTests` — valid/invalid YAML; malformed signature form rejected with an actionable error naming nearest candidates.
   - `AssemblyContextTests` — loads a tiny synthetic assembly+PDB fixture (checked in under `tools/TaintAnalyzer.Tests/Fixtures/`), resolves methods by `FullName`, exposes sequence points.
   - `CallGraphTests` — direct calls resolved; virtual calls with flow-type narrowing on a sealed type resolve to one target; virtual calls without narrowing fall back to CHA closure; external-assembly calls set `closure_boundary: true`.
   - `SinkShapesTests` — `newarr`, `ArrayPool.Rent`, and `ReadOnlySpan.Slice` matchers fire on hand-crafted IL; do not fire on similar-but-non-tainted sites.
   - `SanitizerShapesTests` — compare-and-throw with both branch directions (negated vs. non-negated operator) produces the correct `establishes_bound`; throw-helper predicate accepts `Throw*` + `[DoesNotReturn]` methods and rejects plain void methods.
   - `TaintWalkerTests` — on a hand-crafted assembly: taint flows through `stfld`/`ldfld` on `this`; taint survives cross-method via the summary; sanitizer hop recorded but taint continues; sink fires when tainted size reaches `newarr`.
   - `TraceEmitterTests` — round-trips a synthetic `HopRecord` list to YAML matching schema v0.2.

   Test-fixture assemblies are shared across `CallGraphTests`, `SinkShapesTests`, `SanitizerShapesTests`, and `TaintWalkerTests`: a single `tools/TaintAnalyzer.Tests/Fixtures/` directory holds the pre-compiled synthetic `.dll`+`.pdb` pairs plus their C# source for reproducibility. The fixtures project is a sibling csproj (`TaintAnalyzer.Tests.Fixtures.csproj`) built as part of the test run — authored once when first needed, extended per test class as later components require new IL shapes. `AssemblyContextTests` uses the smallest fixture; richer IL shapes accrete in the same directory.
2. `ValidateFixture --compare` accepts valid input pairs; new tests (FX060/FX061/FX062/FX063) covering mismatch cases all pass, including the metadata-field exemption and the ±2-line tolerance on `sanitizer_absence.location`.
3. `TaintAnalyzer <ImageSharp.dll-built-from-pre-fix-parent> --rules fixtures/imagesharp-3074-prefix/rules.yaml --output /tmp/out.yaml`, then `ValidateFixture --compare fixtures/imagesharp-3074-prefix/trace.yaml /tmp/out.yaml` → exit 0.
4. Same on post-fix. Compare against `fixtures/imagesharp-3074-postfix/trace.yaml` → exit 0.
5. Existing fixture-validator tests still pass; build clean.
6. Shared ImageSharp clone untouched; all build artifacts live under isolated `/tmp/` or a new `artifacts/` directory (gitignored) in the analyzer repo.
7. **Bonus (non-blocking):** `TaintAnalyzer` run unchanged against `fixtures/imagesharp-3079-prefix/` built artifacts, compared against that fixture's `trace.yaml`. Exit 0 → #3079 is covered and milestone D scope shrinks. Non-zero → findings feed milestone D as planned; the components that failed are the milestone-D starting points.

## Design tradeoffs (explicitly flagged for review)

- **Intra-method state tracking** is a forward pass over instructions with a symbolic stack, a local-taint map, and a per-method object-field-taint summary on `this`. Adequate for #3074's flow (`stream` → `this.fileHeader` via `stfld` in callee → `this.fileHeader.Value.Offset` via `ldfld` in caller → subtraction → `new byte[]`). Not a worklist/CFG analysis — if a future bug fixture has branches where taint diverges and re-converges at join points, we'll upgrade. Not anticipated for #3074 or #3079.
- **Sanitizer `establishes_bound` extraction** is done at IL level with explicit branch-direction detection (see SanitizerShapes). For #3074's single sanitizer (`if (this.fileHeader.Value.Offset > stream.Length) throw`), the Roslyn-emitted IL will be `ldfld Offset; ldarg stream; callvirt Length; ble.un SAFE; <throw body>; SAFE:` — the matcher identifies the throw body structurally, concludes safe-side = fall-through of the `ble.un`-taken-branch, and emits `relation: "<="`, `upper_bound: stream.Length`. Complex bound expressions (`data.Length - 4`) are reconstructed from the IL `sub`/`ldc` sequence preceding the comparison as concatenated operand names; reasonable for MVP, may be imprecise for multi-term bounds.
- **Virtual-call resolution** combines flow-type narrowing (Step 1) with CHA closure (Step 2) — see CallGraph. Without Step 1, the fixture's hop-2 result (one target, `closure_boundary: false`) is unreachable because the call-site static type is `System.IO.Stream`. MVP analyzes a single ImageSharp DLL passed on the command line; transitive dependencies treated as `closure_boundary: true` per call.
- **Object-field taint propagation** on `this` is cross-method via a summary (`{tainted_return, newly_tainted_this_fields}`) rather than a whole-program points-to analysis. Trades precision for tractability: if a field is tainted via a callee on `this`, every caller of that callee using the same `this` sees the field tainted. Fails when a method taints a field on a non-`this` object argument — explicitly out of scope for MVP; anticipated for some future fixture but not #3074 or #3079.
- **Line-number fidelity** depends on PDB sequence points, which depend on compilation flags. We will build ImageSharp in `Debug` mode from the pre-fix and post-fix commits; `Release`/`Optimize` removes sequence points for some locals and reorders instructions. If `Debug` builds also differ from our fixture's lines, the fixture was authored against a specific source snapshot and may need regeneration against the freshly built snapshot. Flag as a risk; mitigate via explicit build-config documentation and by treating the first end-to-end run as a potential fixture-line-refresh event.

## Operational concerns (not code scope, but affect execution)

- **Building ImageSharp at specific commits.** The analyzer needs a DLL built from each of the pre-fix parent commit (`67bac23cff7c32743d0c8e166e9cccbf567837e0`) and the fix-merge commit (`461c021608802370374afabd5d3c2720b3e46f04`). The shared clone at `/mnt/c/work/dotnet-fuzzing/external/ImageSharp` is **shallow** — `.git/shallow` pins `461c02160` as a boundary (its `%P` is empty). Both commits the spec references have their file trees intact, so materialization is straightforward, but `git clone <shallow>` propagates shallowness and `git worktree add` modifies `.git/worktrees/` inside the shared clone (policy violation). Proposed mechanism:
  - For each commit: `git -C /mnt/c/work/dotnet-fuzzing/external/ImageSharp archive <sha> | tar -x -C artifacts/<sha>/` — produces a pure file tree at `artifacts/<sha>/` with no git metadata, no shallowness, no submodule traversal. Read-only against the shared clone.
  - Run `dotnet build -c Debug src/ImageSharp/ImageSharp.csproj` inside each extracted tree. Debug emits portable PDBs with line-precise sequence points.
  - Reference the resulting `artifacts/<sha>/src/ImageSharp/bin/Debug/net*/SixLabors.ImageSharp.{dll,pdb}` from the analyzer invocation.
  - A small Bash script (`scripts/materialize-imagesharp-3074.sh`) automates this; documented but not code-scope of the analyzer itself. (PowerShell variant deferred — Linux/WSL is the primary execution environment.)
- **Rules file location.** Rules live next to the fixture they describe: `fixtures/imagesharp-3074-prefix/rules.yaml` and `fixtures/imagesharp-3074-postfix/rules.yaml`. Both point at the sync `BmpDecoderCore::Decode` overload only (async deferred per O3).
- **PDB availability.** ImageSharp's standard build emits portable PDBs (default for recent .NET SDKs). Cecil reads these via `ReaderParameters { ReadSymbols = true }` with auto-detection of portable vs. Windows PDB format. Fallback: if PDBs are absent, the analyzer emits `line: 0` and the validator's `--compare` mode reports mismatch — forces the user to produce PDBs.

## Open questions — carry forward (not blocking C)

- **O2** — aggregate-to-scalar modelling. Analyzer's `field_load` + `arithmetic` split will mirror the fixture's convention. Still marginally clunky.
- **O3** — async / `MoveNext`. Not exercised; rules target sync overloads only. If the analyzer encounters an async method in the #3074 call graph (unlikely — BMP decode is sync), we'll abort with a clear error.
- **O4** — `Nullable<T>.Value`. Same as O2. Modelled as `field_load`.
- **O5** — compound sanitizer conditions. Collapse to meaningful single bound.
- **O6 (provisional)** — indirect bound safety for span indexing. Surfaced during A10 review; not formalized. If the analyzer's forward-folding (which we're NOT doing in MVP — the trace just records what the sanitizer establishes) needs to derive `safe(data[zeroIndexKeyword + 1])` from `zeroIndexKeyword <= data.Length - 4`, that's symbolic reasoning beyond our scope. MVP: emit the sanitizer hop, let downstream analysis worry about the implication.

## Execution plan outline

(Full plan authored in the writing-plans step.)

1. Scaffold `tools/TaintAnalyzer/` and `tools/TaintAnalyzer.Tests/` projects; add to solution; pin Mono.Cecil.
2. `RulesDocument.cs` + loader + tests (including signature-form validation).
3. `AssemblyContext.cs` loader + a synthetic test assembly + tests.
4. `SinkShapes.cs` matchers + tests against hand-crafted IL.
5. `SanitizerShapes.cs` matchers (throw-helper predicate + branch-direction detection) + tests.
6. `CallGraph.cs` builder with flow-type narrowing + CHA + tests.
7. `TaintWalker.cs` (the bulk of the work) — intra-method pass (including `stfld` and object-field-taint), cross-method recursion with memoization by `FullName`, sanitizer dispatch, sink dispatch, sequence-point fallback.
8. `TraceEmitter.cs` (including pre-fix `sanitizer_absence` synthesis) + tests.
9. CLI wiring for `TaintAnalyzer` (stdout default, exit codes).
10. Validator `--compare` mode (metadata-field exemption, ±2-line tolerance, unified diagnostic format) + FX060/FX061/FX062/FX063 tests.
11. Build script: `scripts/materialize-imagesharp-3074.sh` — `git archive` extraction for the two pinned commits, `dotnet build -c Debug`. Add `artifacts/` to `.gitignore` in the same step (spec-success criterion #6 requires it to be gitignored; the build script is what first creates the directory).
12. Rules files: `fixtures/imagesharp-3074-{prefix,postfix}/rules.yaml`.
13. End-to-end: run analyzer on both builds; compare against ground-truth fixtures; both exit 0.
14. **Bonus check:** run analyzer against `fixtures/imagesharp-3079-prefix/` built artifacts; compare → decide #3079-is-covered vs. milestone-D-input.
15. Final cross-check.

## Revision history

- **2026-04-19** — Initial spec; approved pending review.
- **2026-04-23** — Post-review revision. Changes:
  - **CallGraph.** Added two-step virtual resolution (flow-type narrowing + CHA closure). Pure CHA on the call-site static type could not reproduce #3074 hop 2's single-target result.
  - **TaintWalker.** Added `stfld`/`stsfld` propagation and a per-method object-field-taint summary on `this`. Required to carry taint from `this.fileHeader = …` in `ReadFileHeader` to `this.fileHeader.Value.Offset` in `ReadImageHeaders`. Memoization key clarified to `(MethodDefinition.FullName, tainted-param-bitmask)`. Null-sequence-point fallback specified.
  - **SanitizerShapes.** Added explicit throw-helper predicate (name-prefix `Throw*` + non-returning) and structural branch-direction detection (identifies the failure side by the transitive presence of a throw-helper or `ret`; reads the safe-side bound off that, handling compiler-negated operators).
  - **RulesDocument.** Specified the `SourceMethods` signature form (Cecil `FullName`-compatible, overload-disambiguating, no wildcards). Rules target sync overloads only for milestone C.
  - **TraceEmitter / `--compare` (FX062).** Reworked pre-fix `sanitizer_absence` synthesis: one entry per unsanitized path, `location` at the propagator hop immediately preceding the sink, `tainted_value` from that hop's `tainted_value_out`, `expected_check` a derived summary. `--compare` drops `expected_check` substring equivalence (unjustified for machine-vs-human prose); adds ±2-line tolerance on `location`; ignores provenance metadata (`vuln_id`, `fix_commit`, `fix_pr`, `description`). Diagnostic format unified.
  - **`--compare` (FX063).** Sanitizer-hop match now covers `establishes_bound.relation`, upper/lower bound, and `on_failure` kind/exception — not just `establishes_bound.target`.
  - **CLI.** `--output` defaults to stdout when omitted.
  - **Operational concerns.** Documented that the shared clone is shallow; replaced `git worktree`/`git clone` materialization (policy-violating or shallowness-propagating) with `git archive | tar -x` per commit. Added rules-file location convention.
  - **Success criteria.** Expanded test plan for `TaintAnalyzer.Tests` (seven named test classes, each with a scope statement). Added bonus criterion #7 for the #3079 reproduction check.
  - **Execution plan outline.** Added rules-file authoring step and the #3079 bonus step; clarified build-script mechanism.
- **2026-04-23 (clarifications, same day).** Follow-up tightening after pre-plan review:
  - `RulesDocument.VulnId` omitted-rules behavior specified (emit no `vuln_id` key; `SourceMethods` missing/empty is a startup error).
  - FX063 rationale for no line-tolerance made explicit (sanitizer-hop line is the check; shifted match is a real defect).
  - `tools/TaintAnalyzer.Tests/Fixtures/` shared-fixture-assemblies convention documented (single sibling csproj, authored once, extended per test class).
  - `artifacts/` `.gitignore` entry folded into execution-plan step 11 (build-script step).
