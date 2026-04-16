# Milestone 1 — Ground-truth trace of ImageSharp #3074

**Status:** Approved 2026-04-16 (awaiting post-write review before execution).
**Next milestone dependency:** Tech-choice decision (Roslyn / Cecil / ILLink) is blocked on completion of this milestone.

## Context

The parent project is `dotnet-taint-analyzer`: a static taint-flow analyzer for .NET image decoders that aims to catch the class of bugs in which an attacker-controlled size field from a file header flows into an unchecked allocation. The approach, inspired by Ferrocene's callgraph-closure technique, asserts that the set of functions reachable from a decoder entry point which have not passed a tainted value through a sanitizer is closed under the call operator. Unlike pattern-matching source/sink tools (CodeQL, Semgrep), indirection stops mattering because the property propagates across calls.

Before deciding on analyzer architecture, we want a concrete ground-truth trace of a real vulnerability the analyzer must catch. The pre-fix state of SixLabors/ImageSharp issue #3074 (BMP decoder OOM, fixed by PR #3075, merge commit `461c021608802370374afabd5d3c2720b3e46f04`) is the test case. Its fix message states the root cause directly: *"Add check, if Offset is greater than stream length when reading bitmap colorMapSize."*

## Goals

1. Produce a machine-checkable fixture describing the exact source → sink path that exists in the pre-fix code.
2. Produce a narrative companion that makes the fixture auditable by a human reader who does not already know the bug.
3. Extract the pre-fix source snippets for each hop as standalone files the eventual analyzer can consume as test inputs.
4. Surface the schema pressure points the fixture format will have to handle for the other six ImageSharp bugs already in scope (#3067, #3071, #3078, #3079, #3082).

## Non-goals

- No analyzer code.
- No decision on Roslyn vs. Cecil/dnlib vs. ILLink.
- No generalization of the schema across multiple bugs — only #3074. Later fixtures may expose schema gaps; those are resolved then, not pre-emptively now.
- No PoC input / crash reproduction. Analysis is read-only.
- No modifications to the shared ImageSharp clone at `/mnt/c/work/dotnet-fuzzing/external/ImageSharp`.

## Approach

### Source of truth for pre-fix code

The shared clone is a shallow clone whose HEAD contains the fix merge. The fix commit's parent is outside the shallow boundary, so we cannot directly check out the pre-fix state. Two options were considered:

1. **Copy the clone, unshallow it, check out the fix merge's first parent.** Requires network fetch and ~1 GB of history. Buys a fully buildable pre-fix worktree.
2. **Reconstruct pre-fix code in place using `git log -p HEAD -- <file>`.** The fix's diff hunks for each touched file, reversed, yield the exact pre-fix text. No working-tree checkout. No network. No modifications to the shared clone.

Option 2 is sufficient because milestone 1 is read-only analysis and does not require executing the pre-fix code. The extracted snippets go under `fixtures/imagesharp-3074/prefix-snippets/`. We defer option 1 until a later milestone that needs a buildable pre-fix worktree (running the analyzer against it, fuzzing it, instrumenting it).

### Deliverable layout

```
fixtures/
  imagesharp-3074/
    trace.yaml                 # machine-checkable fixture, per schema below
    trace.md                   # narrative companion; walks trace.yaml hop-by-hop
    prefix-snippets/
      <FileName>.cs            # exact pre-fix content of each file touched by the fix
      <FileName>.meta.json     # { source_path, upstream_sha_reconstructed_against, sha256 }
```

### Fixture schema v0

YAML. Intentionally minimal but capable. Expected to evolve during the trace itself; any extension is recorded in an `Open schema questions` section of `trace.md` so the schema's v1 freeze (after more fixtures exist) can address it.

```yaml
vuln_id: imagesharp-3074
fix_commit: 461c021608802370374afabd5d3c2720b3e46f04
fix_pr: https://github.com/SixLabors/ImageSharp/pull/3075
description: BMP decoder OOM — unchecked allocation sized by attacker-controlled
             colorMapSize derived from header Offset field.

source:
  kind: decoder_entry
  method: <fully-qualified method, e.g. SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore.Decode>
  file: src/ImageSharp/Formats/Bmp/BmpDecoderCore.cs
  line: <line number in pre-fix source>
  tainted_inputs:
    - name: <parameter or local name>
      origin: <stream_read | param | header_field:<name>>

sink:
  kind: allocation
  api: <new_array | array_pool_rent | alloc_hglobal | memory_pool_rent | stackalloc>
  file: <path>
  line: <line>
  size_expression: <stringified expression feeding the size argument>

path:
  - hop: 0
    method: <fq name>
    file: <path>
    line: <line>
    role: source                       # source | propagator | sanitizer | sink
    tainted_value_in: <name>
    transformation: <kind>             # see vocabulary below
    tainted_value_out: <name>
    dispatch:                          # richer record per edge
      kind: <direct | virtual | interface | async_continuation | delegate | reflection | unknown>
      static_type: <type at call site>
      resolved_targets:                # CHA closure within analyzed assembly set
        - <fq method>
      closure_boundary: <bool>         # true if resolution escapes analyzed assemblies
    note: <freeform>
  - hop: 1
    ...

sanitizer_absence:
  - location: <file:line>
    expected_check: <description of the check the fix added>
    tainted_value: <name>
    present_pre_fix: false
    present_post_fix: true
    fix_evidence:
      commit: 461c021608802370374afabd5d3c2720b3e46f04
      added_lines: <file:line-range>
```

### `transformation` vocabulary (v0, closed)

Captures what happened to the tainted value at the hop. Additions during the trace are recorded in `trace.md`.

| Value           | Meaning                                                                       |
|-----------------|-------------------------------------------------------------------------------|
| `identity`      | Passed through without change (e.g., forwarded as an argument).               |
| `read_stream`   | Value was read from the input stream at this hop (taint origin).              |
| `field_load`    | Loaded from a field of a tainted aggregate (header struct, etc.).             |
| `arithmetic`    | Arithmetic combining tainted and/or constant operands (+, *, <<, etc.).       |
| `cast`          | Type conversion (`(int)`, `checked((int)...)`, `Convert.ToInt32`, etc.).      |
| `array_index`   | Used to index into an array (consumes the taint at a specific position).      |
| `stream_offset` | Used as a stream position (Seek, Position = ...).                             |

**Note on change from the brainstorm vocabulary.** The brainstorm round listed `{identity, read_stream, arithmetic, cast, array_index, bounds_check, clamp, cap}`. While writing this spec I realised `bounds_check`, `clamp`, and `cap` describe *sanitizer outcomes*, not value transformations — a clamp is a check that happens to also modify the value, but what makes it interesting for taint analysis is the role (`role: sanitizer`), not the transformation. They are now expressible via a node with `role: sanitizer` and (prospectively, see Open question O1) a `sanitizer_kind` field on that node. In exchange, `field_load` and `stream_offset` are added because the first (unrefined) pass of the BMP trace already needs them — header fields are loaded via `field_load` after the header struct is first read, and `stream_offset` captures the `Stream.Seek(offset, ...)` call the fix now guards.

### `role` vocabulary (v0, closed)

| Value        | Meaning                                                                                   |
|--------------|-------------------------------------------------------------------------------------------|
| `source`     | Origin of tainted value (decoder entry, `Stream.Read` return, etc.).                      |
| `propagator` | Hop where the value is transformed or forwarded without being checked or consumed.        |
| `sanitizer`  | Hop where a check establishes a provable bound on the tainted value.                       |
| `sink`       | Hop where the tainted value is used as an allocation size argument.                       |

### `dispatch.kind` vocabulary (v0, closed)

| Value                 | Meaning                                                                               |
|-----------------------|---------------------------------------------------------------------------------------|
| `direct`              | Non-virtual method call; exact target known from the IL `call` instruction.           |
| `virtual`             | Virtual method call on a concrete class type (`callvirt` on non-interface).           |
| `interface`           | Interface dispatch (`callvirt` on interface type).                                    |
| `async_continuation`  | Hop through a compiler-generated state machine (`MoveNext` / `Task` continuation).    |
| `delegate`            | `Delegate.Invoke` or equivalent indirect call through a delegate instance.            |
| `reflection`          | `MethodInfo.Invoke`, `DynamicMethod`, expression tree compile, etc.                   |
| `unknown`             | Escape hatch; must come with a `note`.                                                |

### Narrative companion (`trace.md`)

Sections:
1. **Summary** — one paragraph: what is the bug, what header field drives it, what allocation blows up, what the one-line fix is.
2. **Header reference** — a table mapping BMP header field offsets to names, with emphasis on fields that feed the sink.
3. **Hop-by-hop walkthrough** — each `path` node in `trace.yaml` gets a subsection containing (a) the pre-fix code snippet (fenced, referencing the file under `prefix-snippets/`), (b) what the tainted value is at entry/exit, (c) why this hop is a propagator / sanitizer / sink, (d) for virtual/interface edges, the CHA closure and whether it stays within the analyzed assembly.
4. **Sanitizer absence** — the exact check the fix added, side-by-side pre-fix vs. post-fix.
5. **Open schema questions** — any case the v0 schema could not cleanly express, with a concrete example.

## Done criteria

1. `trace.yaml` parses as YAML and every enum-typed field uses a value from the closed vocabularies above (or extends them with a documented addition).
2. Every `path[*].file:line` resolves to a real file and line in the pre-fix snippet files.
3. Every `path[*].method` is a fully-qualified .NET method name that exists (post-fix) in the current HEAD of the shared ImageSharp clone; any pre-fix-only method is flagged.
4. `sanitizer_absence[*].fix_evidence.added_lines` cites the exact lines the fix added in `461c021...`.
5. `trace.md` is readable end-to-end by someone who does not know the bug and convinces the reader the fixture is faithful.
6. Every virtual/interface edge in the trace has a populated `dispatch.resolved_targets` list or an explicit `closure_boundary: true` with a note.

## Open questions to resolve during execution (not blocking approval)

- **O1.** Does the trace need a `taint_value_state` field (e.g., `unbounded`, `bounded_by:<expr>`) in addition to `transformation`? Likely yes, to express what a sanitizer actually establishes — but let the first sanitizer-absence narrative pressure it rather than over-specifying now.
- **O2.** How do we represent a tainted *aggregate* (e.g., the entire parsed BMP header struct) vs. a tainted scalar? Option: treat the aggregate as the tainted value and use `field_load` to narrow to the relevant scalar at the hop that first uses it. Revisit if it produces awkward traces.
- **O3.** Async / state-machine hops likely don't appear in the BMP decoder (it's synchronous), so the `async_continuation` dispatch kind will go unexercised by this trace. That's expected; it's in v0 so the schema can encode it when a later trace needs it.

## Execution plan (to be expanded in the writing-plans step)

1. Extract the fix's diff for every file it touched: `git log -p HEAD -- <file>` in the shared clone. Save each file's pre-fix content to `prefix-snippets/<FileName>.cs`, with a `.meta.json` sidecar.
2. Starting from the BMP decoder entry point in the pre-fix snippets, walk the call graph by hand to the allocation(s) the fix protected. Record each hop.
3. For every virtual/interface call on the path, compute the CHA closure within the ImageSharp assembly (by grep for overrides/implementations). Flag any that leak outside the assembly boundary.
4. Write `trace.yaml`, validating vocabularies as we go.
5. Write `trace.md` narrating the fixture and recording any open schema questions.
6. Sanity-check: a reader who doesn't know the bug can follow `trace.md` end-to-end.
