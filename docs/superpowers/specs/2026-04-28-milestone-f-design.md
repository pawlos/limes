# Milestone-F — Tainted-value naming pass (design)

**Status:** Approved 2026-04-28.

**One-liner:** Replace MethodReference-style synthetic names in `tainted_value_in` / `tainted_value_out` with PDB-resolved local names, and strip `get_` from property-getter call provenance, so analyzer-emitted traces are navigable by a human triager.

---

## Motivation

Milestone-E shipped U7+U8+U9 and met the required gate (5/5 fixtures pass `--compare` non-strict) but underdelivered on the strict bonus (2/5 vs target ≥4/5). The strict-gap data showed that two of the three bonus failures (#3074-prefix/postfix at 95–99 hops vs ceiling 10–12) are partly tunable and one (#3079 at 15965 hops, 40 docs) is structurally over. Continuing to chase strict bonus carries diminishing returns.

Meanwhile, the milestone-D backlog has flagged a consistently-painful, gate-orthogonal problem: every analyzer-emitted trace, on every fixture, contains `tainted_value_*` fields populated with MethodReference display names like `Span'1.op_Implicit`, `BmpInfoHeader.get_ProfileSize`, `StreamExtensions.Read` — the wrong handle for a triager who navigates the trace by following named locals (`buffer`, `profileSize`, `data`).

Milestone-F pivots to fixing that. The benefit lands on every existing fixture, every triager who reads a trace, immediately, and is independent of the strict-mode gate.

## Decisions / premises

- **Single work unit, two co-located edits** in `TaintWalker.cs`:
  - **N1 — stloc-return naming:** override slot `Provenance` with PDB-resolved local name at `stloc`.
  - **N2 — property-getter naming:** strip `get_` prefix when composing receiver-call provenance.
- **Approach for N1: eager rename at stloc** (chosen over conditional-by-call-instruction or lazy-at-ldloc). Concentrates the logic at one site; consistent with the existing single-pass walker model. The arithmetic-hop's own `tainted_value_out` still carries the inline expression (`recordCount * recordStride`); the local name takes over only for *subsequent* reads of the stored local.
- **Approach for N2: tiny helper `CleanCalleeName` that strips `get_` only.** Other patterns (`set_`, `add_`, `remove_`) don't compose into provenance the same way and are out of scope.
- **Compiler-generated locals are skipped.** PDB names that look like `<>g__…`, `CS$…`, etc. (or are absent entirely) leave the slot's existing synthetic provenance unchanged.
- **No new regression fixture.** The existing 5 fixtures concentrate the failure modes; a synthetic addition would duplicate what `imagesharp-3074-prefix` already exercises. Backlog DoD #1 ("new regression fixture") is consciously waived.
- **Ground-truth refresh strategy: regenerate verbatim** for each existing fixture — re-run analyzer, copy output into `trace.yaml`'s source/sink/path/sanitizer_absence blocks, preserve the metadata header (vuln_id, fix_commit, fix_pr, description). Same pattern as milestone-E Task 5.
- **Strict-bonus tally is best-effort.** Naming changes don't directly affect document count, hop count, or U8/U9 dedup behavior, so the bonus is expected to land at ~2/5 again. May incidentally improve if the renamed `Provenance` happens to make U8's operand-key tuple collide where it didn't before; that's a nice-to-have, not a goal.
- **Out-of-scope, deferred to milestone-G:**
  - Sub-problem (iii): `loc_N` recovery in sanitizer hops (sanitizer-shape matcher, separate code site).
  - Arithmetic attribution: discovered during this brainstorm that all binary opcodes (`Add`/`Sub`/`Mul`/`Div`/`Shl`/`Shr`/`Or`/`And`/`Xor`/`Rem` plus `*_Ovf` variants) already emit `transformation: "arithmetic"` propagator hops via the same handler in `TaintWalker.cs:448-480`. The original "Mul/Div/Shl don't trigger emission" hypothesis is wrong. The blind-test gap (lost fixture, never committed) needs investigation, not a known-fix; it's a bigger work item that opens with diagnosis.

## Architecture

Single intervention in `TaintWalker.cs`. No new files, no new types, no public-API changes.

```
ldarg / ldfld / call (return) / arithmetic   →   StackSlot.Provenance = synthetic
                          ↓
                    stloc to local L  →  if L has PDB name N (and N is meaningful),
                                          slot.Provenance := N  before going into state.Locals
                          ↓
            ldloc L → push slot with Provenance = N
                          ↓
                    next hop's tainted_value_in / tainted_value_out = N
```

For property getters specifically, the synthetic-provenance build path at the call-handler site is:

```
receiver.Provenance = "fileHeader"
callee.Name = "get_Value"
                          ↓
       Old: prov := "fileHeader.get_Value"
       New: prov := "fileHeader.Value"          via CleanCalleeName(callee)
```

## Components

### N1 — stloc-return naming

**Edit site:** `TaintWalker.StoreLocal(MethodDefinition method, Instruction ins, int idx, TaintState state)` at `TaintWalker.cs:295-316`. Currently the method just pops the slot and assigns to `state.Locals[idx]`; no hop emission.

**PDB resolution pattern:** The same lookup already exists at `TaintWalker.cs:260-266` for sink-hop `tainted_value` resolution. Reuse the shape:

```csharp
if (method.Body?.Variables is { } vars && idx < vars.Count
    && method.DebugInformation?.TryGetName(vars[idx], out var dn) == true
    && !string.IsNullOrEmpty(dn)
    && IsMeaningfulLocalName(dn))
{
    // use dn
}
```

**Logic:**
1. Pop the source slot from the stack (existing).
2. If `value.Tainted` and a meaningful PDB-resolved local name `N` is available for `idx`, store `StackSlot.TaintedWith(N)` into `state.Locals[idx]`.
3. Otherwise, store the original `value` unchanged.

`IsMeaningfulLocalName(string n)`: skip names that start with `<` (compiler-generated state-machine fields), start with `CS$` (compiler-generated temporaries), or match `loc_\d+` (debug-info fallback that already plagues sanitizer hops). Keep everything else.

**Why eager:** the rename point is `stloc`, the read point is later `ldloc`. Renaming once at `stloc` propagates the local name to every downstream `ldloc` automatically through the existing slot-clone semantics. No change to `ldloc` handlers required. `StoreLocal` does not emit hops directly; the visible benefit appears when downstream `ldloc` flows into a hop-emitting opcode (arithmetic, field-load, call-boundary, sink).

**Interaction with `FirstLocalTaintLine`** (`TaintWalker.cs:308-315`): the map stores `(url, line, value.Provenance)`. After N1, `value.Provenance` for the stored slot will be the local name. This is the desired behavior — `firstTaintedProvenance` flowing into the absence-emission code path (visible in sanitizer-absence's `tainted_local`) becomes a readable name.

### N2 — property-getter naming

**Edit sites in `TaintWalker.cs`:**
- Line 783: `prov = $"{receiverSlot.Provenance}.{callee.Name}"` — primary site, hits when external call has tainted receiver. Change to `prov = $"{receiverSlot.Provenance}.{CleanCalleeName(callee)}"`.
- Line 788: `prov = $"{callee.DeclaringType.Name}.{callee.Name}({firstTainted.Provenance})"` — secondary; getters take no value args so this branch is rarely hit by getters, but apply the strip defensively.
- Line 834: `CombineProvenanceArgs(argSlots, $"{callee.DeclaringType.Name}.{callee.Name}")` — internal-call return; getters again rare here, apply defensively.

**Helper:**
```csharp
private static string CleanCalleeName(MethodReference callee)
{
    var name = callee.Name;
    if (name.StartsWith("get_", StringComparison.Ordinal) && name.Length > 4)
    {
        return name.Substring(4);
    }
    return name;
}
```

Place near the other private helpers in `TaintWalker.cs`. No public API change.

**Why minimal:** other accessor patterns (`set_*`, `add_*`, `remove_*`, `op_*`) don't compose into provenance the same way and are not the source of the visible noise in the existing fixtures. Keeping the helper narrow reduces blast radius.

## Ground-truth refresh

Every existing fixture's `trace.yaml` will need re-authoring because tainted_value strings change on many hops.

**Process per fixture:**
1. Build TaintAnalyzer.
2. Run analyzer on the fixture's DLL with the existing `rules.yaml`. Capture output to a temp file.
3. Read the existing `trace.yaml`'s metadata header (`vuln_id`, `fix_commit`, `fix_pr`, `description`).
4. Read the captured analyzer output's source/sink/path/sanitizer_absence blocks.
5. Construct the new `trace.yaml`: metadata header + analyzer output sections, copied verbatim.
6. Run `--compare` non-strict; expect exit 0.
7. Sanity-spot-check: open the new YAML, confirm `tainted_value_*` fields show local names where you'd expect (e.g., `buffer`, `recordCount`, `fileHeader.Value`).

**Fixtures affected (in order of churn):**
- `imagesharp-3079-prefix` — 40 documents, highest churn.
- `imagesharp-3074-postfix` — 3 documents.
- `imagesharp-3074-prefix` — 3 documents.
- `synthetic-callee-arithmetic` — 1 document; touches `WireReader.ReadU16` etc.
- `synthetic-stackalloc` — 1 document; `WireReader.ReadU16` → `recordCount`.

**Pre-flight diff check:** before refreshing each fixture, diff the analyzer output against the existing trace and confirm that only `tainted_value_*`, `size_expression`, `access_expression`, and `establishes_bound.target` strings changed — not hop counts, not method/file/line, not sink shapes. If any non-naming field changed unexpectedly, investigate before refreshing (likely indicates an unintended walker-behavior change).

## Success criteria

### Required gate

1. `--compare` (non-strict) exits 0 on all 5 existing fixtures after ground-truth refresh.
2. In `fixtures/imagesharp-3074-prefix/trace.yaml`, no hop has a `tainted_value_in` or `tainted_value_out` of the shape `<Type>.<methodName>` for a value that is `stloc`'d to a named local in the same method on the same line. Spot-check at least 5 hops that previously had MethodRef-style names; confirm they now use the local name.
3. Property-getter calls render as `{receiver}.{Property}` rather than `{receiver}.get_{Property}` in at least one fixture (concrete check: `BmpInfoHeader.get_ProfileSize` should now appear as `infoHeader.ProfileSize` or similar in `imagesharp-3074-prefix`).
4. Build clean (0/0). Full analyzer + validator test suites green.

### Bonus / observational

- Strict pass count (`--compare --strict`) doesn't regress from milestone-E's 2/5.
- New unit tests for `CleanCalleeName` and the `StoreLocal` rename branch (compiler-generated-name skip, untainted-slot no-op, missing-PDB-name fallback).

### Non-goals

- Do not change document count or hop count in any fixture's analyzer output.
- Do not introduce new sink kinds, sanitizer kinds, or rules-file fields.
- Do not modify `--compare` semantics or add new FX0NN diagnostic codes.

## Risks

- **Ground-truth refresh masks an unintended walker change.** Mitigation: pre-flight diff (described above) before each fixture's refresh; diff only naming-related fields.
- **Compiler-generated-name detection is incomplete.** Mitigation: start with the obvious patterns (`<` prefix, `CS$` prefix); if we miss a pattern and a fixture's trace.yaml regresses to opaque names, add a pattern in a follow-up. Low-cost iteration.
- **PDB resolution returns `loc_N`-style fallback names** because debug info is partial. Mitigation: explicitly skip names matching `loc_\d+` — those are exactly the noise we don't want.
- **N2's `get_` strip collides with a legitimately-named method called `get_Foo` that isn't a getter.** Vanishingly rare; if encountered, fix forward (predicate could check `callee.Resolve().IsGetter` for accuracy, at the cost of a Cecil resolution).

## Carry-overs to milestone-G

- **Sub-problem (iii) `loc_N` recovery in sanitizer hops** — separate code site (`SanitizerShapes.OperandName`); deferred from milestone-F's A2 sub-scope.
- **Arithmetic attribution / blind-test gap** — original milestone-F focus, redirected after discovering the emission path is intact. Needs investigation: reproduce a Pmsg-like fixture, run analyzer, inspect actual trace, identify why the multiply hop is missing or visually masked. Could be filtering, could be naming (might collapse into the milestone-F work), could be something else.
- **U9 tuning + cross-method sink-document dedup** — strict-bonus recovery work from milestone-E carry-over. Structural; needs design before plan.
- **U1.c redesign** — meaningful sanitizer bound vs sibling guard. Original milestone-D Task 5 work that was reverted. Targets #3079 over-emission specifically.
- **parquet-dotnet round-trip** — fixture authored, materialize script + analyzer run still pending.

## Execution plan outline (handed to writing-plans)

1. **Task 1 — N1 stloc-return naming:** TaintWalker.StoreLocal rename branch + unit tests for the rename / skip / no-op cases.
2. **Task 2 — N2 property-getter naming:** `CleanCalleeName` helper + usage at `:783` (and audit `:788`/`:834`) + unit tests.
3. **Task 3 — Ground-truth refresh: synthetic fixtures** (synthetic-callee-arithmetic, synthetic-stackalloc). Smaller; warm-up.
4. **Task 4 — Ground-truth refresh: imagesharp-3074 fixtures** (prefix + postfix).
5. **Task 5 — Ground-truth refresh: imagesharp-3079-prefix.** Highest-churn; isolated to its own task.
6. **Task 6 — Cross-fixture verification + spot-checks:** required-gate run, spot-check that the four DoD criteria are met.
7. **Task 7 — Spec status update + carry-over capture for milestone-G.**

(Actual plan structure decided by writing-plans; this is the design's view of the work.)

## Revision history

- **2026-04-28 (approved).** Pivoted from arithmetic attribution after discovering all binary opcodes already emit propagator hops; the blind-test gap is investigation-shaped, not known-fix-shaped, and unsuitable for a "smaller steps" milestone. Settled on tainted-value naming sub-scope A2 (stloc-return + property-getter, both in `OperandName`/walker provenance composition); waived backlog DoD #1 (new regression fixture) on grounds the existing 5 concentrate the failure modes; deferred sub-problem (iii) `loc_N` recovery to milestone-G as a separate code site.
