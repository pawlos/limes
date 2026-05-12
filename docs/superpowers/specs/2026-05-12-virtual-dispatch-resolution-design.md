# Milestone-R: Virtual-dispatch resolution

**Date:** 2026-05-12
**Status:** Design approved; ready for implementation plan.
**Scope:** R1 from the analyzer gap backlog, plus a `scan-protobuf-net` proof fixture.

## Problem

Both `ReverseCallGraph` (reachability) and `TaintWalker.HandleCall`
(interprocedural follow-through) resolve every `callvirt` operand to the **static**
target via `MethodReference.Resolve()`. When the static target is an abstract or
virtual method whose body is empty (the abstract base), the concrete overrides
on derived types are never visited. Two consequences:

1. **Reachability false-negatives.** Concrete overrides on internal/nested types
   appear as orphans even though they ARE callable from the public surface via
   the abstract base — for example, `ReadOnlySequenceProtoReader::ImplReadString`
   on protobuf-net ≤ 3.2.56 is reachable via
   `ProtoReader.Create(ROS<byte>, …).ReadString() → callvirt ImplReadString`,
   but `--scan` won't enumerate it.
2. **Interprocedural taint dropped at the callvirt site.** When `TaintWalker`
   crosses a `callvirt` into an abstract method, `WalkWithSeed` produces an
   empty summary (no body to walk). Any sink inside the override is invisible.

The fix benefits both consumers at once: enumerate overrides of a `callvirt`
target in the same assembly and treat each as an additional edge / additional
walk target.

## Goals & non-goals

**In scope (R1):**
- Resolve overrides of `callvirt` targets in the same assembly.
- Apply in both `ReverseCallGraph` and `TaintWalker.HandleCall`.
- Lock a `scan-protobuf-net` fixture that demonstrates the protobuf-net OOM bug
  being caught cold via `--scan`.

**Out of scope (deferred to future R-series):**
- R2: field-type unwrapping for wrapper structs (`ReadOnlySequence<byte>.Enumerator`).
  Likely unnecessary once R1 lands; keep on watch list.
- R3: non-public entry points reachable via reflection / `[InternalsVisibleTo]` / COM.
- Receiver-static-type narrowing at the call site (we walk all overrides of the
  virtual target regardless of the receiver's inferred static type at the call site).
- `call` (non-virt) opcode handling — the CLI emits `call` only when the target
  has a static binding, so override expansion is unnecessary.
- Cross-assembly override resolution.

## Architecture

```
AssemblyContext
  └── VirtualOverrideIndex   (new — owned by AssemblyContext; the whole
                               index is built on the first EnumerateOverrides
                               call, then cached)
        ├── BuildIndex(AssemblyDefinition)
        │     Walk every type, every method. For each method M:
        │       (a) If M.HasOverrides (explicit MethodImpl), for each
        │           r in M.Overrides: resolve r; if r.Module.Assembly == this,
        │           append M to index[r].
        │       (b) If M.IsVirtual && M.IsReuseSlot (implicit override),
        │           walk M.DeclaringType.BaseType chain; for EACH ancestor
        │           virtual/abstract method with matching name+signature
        │           that is in-assembly, append M to index[v]. Continue past
        │           matches so deep chains are flattened (M overrides B AND
        │           M overrides A when B itself overrides A).
        │
        ├── EnumerateOverrides(MethodReference vRef) -> IReadOnlyList<MethodDefinition>
        │     Resolve vRef. If resolution fails -> [].
        │     If denylisted -> [resolved] (single static target, no expansion).
        │     If not virtual/abstract -> [resolved].
        │     Else -> [resolved, ...index[resolved]].
        │
        └── IsDenylisted(MethodDefinition m) -> bool
              True iff m's full name matches one of:
                System.Void System.Object::Finalize()
                System.String System.Object::ToString()
                System.Boolean System.Object::Equals(System.Object)
                System.Int32 System.Object::GetHashCode()

Consumer 1 — ReverseCallGraph
  In the BFS, when an instruction is Callvirt with a MethodReference operand:
    foreach target in VirtualOverrideIndex.EnumerateOverrides(operand):
      if target.Module.Assembly == assembly && _reachableFromPublic.Add(target):
        queue.Enqueue(target)
  Call/Newobj edges unchanged (single resolved target).

Consumer 2 — TaintWalker.HandleCall (after in-assembly resolution check)
  if (ins.OpCode == Callvirt) {
    var targets = _context.VirtualOverrides.EnumerateOverrides(callee);
    calleeSummary = targets.Count == 1
      ? WalkWithSeed(targets[0], bitmask, seedFields)
      : WalkAndMerge(targets, bitmask, seedFields);
  } else {
    calleeSummary = WalkWithSeed(resolved, bitmask, seedFields);  // unchanged
  }
```

## Override-discovery rules

Three flavours of override the C# compiler emits, all handled by `BuildIndex`:

1. **Implicit overrides** (the normal `override` keyword). Discovered by walking
   the derived type's base chain at index-build time for any method with
   `IsVirtual && IsReuseSlot` — for EACH ancestor virtual/abstract method with
   matching name + signature, record this method as an override. Walking
   continues through the entire base chain so a deep override (C overrides B
   overrides A) is recorded as an override of both B and A — `callvirt A::Foo()`
   must enumerate every concrete override in the chain, not just the closest.
2. **Explicit interface / method implementations** (`void IFoo.Bar() { … }`).
   Discovered via Cecil's `MethodDefinition.Overrides` collection — each entry
   is a `MethodReference` to the virtual being overridden.
3. **Interface method targets** (`callvirt IDisposable::Dispose()`). Reached
   through either implicit or explicit paths above — no special handling.

**Signature matching:** return type + name + parameter types in order, with
`modreq(InAttribute)` stripped per the milestone-N fix at
`AssemblyContext.BuildShortSignature`. Generic type parameters are matched
structurally; type arguments at the call site are not required to match because
Cecil resolves to the generic definition.

**Denylist** (excluded — `EnumerateOverrides` returns the single static target
and does NOT enumerate overrides):

- `System.Object::ToString()`
- `System.Object::Equals(System.Object)`
- `System.Object::GetHashCode()`
- `System.Object::Finalize()`

Comparison is by `MethodDefinition.FullName` against the resolved target.
`IDisposable.Dispose`, `IEnumerator.MoveNext`, `Stream.Read` etc. are NOT
denylisted; they appear frequently in decoder paths and are load-bearing.

**Cross-assembly:** only overrides whose
`DeclaringType.Module.Assembly == this assembly` are recorded. Matches the
existing single-assembly scope of both consumers.

## Summary merge — `WalkAndMerge`

When `targets.Count > 1`, walk each via existing `WalkWithSeed` (memoization
in `WalkWithSeed` makes repeats free) and fold:

| Field                          | Merge rule              | Rationale |
|--------------------------------|-------------------------|-----------|
| `ReturnsTainted`               | OR (union)              | If any override taints the return, the call-site return is tainted. |
| `ReachedSink`                  | OR (union)              | Vulnerable override surfaces as ReachedSink. |
| `NewlyTaintedThisFields`       | union of name sets      | Caller may observe any override's writes to caller's `this`-fields. |
| `AppliedValueClamp`            | AND (intersection)      | Suppressing the `bitmask != 0` over-approximation requires EVERY override to value-clamp. |
| `AppliedThrowShapeSanitiser`   | AND (intersection)      | Suppressing byref propagation requires EVERY override to throw-sanitise. |
| `Hops`                         | First override that has `ReachedSink == true`; otherwise first with `ReturnsTainted == true`; otherwise first with non-empty hops; else empty. | One concrete trace per finding; pick the worst-case witness. |

The intersection rule on sanitiser flags is the load-bearing safety property:
a single sanitised override CANNOT hide a vulnerable sibling.

## Expansion guard (U10) under override expansion

The existing `expandedCallees` key is `{resolved.FullName}|{bitmask}|{seedKey}`.
Each override gets its own key built from `target.FullName` — distinct bodies
get distinct dedupe slots; repeat `callvirt`s to the same call-site still emit
the call-boundary identity hop but skip re-appending callee hops.

## CLI / configuration

No new flags. Override expansion is always on, gated only by the
`OpCodes.Callvirt` check and the `System.Object` denylist.

## Testing

**Unit tests — `VirtualOverrideIndexTests` (new):**

1. `EnumerateOverrides_NonVirtualTarget_ReturnsSingleStatic`
2. `EnumerateOverrides_ImplicitOverride_Found` — abstract Base + override on derived
3. `EnumerateOverrides_ExplicitInterfaceImpl_Found` — `void IFoo.Bar()` shape
4. `EnumerateOverrides_TransitiveOverride_AllFound` — A→B→C chain
5. `EnumerateOverrides_DenylistedObjectToString_ReturnsBaseOnly`
6. `EnumerateOverrides_DenylistedEquals_ReturnsBaseOnly`
7. `EnumerateOverrides_DenylistedGetHashCode_ReturnsBaseOnly`
8. `EnumerateOverrides_DenylistedFinalize_ReturnsBaseOnly`
9. `EnumerateOverrides_CrossAssemblyOverride_Excluded`
10. `EnumerateOverrides_IDisposableDispose_ImplIncluded` — denylist precision
11. `EnumerateOverrides_IEnumeratorMoveNext_ImplIncluded` — denylist precision
12. `EnumerateOverrides_ModreqInAttribute_SignatureMatches`
13. `EnumerateOverrides_ResolveFailure_ReturnsEmpty`

**Unit tests — `ReverseCallGraphTests` (extend existing):**

14. `Callvirt_Override_ReachableFromPublicCaller`
15. `Callvirt_OverrideOfDenylistedObjectMethod_NotEnqueued`
16. `Callvirt_ExplicitInterfaceImpl_Reachable`
17. `Callvirt_TransitiveOverride_Reachable`

**Unit tests — `TaintWalkerTests` (extend existing):**

18. `Callvirt_SingleOverride_PropagatesTaintFromOverrideBody`
19. `Callvirt_MultipleOverrides_OneTaintsReturn_SummaryHasReturnsTainted`
20. `Callvirt_MultipleOverrides_OneSanitises_AppliedThrowShapeSanitiserStaysFalse`
21. `Callvirt_AllOverridesSanitise_AppliedThrowShapeSanitiserTrue`
22. `Callvirt_OneOverrideReachesSink_OverallReachedSink`
23. `Callvirt_HopsPreferSinkReachingOverride`
24. `Callvirt_DenylistedObjectToString_FallsBackToSingleTarget`
25. `Callvirt_NotInAssembly_FallsBackToExternalPath`
26. `Call_OpcodeOnVirtualMethod_NoOverrideExpansion`

**Fixture lock — `fixtures/scan-protobuf-net/` (new):**

Target: `protobuf-net.Core.dll` ≤ 3.2.56.
- `--scan` enumerates the public surface (`ProtoReader.ReadString`,
  `ProtoReader.Create(ROS<byte>, …)`, etc.).
- Walker now traverses callvirt → `ReadOnlySequenceProtoReader::ImplReadString`
  override; the OOM allocation sink is reached.
- Same `--compare` non-strict pattern as `fixtures/scan-nbmp-1.1.25/`.
- Locked at the milestone-R merge commit.

**Anchors that MUST stay green:**

- All `imagesharp-307{4,9}-{prefix,postfix}` `--compare` non-strict
- All `otelcontrib-{55m9,vc24}-{prefix,postfix}` (55m9 is the HandleCall canary)
- `otelcontrib-opamp-w2jh-{prefix,postfix}`
- `otelcontrib-aws-fp-fixed`
- All synthetic + parquet fixtures
- `nbmp-2cwq-pwfr-wcw3-{prefix,postfix}`
- `scan-nbmp-1.1.25` (milestone-Q proof)
- Full 294-test suite + the new tests above

## Files touched

**New:**
- `tools/TaintAnalyzer/VirtualOverrideIndex.cs`
- `tools/TaintAnalyzer.Tests/VirtualOverrideIndexTests.cs`
- `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.VirtualDispatch.cs` (new fixture
  source for the override-discovery tests)
- `fixtures/scan-protobuf-net/` (new fixture directory: rules.yaml, expected.yaml,
  snippets, README)

**Modified:**
- `tools/TaintAnalyzer/AssemblyContext.cs` — own a lazy `VirtualOverrideIndex`
- `tools/TaintAnalyzer/ReverseCallGraph.cs` — callvirt edge expansion
- `tools/TaintAnalyzer/TaintWalker.cs` — `HandleCall` callvirt branch +
  `WalkAndMerge` helper
- `tools/TaintAnalyzer.Tests/ReverseCallGraphTests.cs` — 4 new tests
- `tools/TaintAnalyzer.Tests/TaintWalkerTests.cs` — 9 new tests

## Risks

1. **Anchor regressions.** Every existing fixture's hop trace could shift if a
   previously-empty `callvirt` summary now folds in override hops. Mitigation:
   run the full `--compare` non-strict suite before merge; investigate any
   shift before accepting.
2. **Index build cost.** `BuildIndex` walks every method × every base type;
   O(types²) worst case but small constants and runs once per assembly.
   Mitigation: lazy — only built when the index is first queried.
3. **Cecil `Resolve()` failures inside `BuildIndex`.** Already handled in the
   existing code paths via try/catch returning null. Continue that pattern.
4. **Merge rule on Hops loses information.** A single witness trace is selected
   even when multiple overrides reach a sink. Acceptable: the user-facing trace
   model is "one path per finding"; sibling vulnerabilities surface as separate
   findings via the per-target memo + per-target sink hop.

## Success criteria

- 26 new unit tests green (13 VirtualOverrideIndex + 4 ReverseCallGraph + 9 TaintWalker).
- All 294 existing tests still green; total test count becomes 320.
- `fixtures/scan-protobuf-net/` locked; `--scan` over protobuf-net.Core ≤ 3.2.56
  flags `ImplReadString` OOM finding via `--compare` non-strict.
- All anchor fixtures stay green via `--compare` non-strict.
- No new CLI flags; behaviour change is invisible to the user except in
  scan-mode coverage.
