# Milestone D — Backlog

Inputs feeding milestone-D scope. Populated as findings emerge during
milestone-C exit testing and ad-hoc experiments. Each entry should be enough
to recover context cold; concrete file/line pointers preferred over prose.

---

## Trace attribution: surface intra-callee arithmetic transformations

**Status.** Open. Discovered 2026-04-26 during a blind-test experiment
(general-purpose agent authored a small fictional `Pmsg.Protocol`
parser; analyzer was run blind against the resulting DLL).

**Finding.** The analyzer correctly detects unbounded `new byte[totalBytes]`
end-to-end, with absence emitted at the right line and the correct tainted
local. But the trace doesn't include a propagator hop for the **load-bearing
arithmetic transformation** that actually computes the dangerous size.

In the blind-test case, that transformation is
`PayloadSizer.RecordsAreaBytes`:

```csharp
return (int)recordCount * (int)recordStride;   // u16 * u16 → int, overflow-prone
```

This is the multiplication that lets a u16×u16 input drive a ~2 GiB
allocation. Taint *flows through* the call boundary correctly (the cross-
method machinery from milestone-C handles it), but the arithmetic step is
invisible in the trace — the only hops emitted around it are the call-
boundary `identity` hops.

**Why it matters.** Detection works without this; diagnostics suffer. A
human reading the trace can see "unbounded `byte[totalBytes]`" but can't see
*where* the dangerous transform happens — they'd have to open
`PayloadSizer` and find it themselves. For real-world triage, attributing
the transform is the more useful signal (it's where the fix goes).

**Reference fixture.** `/tmp/blind-test-demo/` contained the demo at the
time of writing. Not committed. Reproducing requires re-spawning the
authoring agent (or re-creating manually) — the path-shape is canonical
enough (multi-hop u16×u16 multiply through a sizing-helper class) that
authoring a permanent regression fixture is probably worth it as part of
this task.

**Implementation sketch.**

- TaintWalker currently emits propagator hops on stloc-to-tainted-local and
  on certain field/cast operations (search for `Transformation = "arithmetic"`
  emission sites). Inside callees, the value-introducing arithmetic *does*
  fire emission, but the hop's `Method` is the callee — and when the merged
  flat hop list is built, those callee hops are present.
- Need to verify what's actually happening in the blind-test trace:
  the WireReader byte-shifting hops *do* show up (lines 33–34 of
  WireReader.cs in the trace) but `PayloadSizer.RecordsAreaBytes`'
  multiplication does not. Likely cause: the `*` happens on a return path
  where the symbolic stack handling of `mul` / `mul.ovf` doesn't trigger
  the same propagator-emit path that `add` / `or` / shifts do.
- Cross-check `OperandName` Add/Sub composition (added in milestone-C for
  bound normalization) — `Mul`/`Div`/`Shl`/`Or` may need analogous
  handling so the operand-name resolution surfaces the underlying locals.
- Consider: when a callee's tainted return is consumed by the caller's
  stloc, emit a propagator hop pinned to the `*` instruction's sequence
  point even if the call-boundary hop already covered it. Two hops (the
  call boundary + the value-introducing transform) is fine; the transform
  hop is the one a triager wants.

**Definition of done.**

1. A regression fixture (committed) where the load-bearing arithmetic is
   in a helper method's return value. Could be a trimmed-down version of
   the Pmsg blind-test demo.
2. Analyzer trace for that fixture contains a propagator hop with
   `transformation: arithmetic` whose `file:line` points at the actual
   `*` / `+` / `<<` site, not just the call boundary.
3. ImageSharp / parquet-dotnet fixtures still `--compare` exit 0.

---
