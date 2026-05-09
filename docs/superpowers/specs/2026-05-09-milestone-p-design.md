# Milestone-P — MongoDB.Bson cold hunt (design)

**Status:** Design 2026-05-09. Finding-driven milestone, parallel in shape to milestone-K (protobuf-net).

**One-liner:** Run Limes against the MongoDB C# driver's `MongoDB.Bson` namespace looking for CWE-770 size-prefix-to-allocation flows analogous to the protobuf-net string-OOM finding. Hunt cold (no upstream fix to anchor on). Outcome is one of: confirmed advisory-grade finding + draft advisory + any analyzer extension that fell out, OR documented negative result with a triaged exclusion list.

---

## Motivation

Milestones K through O were finding-driven and each closed one analyzer gap as a side-effect of hunting a real bug (FingerprintDedup `SinkKind` split, `AppliedThrowShapeSanitiser`, stream-returning HttpRead exclusion, modreq stripping, Shape C Variant 1). The P0/P1 backlog is now closed; the next analyzer-gap signal will come from a new target.

BSON is a structurally strong fit for the existing analyzer: every BSON string, binary, and embedded document is int32-length-prefixed, so the read paths look like the protobuf-net string-OOM shape. The MongoDB C# driver is widely deployed — a real finding here would have meaningful blast radius — and the exercise also serves as the first independent validation of milestones J/L/O's sanitiser coverage on a third-party deserializer outside the OTel/MessagePack family.

## Goals

1. Stand up `experiments/mongodb-bson/` with a SHA-pinned MongoDB.Bson build and a runnable Limes invocation.
2. Draft `rules.yaml` covering BSON sources; rely on existing sink coverage.
3. Run Limes; triage every finding into REAL / SANITISER-MISS / WALKER-FP / OUT-OF-SCOPE.
4. For any REAL finding: build a PoC, draft an advisory under `docs/draft-advisory-mongodb-bson-*.md`, file via private channel, record memory.
5. For any SANITISER-MISS finding cheap enough to fix in-milestone: implement, add regression test, re-run anchors.
6. Update `analyzer_gap_backlog.md` with the milestone-P closure summary and any new deferred gaps.

## Non-goals

- The full MongoDB driver (server discovery, change streams, cluster topology, etc.) is out of scope. Only `MongoDB.Bson.csproj` and its dependencies are scanned.
- BSON-as-text JSON parsing (`BsonDocument.Parse(string)`) is out of scope unless a finding pulls it in — different threat model than the binary read path.
- Other size-prefixed deserializers (Avro, CBOR, full MessagePack surface) are explicitly deferred. Each is a candidate for a follow-up milestone if milestone-P validates the approach.
- Cross-language BSON drivers (Java, Python, Node) are not consulted as conceptual anchors. The hunt is cold by choice.

---

## Targets / read paths

In approximate priority order:

1. **`BsonBinaryReader.ReadString()`** — int32 length prefix + UTF-8 bytes + 0x00 terminator. Direct analogue of the protobuf-net finding.
2. **`BsonBinaryReader.ReadBinaryData()`** — int32 length + subtype byte + binary payload. Subtype byte may produce a different sink fingerprint.
3. **Old binary subtype 0x02** — historic gotcha: a nested int32 length lives inside the outer int32 length. Inner/outer mismatch is precisely the shape that gets missed in hand-written parsers.
4. **`ReadStartDocument` / `ReadEndDocument`** — int32 defines a sub-region. Doesn't allocate directly but feeds depth-bounded recursion. Deferred unless (1)–(3) come up dry.
5. **`ReadJavaScriptWithScope` / `ReadSymbol`** — variants of (1). Audit if the primary sites are clean.

Sinks: existing coverage (MatchNewArray, MatchArrayPoolRent, MatchStackallocSink, MatchSpanAccess) is expected to suffice. No new sink kinds are anticipated up front; if one is needed, that itself is the SANITISER-MISS signal.

Sanitisers Limes is expected to recognise on this target:

- value-clamp (milestone-J)
- throw-shape (milestone-L)
- throw-shape multi-way-OR (milestone-O)
- loop-guard (milestone-I)

Sanitisers that may be *new* patterns and would trigger an analyzer extension:

- Comparison against `_currentDocumentLength` / region-remaining-bytes (an instance-field bound rather than a buffer-length bound).
- Subtype-byte gating (allocation only when subtype matches a closed set).
- Throw-via-helper indirection the walker can't see through (BmpThrowHelper-style).

---

## Architecture

### Component 1 — Experiment rig

**Path:** `experiments/mongodb-bson/`. Mirrors `experiments/protobuf-net/`.

Layout:

```
experiments/mongodb-bson/
  README.md         # SHA pin (date-stamped), build & run notes
  src/              # SHA-pinned mongo-csharp-driver checkout
  build/            # MongoDB.Bson.dll + transitive deps from `dotnet build`
  rules.yaml        # BSON-specific source/sink rules (Component 2)
  run.sh            # one-liner: limes scan against build/ with rules.yaml
  findings/
    raw.txt         # captured analyzer output
    triage.md       # finding-by-finding classification (Component 3)
```

Build scope: `MongoDB.Bson.csproj` only. The full driver pulls in `MongoDB.Driver`, server discovery, etc. — those are out of scope for a CWE-770 BSON hunt.

SHA pin: latest stable mongo-csharp-driver tag at experiment time, recorded in `README.md` with the date.

Pre-disclosure policy: `experiments/` is already untracked in git status — keep it that way. Do not stage anything from `experiments/mongodb-bson/` to the public limes repo. Drafts and PoCs follow the same rule until upstream publishes.

### Component 2 — `rules.yaml` for BSON

**Path:** `experiments/mongodb-bson/rules.yaml`.

Drafting strategy: start broad with top-level deserialization sources; narrow only if the walker can't reach the read sites.

Broad sources (try first):

- `MongoDB.Bson.Serialization.BsonSerializer::Deserialize<T>(Stream)`
- `MongoDB.Bson.Serialization.BsonSerializer::Deserialize(byte[], …)`
- `MongoDB.Bson.BsonDocument::ReadFrom(IBsonReader)`

Narrow sources (fallback if broad rules yield zero findings):

- `MongoDB.Bson.IO.IBsonReader::ReadString`
- `MongoDB.Bson.IO.IBsonReader::ReadBinaryData`
- `MongoDB.Bson.IO.IBsonReader::ReadBytes`

Sinks: rely on the existing built-in matchers; no rules-file additions for sinks expected.

Sanitisers: no rules-file additions; analyzer-builtin sanitiser matchers cover the expected shapes.

Exact signatures will be filled in once the experiment dir is built and Cecil can produce the precise modreq-stripped short signatures the rules-file validator expects (milestone-N gates this — `in T&` parameters in the BSON reader API surface need that fix in place).

### Component 3 — Triage classification

**Path:** `experiments/mongodb-bson/findings/triage.md`.

Each emitted finding lands in exactly one bucket:

| Bucket | Meaning | Action |
|---|---|---|
| **REAL** | Tainted size flows to allocation, no recognised bound on path, PoC reproduces an oversized allocation | Draft advisory; build PoC under `samples/mongodb-bson-dos-poc/` |
| **SANITISER-MISS** | A bound exists in code but Limes doesn't model it | Add to `analyzer_gap_backlog.md`; in-scope for milestone-P if cheap, else milestone-Q |
| **WALKER-FP** | Known walker limitation (P3 list — linear walker, path sensitivity, async, delegates, reflection) | Note in triage; no analyzer change |
| **OUT-OF-SCOPE** | Rule target is not attacker-reachable (e.g. internal-only serializer, test-fixture path) | Refine rule targeting; no other action |

Stop condition: every finding bucketed; every REAL has a PoC; every SANITISER-MISS is either fixed or logged.

### Component 4 — Optional analyzer extension

If a SANITISER-MISS pattern surfaces and looks cheap (one-shape extension to `MatchValueClamps`, `MatchThrowShape`, or `MatchAll`'s shape menu), implement it inside milestone-P with:

- Two unit tests (positive and negative).
- A synthetic fixture if the pattern is general; an experiment-only re-run if it's BSON-shape-specific.
- Anchor verification (see Verification gate).

If a SANITISER-MISS pattern is structural (requires a new walker capability, a new summary flag, a new sink kind), defer to milestone-Q with a backlog entry that captures the shape and the rough fix approach.

---

## Execution order

1. Stand up `experiments/mongodb-bson/`: clone driver, lock SHA, build `MongoDB.Bson.csproj`. Capture build output in `README.md`.
2. Draft broad `rules.yaml` (top-level `BsonSerializer.Deserialize` sources). Confirm signatures via Cecil.
3. Run Limes; capture raw output to `findings/raw.txt`.
4. If broad rules yield zero findings, swap to `IBsonReader`-level sources and re-run.
5. Triage every finding into the four-bucket schema. Save to `findings/triage.md`.
6. For each REAL: build PoC, draft advisory under `docs/draft-advisory-mongodb-bson-*.md`, file via private channel, save `memory/project_mongodb_bson_advisory.md`.
7. For each cheap SANITISER-MISS: implement fix + tests; re-run anchors; commit.
8. For each expensive SANITISER-MISS: backlog entry only.
9. Verification gate: full unit-test suite green; `--compare` non-strict green on every locked fixture (see Anchors).
10. Close-out: commit only analyzer changes, tests, and backlog updates. Leave `experiments/`, `samples/`, and `docs/draft-advisory-*` untracked.

---

## Verification gate (anchors)

Any analyzer change made inside milestone-P must keep the following green before close-out:

- `imagesharp-307{4,9}-{prefix,postfix}` `--compare` non-strict
- `otelcontrib-{55m9,vc24}-{prefix,postfix}` `--compare` non-strict (55m9 is the canary for HandleCall changes)
- `otelcontrib-opamp-w2jh-{prefix,postfix}` `--compare` non-strict (milestone-I resolver + clamp matcher)
- `otelcontrib-aws-fp-fixed` `--compare` non-strict (milestone-J `AppliedValueClamp` wiring)
- `nbmp-2cwq-pwfr-wcw3-{prefix,postfix}` `--compare` non-strict (milestone-O Shape C Variant 1)
- All synthetic + parquet fixtures
- Full unit-test suite (currently 229: 161 TaintAnalyzer.Tests + 63 ValidateFixture.Tests + new fixture methods, plus any added in this milestone)

---

## Risk paths and stop conditions

- **No findings, structurally clean.** Documented negative result. Useful in itself — first independent validation of milestone-J/L/O sanitiser coverage on a third-party deserializer outside the OTel/MessagePack family. Milestone closes with a `findings/triage.md` recording the broad/narrow runs and zero-findings outcome.
- **Walker can't reach BSON read sites at all.** The gap itself becomes the milestone deliverable: identify root cause (interface dispatch, abstract base type, async state machine, or other), implement fix, re-run. Likely candidates given the IBsonReader interface and the driver's async paths.
- **Finding-flood (>50).** Scope-cut to top-N most likely REAL by manual triage; defer the long tail to milestone-Q with a backlog entry. Don't try to bucket all 50 inside this milestone.
- **REAL finding with no clear fix on upstream's side.** File the advisory anyway; note in memory that disclosure is awaiting maintainer roadmap.

---

## Deliverables summary

| Artifact | Path | Tracked? |
|---|---|---|
| Experiment rig | `experiments/mongodb-bson/` | Untracked |
| Triage notes | `experiments/mongodb-bson/findings/triage.md` | Untracked |
| PoC project (if REAL) | `samples/mongodb-bson-dos-poc/` | Untracked until disclosure |
| Draft advisory (if REAL) | `docs/draft-advisory-mongodb-bson-*.md` | Untracked until disclosure |
| Analyzer fix(es) (if any) | `tools/TaintAnalyzer/` source + tests | Committable |
| Backlog updates | `memory/analyzer_gap_backlog.md` | Saved to memory |
| Advisory memory (if REAL) | `memory/project_mongodb_bson_advisory.md` | Saved to memory |
