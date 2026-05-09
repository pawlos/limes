# Milestone-P Implementation Plan — MongoDB.Bson cold hunt

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run Limes against the MongoDB C# driver's `MongoDB.Bson` namespace, hunting for CWE-770 size-prefix-to-allocation flows analogous to the protobuf-net string-OOM finding from milestone-K. Either produce an advisory-grade finding (REAL) plus any analyzer extension that fell out, or document a clean negative result.

**Architecture:** Stand up `experiments/mongodb-bson/` mirroring `experiments/protobuf-net/` (untracked nupkg-extract layout). Draft a BSON-specific `rules.yaml` covering top-level deserializer entry points, fall back to interface-level sources (`IBsonReader.ReadString`, etc.) if the broad rules yield zero findings. Triage every emitted finding into REAL / SANITISER-MISS / WALKER-FP / OUT-OF-SCOPE. The follow-up phase (PoC, advisory, analyzer extension) is decision-gated on triage output; this plan defines the gate and links to the prior-art templates the follow-up uses.

**Tech Stack:** .NET 10, C#, Mono.Cecil, Limes CLI (`tools/TaintAnalyzer`), nupkg extraction, YAML rules.

**Spec:** `docs/superpowers/specs/2026-05-09-milestone-p-design.md`

---

## File Structure

**Created (untracked under pre-disclosure policy):**
- `experiments/mongodb-bson/README.md` — SHA pin / version pin, build & run notes.
- `experiments/mongodb-bson/lib-nupkg/` — downloaded `MongoDB.Bson.<version>.nupkg`.
- `experiments/mongodb-bson/lib/MongoDB.Bson.dll` (+ `.pdb` if available) — extracted from the nupkg.
- `experiments/mongodb-bson/rules.yaml` — BSON sources + sinks (broad initially, narrow on fallback).
- `experiments/mongodb-bson/run/` — runnable CLI command + output capture.
- `experiments/mongodb-bson/findings/raw.txt` — captured analyzer output.
- `experiments/mongodb-bson/findings/triage.md` — finding-by-finding classification.

**Created conditionally (depending on triage outcome):**
- `samples/mongodb-bson-dos-poc/` — PoC project (only if REAL).
- `docs/draft-advisory-mongodb-bson-*.md` — advisory draft (only if REAL).
- `memory/project_mongodb_bson_advisory.md` — auto-memory entry (only if REAL).

**Modified conditionally:**
- `tools/TaintAnalyzer/...` source + `tools/TaintAnalyzer.Tests/...` — only if a cheap SANITISER-MISS is fixed in-milestone.
- `memory/analyzer_gap_backlog.md` — closure summary + any new gap entries (always updated at close-out).
- `memory/MEMORY.md` — index pointer to any new memory file.

**Untouched (verified at close-out via the anchor gate):**
- All locked fixtures: `imagesharp-307{4,9}-{prefix,postfix}`, `otelcontrib-{55m9,vc24,opamp-w2jh}-{prefix,postfix}`, `otelcontrib-aws-fp-fixed`, `nbmp-2cwq-pwfr-wcw3-{prefix,postfix}`.
- All synthetic + parquet fixtures.

---

## Phase 1 — Experiment rig setup

### Task 1: Create the experiment directory shell

**Files:**
- Create: `experiments/mongodb-bson/README.md`
- Create: `experiments/mongodb-bson/lib-nupkg/.gitkeep` (placeholder; the nupkg will land here)
- Create: `experiments/mongodb-bson/lib/.gitkeep`
- Create: `experiments/mongodb-bson/run/.gitkeep`
- Create: `experiments/mongodb-bson/findings/.gitkeep`

- [ ] **Step 1: Make the directory tree**

```bash
mkdir -p experiments/mongodb-bson/{lib-nupkg,lib,run,findings}
touch experiments/mongodb-bson/lib-nupkg/.gitkeep
touch experiments/mongodb-bson/lib/.gitkeep
touch experiments/mongodb-bson/run/.gitkeep
touch experiments/mongodb-bson/findings/.gitkeep
```

- [ ] **Step 2: Verify `experiments/` remains untracked**

Run: `git check-ignore -v experiments/mongodb-bson/README.md` and inspect.
Expected: either an `.gitignore` rule reports a match, OR `git status --short experiments/mongodb-bson/` shows `??` (untracked) and we leave it that way (precedent: `experiments/protobuf-net/` is currently untracked, not gitignored).

If `experiments/` is currently untracked rather than gitignored, do NOT add a `.gitignore` rule — match the existing convention. Just confirm `git status` shows the new path as untracked and move on.

- [ ] **Step 3: Write `README.md` skeleton**

Create `experiments/mongodb-bson/README.md` with this content (the version pin gets filled in Task 2):

```markdown
# MongoDB.Bson cold-hunt experiment

**Milestone:** P (2026-05-09)

**Target:** `MongoDB.Bson` (NuGet) — BSON binary reader path. Hunt for CWE-770 size-prefix-to-allocation analogous to protobuf-net string OOM (milestone-K).

**Pin:** `MongoDB.Bson <VERSION>` — `<NUPKG-FILENAME>` — fetched <DATE>.

**Pre-disclosure policy:** This directory is untracked. Do not stage. Findings → `findings/triage.md`. If a REAL finding emerges, draft advisory under `docs/draft-advisory-mongodb-bson-*.md` (also untracked).

## Layout

- `lib-nupkg/` — downloaded NuGet package (`.nupkg`).
- `lib/` — extracted assemblies for Limes to scan.
- `rules.yaml` — BSON sources + sinks for this run.
- `run/` — invocation script + raw output.
- `findings/` — triage notes.

## Build / fetch

See Phase 1 Task 2 of `docs/superpowers/plans/2026-05-09-milestone-p.md`.

## Run

See Phase 3 Task 6 of the plan.
```

- [ ] **Step 4: Do NOT commit**

Per spec section 3, this directory stays untracked. Run `git status --short experiments/mongodb-bson/` and confirm everything shows `??`. Do not `git add`.

---

### Task 2: Pin a MongoDB.Bson version and download the nupkg

**Files:**
- Create: `experiments/mongodb-bson/lib-nupkg/MongoDB.Bson.<VERSION>.nupkg`
- Modify: `experiments/mongodb-bson/README.md` (fill the `<VERSION>`/`<DATE>` placeholders)

- [ ] **Step 1: Identify the latest stable MongoDB.Bson version**

Run:

```bash
curl -sSL https://api.nuget.org/v3-flatcontainer/mongodb.bson/index.json | jq -r '.versions | map(select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))) | last'
```

Capture the version string (e.g. `3.2.0`). Record it as `<VERSION>` for subsequent steps.

If `jq` is unavailable, view the JSON manually and pick the highest non-prerelease version.

- [ ] **Step 2: Download the nupkg**

```bash
VERSION=<from Step 1>
cd experiments/mongodb-bson/lib-nupkg
curl -sSLO "https://api.nuget.org/v3-flatcontainer/mongodb.bson/${VERSION}/mongodb.bson.${VERSION}.nupkg"
ls -l "mongodb.bson.${VERSION}.nupkg"
```

Expected: a non-empty `.nupkg` file (~hundreds of KB).

- [ ] **Step 3: Update `README.md` with version + date**

Replace the placeholders in `experiments/mongodb-bson/README.md`:
- `<VERSION>` → e.g. `3.2.0`
- `<NUPKG-FILENAME>` → e.g. `mongodb.bson.3.2.0.nupkg`
- `<DATE>` → today's date (`2026-05-09` or whatever it is at execution time)

---

### Task 3: Extract the assembly from the nupkg

**Files:**
- Create: `experiments/mongodb-bson/lib/MongoDB.Bson.dll`
- Create: `experiments/mongodb-bson/lib/MongoDB.Bson.pdb` (if present in nupkg)

- [ ] **Step 1: Inspect nupkg contents**

```bash
cd experiments/mongodb-bson
unzip -l "lib-nupkg/mongodb.bson.<VERSION>.nupkg" | grep -E '\.(dll|pdb)$'
```

Expected: multiple TFM-suffixed copies (e.g. `lib/netstandard2.0/MongoDB.Bson.dll`, `lib/net6.0/MongoDB.Bson.dll`). Pick the highest TFM available (the analyzer is .NET 10, but the assembly TFM only matters for what runtime APIs the IL references — pick `net6.0` or higher if present, else `netstandard2.1`, else `netstandard2.0`).

- [ ] **Step 2: Extract the chosen DLL (and PDB if present)**

```bash
cd experiments/mongodb-bson
TFM=<from Step 1, e.g. net6.0>
unzip -j -o "lib-nupkg/mongodb.bson.<VERSION>.nupkg" "lib/${TFM}/MongoDB.Bson.dll" "lib/${TFM}/MongoDB.Bson.pdb" -d lib/ 2>/dev/null || \
  unzip -j -o "lib-nupkg/mongodb.bson.<VERSION>.nupkg" "lib/${TFM}/MongoDB.Bson.dll" -d lib/
ls -l lib/
```

Expected: `lib/MongoDB.Bson.dll` exists. PDB is best-effort.

- [ ] **Step 3: Sanity-check the assembly**

```bash
file experiments/mongodb-bson/lib/MongoDB.Bson.dll
```

Expected: identifies as a PE32+ executable (.NET assembly). If the file command says something else, the extraction picked the wrong path; redo Step 2.

- [ ] **Step 4: Record the chosen TFM in `README.md`**

Append to `experiments/mongodb-bson/README.md`:

```markdown
**Extracted from:** `lib/<TFM>/MongoDB.Bson.dll` inside the nupkg.
```

---

## Phase 2 — Draft initial `rules.yaml`

### Task 4: Survey BSON read-path APIs in the assembly

**Files:**
- Modify: `experiments/mongodb-bson/README.md` (record the API surface notes)

- [ ] **Step 1: Dump candidate source method signatures using Cecil**

Use `dotnet-ildasm` if installed, or a quick Cecil one-liner via the analyzer's existing tooling. The simplest path is `ildasm`-style listing via .NET SDK:

```bash
cd experiments/mongodb-bson/lib
dotnet tool run dotnet-ildasm MongoDB.Bson.dll 2>/dev/null | grep -E "Deserialize|ReadString|ReadBinaryData|ReadBytes" | head -40
```

If `dotnet-ildasm` isn't installed, use `mono-cil-strip --help`-style alternatives, or write a 5-line Cecil dump under `experiments/mongodb-bson/run/dump-signatures.cs`. The goal is to see the exact `MongoDB.Bson.Serialization.BsonSerializer::Deserialize` overload set and the `IBsonReader` / `BsonBinaryReader` read methods.

Record the signatures (or a representative sample) in the experiment README under a `## API surface` section.

- [ ] **Step 2: Note any modreq surprises**

If signatures contain `modreq(InAttribute)` (`in T&` parameters), confirm milestone-N's `BuildShortSignature` strip handles them — these should appear as `T&` in the rules file. The validator's no-spaces rule applies (rules-file shape gate).

If a target signature contains a space (e.g. for nested generics), pick a different overload or escalate — milestone-N closes the modreq gap but not the no-space rule.

---

### Task 5: Write the broad `rules.yaml`

**Files:**
- Create: `experiments/mongodb-bson/rules.yaml`

- [ ] **Step 1: Mirror `experiments/protobuf-net/rules.yaml` structure**

Reference: `experiments/protobuf-net/rules.yaml` uses a single-vuln file with `vuln_id` + `source_methods` (and the engine matches sinks via built-in matchers). Mirror that.

Create `experiments/mongodb-bson/rules.yaml`:

```yaml
vuln_id: mongodb-bson-size-prefix-allocation
source_methods:
  # Top-level deserializer entry points — broad coverage of consumer code.
  # Exact signatures are filled in from Task 4's API surface dump; below are placeholders
  # showing the expected shape. Replace with the actual overloads from Cecil.
  - MongoDB.Bson.Serialization.BsonSerializer::Deserialize<T>(System.IO.Stream)
  - MongoDB.Bson.Serialization.BsonSerializer::Deserialize(System.Byte[],System.Type)
  - MongoDB.Bson.BsonDocument::ReadFrom(MongoDB.Bson.IO.IBsonReader)
```

The exact signatures depend on the version pinned in Task 2 — copy them verbatim from Task 4's signature dump. Do not paraphrase. The rules-file validator rejects signatures with spaces; if a signature has a space, pick a non-overloaded alternative or use a different entry point.

- [ ] **Step 2: Validate the rules file shape**

Run a quick sanity build of the analyzer to make sure the rules parse:

```bash
cd /mnt/c/work/dotnet-taint-analyzer
dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj -c Release 2>&1 | tail -5
```

Expected: build succeeds (no analyzer code changes yet, just confirming we have a buildable binary for Phase 3).

---

## Phase 3 — Run Limes and capture output

### Task 6: Execute the analyzer against MongoDB.Bson

**Files:**
- Create: `experiments/mongodb-bson/run/scan.sh`
- Create: `experiments/mongodb-bson/findings/raw.txt`
- Create: `experiments/mongodb-bson/findings/trace.yaml` (the analyzer's `--output`)

- [ ] **Step 1: Write the run script**

Create `experiments/mongodb-bson/run/scan.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
ANALYZER="${ROOT}/tools/TaintAnalyzer/bin/Release/net10.0/TaintAnalyzer.dll"

if [[ ! -f "${ANALYZER}" ]]; then
  echo "analyzer not built — run: dotnet build tools/TaintAnalyzer/TaintAnalyzer.csproj -c Release" >&2
  exit 1
fi

dotnet "${ANALYZER}" "${HERE}/lib/MongoDB.Bson.dll" \
  --rules "${HERE}/rules.yaml" \
  --output "${HERE}/findings/trace.yaml" \
  2>&1 | tee "${HERE}/findings/raw.txt"
```

```bash
chmod +x experiments/mongodb-bson/run/scan.sh
```

- [ ] **Step 2: Run the scan**

```bash
experiments/mongodb-bson/run/scan.sh
```

Expected: the analyzer either emits findings to `trace.yaml` or exits cleanly with no findings. Inspect:

```bash
ls -l experiments/mongodb-bson/findings/
wc -l experiments/mongodb-bson/findings/trace.yaml
head -40 experiments/mongodb-bson/findings/raw.txt
```

- [ ] **Step 3: Decision gate — broad-rules outcome**

If `trace.yaml` is empty (zero findings) AND `raw.txt` shows the analyzer reached the source methods (look for the source method name in stderr/stdout): proceed to Phase 4 with the negative-result triage path.

If `trace.yaml` is empty AND `raw.txt` shows the analyzer never reached the source methods (e.g. zero hops emitted, source method not found): proceed to Task 7 (narrow-rules fallback).

If `trace.yaml` has findings: proceed to Phase 4 with the findings triage path.

---

### Task 7 (fallback): Narrow rules — `IBsonReader` direct sources

**Files:**
- Modify: `experiments/mongodb-bson/rules.yaml`

Skip this task if Task 6 produced findings or a clean reach-but-no-findings result.

- [ ] **Step 1: Add interface-level sources**

Replace the broad `source_methods` block in `rules.yaml` with:

```yaml
vuln_id: mongodb-bson-size-prefix-allocation
source_methods:
  # Narrow — direct sources at the byte-stream interface. Use only when broad sources
  # didn't reach the read sites.
  - MongoDB.Bson.IO.IBsonReader::ReadString
  - MongoDB.Bson.IO.IBsonReader::ReadBinaryData
  - MongoDB.Bson.IO.IBsonReader::ReadBytes(System.Int32)
```

Exact signatures: pull from Task 4's dump. Note that `IBsonReader` is an interface — Limes' resolver should virtualise to the concrete `BsonBinaryReader` impl. If it doesn't, that's an analyzer-extension trigger (likely a milestone-I-class resolver gap, deferred).

- [ ] **Step 2: Re-run the scan**

```bash
experiments/mongodb-bson/run/scan.sh
```

Expected: either findings or a clean zero-findings result (now reaching the read sites).

- [ ] **Step 3: Record which rule set produced the final output**

Append to `experiments/mongodb-bson/README.md`:

```markdown
**Final rules used:** broad / narrow (delete one). Rationale: <why>.
```

---

## Phase 4 — Triage

### Task 8: Bucket every finding

**Files:**
- Create: `experiments/mongodb-bson/findings/triage.md`

- [ ] **Step 1: Open the trace.yaml and enumerate findings**

```bash
grep -E "^vuln_id|^- vuln_id|method:" experiments/mongodb-bson/findings/trace.yaml | head -40
```

Each finding has a sink + a path. Count findings:

```bash
grep -c "^path:" experiments/mongodb-bson/findings/trace.yaml || true
```

If zero, skip to Step 4 (negative-result write-up).

- [ ] **Step 2: For each finding, decide a bucket**

For each finding, open the relevant BSON source file in the unpacked driver source (or the decompiled DLL via `ilspycmd` / similar) and read the surrounding code. Decide:

- **REAL** — tainted size flows to allocation, no recognised bound on path, code review confirms the bound is missing in source. Aim to reproduce with a PoC payload before classifying as REAL.
- **SANITISER-MISS** — bound IS present in source, but Limes didn't recognise the shape. Note the shape (e.g. "comparison against `_currentDocumentLength` field", "subtype-byte gating", "throw-via-helper").
- **WALKER-FP** — known walker limitation (linear-walker stack desync, path insensitivity, async edge case, delegate flow, reflection). Refer to `analyzer_gap_backlog.md` P3 list to identify.
- **OUT-OF-SCOPE** — source method isn't reachable from attacker-controlled input (e.g. internal-only serializer, test-fixture path).

- [ ] **Step 3: Write `triage.md`**

Create `experiments/mongodb-bson/findings/triage.md` using this skeleton (one entry per finding):

```markdown
# MongoDB.Bson — Triage

**Run:** <date>
**Rules:** broad / narrow
**Total findings:** N

## Summary

| Bucket | Count |
|---|---|
| REAL | |
| SANITISER-MISS | |
| WALKER-FP | |
| OUT-OF-SCOPE | |

## Findings

### Finding 1 — <sink method>:<line>

- **Source method:** <full signature>
- **Sink:** <method+line>
- **Path summary:** <hops in 1 line>
- **Bucket:** REAL / SANITISER-MISS / WALKER-FP / OUT-OF-SCOPE
- **Rationale:** <why this bucket>
- **Follow-up:** <PoC needed / sanitiser shape to add / backlog entry / refine rule>

### Finding 2 — ...
```

Fill in each finding from Step 2.

- [ ] **Step 4: If zero findings — write the negative-result triage**

If both broad and (if attempted) narrow runs produced zero findings AND the raw output shows the analyzer reached the source methods, write `triage.md` with this content:

```markdown
# MongoDB.Bson — Triage

**Run:** <date>
**Rules:** broad / narrow / both
**Total findings:** 0

## Outcome

The analyzer reached the BSON read sites and emitted no findings. Spot-checked
read sites in `MongoDB.Bson.IO.BsonBinaryReader`:

- `ReadString()` at <file:line> — bounded by <which sanitiser shape Limes recognised>
- `ReadBinaryData()` at <file:line> — bounded by <…>
- (others)

This is the first independent validation that milestone-J (value-clamp) /
milestone-L (throw-shape) / milestone-O (multi-way-OR throw) sanitiser coverage
holds on a third-party deserializer outside the OTel/MessagePack family.
```

Fill in from manual code review of the BSON read sites.

- [ ] **Step 5: Decision gate — what comes next**

Based on `triage.md`:

- **Any REAL finding** → Phase 5a (PoC + advisory).
- **Any cheap SANITISER-MISS** (one-shape extension to existing matchers) → Phase 5b (analyzer extension).
- **Any expensive SANITISER-MISS** (new walker capability / new sink kind) → backlog entry only; Phase 5b skipped.
- **Only WALKER-FP / OUT-OF-SCOPE / zero findings** → Phase 5c (negative-result close-out).

Multiple branches can fire in the same milestone — execute Phase 5a first if applicable, then 5b, then 5c.

---

## Phase 5a — REAL finding follow-up (conditional)

Skip this phase if no REAL finding emerged.

### Task 9: Build a PoC

**Files:**
- Create: `samples/mongodb-bson-dos-poc/Program.cs`
- Create: `samples/mongodb-bson-dos-poc/mongodb-bson-dos-poc.csproj`

- [ ] **Step 1: Set up the PoC project**

Mirror `samples/mpcs-datetime-dos-poc/` (per memory `project_mpcs_advisory.md`).

```bash
mkdir -p samples/mongodb-bson-dos-poc
cd samples/mongodb-bson-dos-poc
dotnet new console -f net10.0 --no-restore
```

- [ ] **Step 2: Add the MongoDB.Bson dependency**

Edit `samples/mongodb-bson-dos-poc/mongodb-bson-dos-poc.csproj` to add:

```xml
<ItemGroup>
  <PackageReference Include="MongoDB.Bson" Version="<VERSION-from-Phase-1>" />
</ItemGroup>
```

- [ ] **Step 3: Write the smallest payload that reproduces the allocation**

Replace `Program.cs` with the minimal repro. Shape (from the triaged finding):

```csharp
using System.Threading.Tasks;
using MongoDB.Bson;
using MongoDB.Bson.IO;

byte[] payload = /* crafted BSON bytes per finding */;
await Task.Run(() =>
{
    using var stream = new System.IO.MemoryStream(payload);
    using var reader = new BsonBinaryReader(stream);
    // call the specific BSON read API the finding identified
});
```

Tailor the payload bytes to the finding (e.g. an int32 length of `0x7FFFFFFF` followed by truncated bytes).

- [ ] **Step 4: Verify the PoC reproduces**

```bash
cd samples/mongodb-bson-dos-poc
dotnet run -c Release
```

Expected: `OutOfMemoryException`, `StackOverflowException` (exit 134 on Linux), or measurable >>buffer-size allocation visible in process metrics. Document the exact failure mode in the README under `samples/mongodb-bson-dos-poc/README.md`.

- [ ] **Step 5: Do NOT commit**

Per pre-disclosure policy: `samples/mongodb-bson-dos-poc/` stays untracked until upstream publishes a fix. Confirm `git status` shows `??`.

---

### Task 10: Draft the advisory

**Files:**
- Create: `docs/draft-advisory-mongodb-bson-<short-name>.md`

- [ ] **Step 1: Mirror `docs/draft-advisory-mpcs-datetime-stackalloc.md`**

Use that file as a template. Fill in:
- Affected version range (specific — e.g. "≤ 3.2.0", or a precise lower bound if `git log` on the driver shows when the bug was introduced).
- Root cause (the exact line / method).
- CWE (likely CWE-770 or CWE-789).
- CVSS v3.1 vector (typical for unauthenticated DoS: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → 7.5).
- PoC reference: `samples/mongodb-bson-dos-poc/`.
- Suggested fix (length validation against region size or buffer length).

Per memory `project_mpcs_advisory.md`: state affected versions precisely (e.g. "3.0.0 – 3.2.0", not "≤ 3.2.0"), if the lower bound is identifiable.

- [ ] **Step 2: Identify the affected version range**

Use `git log` on the unpacked driver source to find when the bug was introduced. Pin a lower-bound version. If the bug is in a method that has existed since project inception, the lower bound is the first published version — say so explicitly.

- [ ] **Step 3: Mark as DRAFT and pre-disclosure**

Header at the top:

```markdown
> **Status:** DRAFT — not submitted.
>
> **Do not commit this file to a public repository before the advisory is published.**
```

- [ ] **Step 4: Submit via private channel**

Submit to maintainers via either GitHub draft Security Advisory (preferred) or private email — match the precedent from `project_protobuf_net_advisory.md` / `project_mpcs_advisory.md`.

Decision criterion (per recent practice): GitHub draft GHSA if the project has Security Advisories enabled; private email otherwise.

After submission, update the advisory file's status header from `DRAFT` to the submission channel + date.

---

### Task 11: Save advisory memory

**Files:**
- Create: `memory/project_mongodb_bson_advisory.md`
- Modify: `memory/MEMORY.md`

- [ ] **Step 1: Write the advisory memory**

Mirror `memory/project_protobuf_net_advisory.md`'s structure. Fields:

```markdown
---
name: MongoDB.Bson advisory status
description: Status of the MongoDB.Bson <short-name> advisory — affected version range, root cause, channel
type: project
---

Vulnerability in `MongoDB.Bson` (NuGet, <version range>) — <one-line root cause>.
CWE-<num>. CVSS <score>. Found via Limes (<which milestone capability matched>).

**Advisory:** `docs/draft-advisory-mongodb-bson-<short-name>.md` — submitted via <channel> <date>.
As of <today> awaiting maintainer response / fix.

**PoC:** `samples/mongodb-bson-dos-poc/`.
**Pin:** MongoDB.Bson <version> (`experiments/mongodb-bson/`).

**Why:** <stake>
**How to apply:** Treat as in-flight (waiting on upstream).
```

- [ ] **Step 2: Add an index entry to `MEMORY.md`**

Append a single line:

```markdown
- [MongoDB.Bson advisory status](project_mongodb_bson_advisory.md) — <short summary> (CWE-<num>); <channel> sent; awaiting maintainer response
```

---

## Phase 5b — Cheap SANITISER-MISS analyzer extension (conditional handoff)

Skip this phase entirely if no SANITISER-MISS surfaced.

This phase is intentionally **not** specified as concrete tasks here. The exact missed-sanitiser shape — and therefore the exact matcher to extend, the exact fixture to add, and the exact unit test to write — is unknown until Phase 4 triage produces it. Writing speculative code in this plan would be a placeholder violation.

Instead, after Phase 4 triage identifies a SANITISER-MISS:

### Task 12: Generate a follow-up plan from the triage output

**Files:** none in this plan

- [ ] **Step 1: Decide cheap vs expensive**

"Cheap" SANITISER-MISS = one shape variant added to an existing matcher (e.g. an additional comparison opcode in `MatchValueClamps`, an additional shape variant in the multi-way-OR throw detection from milestone-O).

"Expensive" SANITISER-MISS = requires a new `MethodSummary` flag, a new sink kind, or a new walker capability.

If expensive: add to `analyzer_gap_backlog.md` as a P-prime entry and skip the rest of this phase. The fix is deferred to milestone-Q.

If cheap: continue.

- [ ] **Step 2: Generate a fresh implementation plan for the cheap fix**

Re-invoke the brainstorming → writing-plans flow with the triage entry as the spec input. The new plan goes to `docs/superpowers/plans/2026-05-09-milestone-p-shape-<short-name>.md` and follows the same TDD shape as the milestone-J / milestone-L / milestone-O plans:

1. Add a fixture method exhibiting the missed shape to `tools/TaintAnalyzer.Tests.Fixtures/Fixtures.cs`.
2. Write a failing unit test asserting the matcher recognises the shape.
3. Implement the matcher extension in the appropriate file.
4. Verify the test passes.
5. Run the full test suite (baseline 229) — no regressions.
6. Run the anchor gate (Phase 6 Task 15 of THIS plan).
7. Re-run the experiment; confirm the triaged SANITISER-MISS finding is silenced.
8. Commit with message `analyzer: milestone-P — <shape summary>`.

The reason this is a separate plan: the steps above can only be made concrete (with code blocks, file:line references, and exact test signatures) once the shape is known. Templates: see `docs/superpowers/specs/2026-05-06-milestone-j-design.md` (`AppliedValueClamp`), `docs/superpowers/plans/2026-05-06-milestone-i.md` Tasks 11–14 (`MatchValueClamps`), and the milestone-L/M/N/O commits (`d2dc234`, `2ef5ce5`, `a373718`, `cba47af`) for working precedents.

- [ ] **Step 3: Execute the follow-up plan**

Hand the new plan off to subagent-driven-development or executing-plans, same as the present plan.

---

## Phase 5c — Negative-result close-out (conditional)

Run this phase if the milestone produced no REAL findings AND no analyzer extensions. (If either Phase 5a or 5b ran, skip Phase 5c — close-out is folded into Phase 6.)

### Task 13: Document the negative result

**Files:**
- Create: `docs/mongodb-bson-cold-hunt-2026-05-09.md` (or whatever date)

- [ ] **Step 1: Write the negative-result writeup**

Mirror `docs/nbmp-mpcs-datetime-stackalloc-2026-05-07.md`'s structure (research-note shape).

Content:
- Date, target version, run command.
- API surface scanned.
- Sanitiser shapes Limes recognised at each read site (specific: which milestone capability matched at which line).
- Conclusion: this is independent validation that milestones J / L / O hold on a third-party deserializer.

- [ ] **Step 2: Commit the writeup**

```bash
git add docs/mongodb-bson-cold-hunt-<date>.md
git commit -m "$(cat <<'EOF'
docs: milestone-P negative-result writeup — MongoDB.Bson cold hunt

No findings; first independent validation of milestone-J/L/O sanitiser
coverage on a third-party deserializer outside the OTel/MessagePack family.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 6 — Anchor verification & memory updates

### Task 14: Run the full anchor gate

**Files:** none (verification only)

- [ ] **Step 1: Run the unit-test suite**

```bash
cd /mnt/c/work/dotnet-taint-analyzer
dotnet test 2>&1 | tail -20
```

Expected: all tests pass (baseline 229 + any added in Phase 5b).

- [ ] **Step 2: Run `--compare` non-strict on every locked fixture**

The locked fixtures (per `analyzer_gap_backlog.md` "Anchor: what NOT to break"):

```bash
for f in \
  imagesharp-3074-prefix imagesharp-3074-postfix \
  imagesharp-3079-prefix imagesharp-3079-postfix \
  otelcontrib-55m9-prefix otelcontrib-55m9-postfix \
  otelcontrib-vc24-prefix otelcontrib-vc24-postfix \
  otelcontrib-opamp-w2jh-prefix otelcontrib-opamp-w2jh-postfix \
  otelcontrib-aws-fp-fixed \
  nbmp-2cwq-pwfr-wcw3-prefix nbmp-2cwq-pwfr-wcw3-postfix \
  ; do
  echo "=== ${f} ==="
  # invoke whatever the project's standard --compare runner is; reference past
  # milestones' spec docs (e.g. milestone-J spec section "Verification") for the exact command.
done
```

If the project has a `scripts/run-compare-all.sh` (or the test suite runs `--compare` automatically), use that instead.

Expected: every fixture green.

- [ ] **Step 3: Synthetic + parquet fixtures**

Confirm the synthetic and parquet fixtures pass. The unit-test suite from Step 1 may already cover these — confirm via the test names.

---

### Task 15: Update backlog memory

**Files:**
- Modify: `memory/analyzer_gap_backlog.md`

- [ ] **Step 1: Append milestone-P closure summary**

Add a section to `memory/analyzer_gap_backlog.md` matching the existing "milestone-N", "milestone-O" closure-summary blocks. Include:
- One-line outcome (REAL found / no findings / etc.).
- Any new SANITISER-MISS gap added (with shape note + fix approach).
- Any backlog entries that flipped to "closed by milestone-P".

- [ ] **Step 2: Update the MEMORY.md index entry**

Adjust the `analyzer_gap_backlog.md` index line in `memory/MEMORY.md` to reflect the new state ("post-milestone-P (2026-05-09); …").

---

### Task 16: Final commit & milestone close-out

**Files:** none new

- [ ] **Step 1: Commit memory updates**

Memory files live under `~/.claude/projects/.../memory/` — they're not part of the project repo, so no commit. They persist via the auto-memory system.

If any project-repo files changed (analyzer source, tests, docs writeup), confirm they're committed. Run:

```bash
git status
```

Expected: clean working tree (modulo the untracked `experiments/`, untracked `samples/` if Phase 5a ran, untracked `docs/draft-advisory-*` if Phase 5a ran).

- [ ] **Step 2: Final close-out summary**

Produce a one-paragraph summary of milestone-P outcomes. Save to `experiments/mongodb-bson/findings/SUMMARY.md` (untracked). Sample shape:

```markdown
# Milestone-P close-out — <date>

- **Pin:** MongoDB.Bson <version>.
- **Findings:** <N total — bucket counts>.
- **Advisory:** filed / not applicable.
- **Analyzer extension:** <commit SHA> — <one-line shape> / not applicable.
- **Net:** <one-line outcome>.
```

---

## Self-review (run before handing off to execution)

- **Spec coverage:** ✓ Goals 1–6 of the spec are covered: Goal 1 by Tasks 1–3; Goal 2 by Tasks 4–5; Goal 3 by Tasks 6–8; Goal 4 by Tasks 9–11; Goal 5 by Task 12 (handoff to follow-up plan if a cheap SANITISER-MISS surfaces); Goal 6 by Task 15.
- **Conditional phases:** Phases 5a/5b/5c are explicitly gated on triage outcome. Each branch is reachable from the Task 8 Step 5 decision gate.
- **Anchors:** Task 14 enforces the verification gate before close-out, matching the spec's Verification gate section.
- **Pre-disclosure compliance:** Tasks 1, 4, 9, 10 all explicitly mark their outputs as untracked. The only committable artifacts are analyzer source/test changes (Phase 5b) and the negative-result writeup (Phase 5c) — both compliant with `project_overview.md`'s pre-disclosure policy.
- **Templates over guesses:** Phase 5b deliberately defers concrete tasks to a follow-up plan generated from triage output, with milestone-J/L/O explicitly named as precedents. This is an honest handoff, not a placeholder — the shape is genuinely unknown until triage runs.
