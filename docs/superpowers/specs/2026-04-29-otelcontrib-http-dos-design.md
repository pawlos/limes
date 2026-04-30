# Milestone-H — HTTP response DoS detection (design)

**Status:** Approved 2026-04-29.

**One-liner:** Extend the analyzer to detect unbounded HTTP response body reads (CWE-770) by adding a `taint_from_external_returns` source annotation and two new HTTP sink shapes, then produce fixture pairs for GHSA-55m9-299j-53c7 and GHSA-vc24-j8c5-2vw4, followed by a broad scan of HTTP-adjacent OpenTelemetry packages.

---

## Motivation

Two disclosed OpenTelemetry advisories share the same root cause as the ImageSharp CVEs: attacker-controlled data (HTTP response body) flows into an unbounded allocation without a size cap. The analyzer cannot currently detect this class because:

1. **Source model gap.** Our sources are decoder entry points where attacker-controlled data arrives as a `Stream`/`ReadOnlySpan<byte>` parameter. For HTTP response reading, the attacker-controlled data is the *return value* of `HttpClient.Send/SendAsync/GetStringAsync` — not any input parameter.
2. **Sink model gap.** Our sinks are explicit IL allocations (`newarr`, `ArrayPool.Rent`, `localloc`). `HttpContent.ReadAsStringAsync()` and `HttpClient.GetStringAsync()` are BCL methods that allocate internally; no explicit `new byte[]` appears in the library IL.

This milestone adds the minimum extension to detect both patterns and validates them with real pre/post-fix fixture pairs.

## Goals

1. `SourceMethodEntry` in `RulesDocument.cs` gains `taint_from_external_returns: [TypeName::MethodName, ...]` — an optional list of external method names whose return values are unconditionally tainted during a walk started from this source.
2. `TaintWalker.HandleCall` uses the list when processing external calls: if the callee matches any entry, it pushes a tainted return regardless of input taint.
3. Two new `SinkApi` values (`HttpContentRead`, `HttpClientRead`) added under `SinkKind.Allocation`, with a new `SinkShapes.MatchHttpRead` matcher that fires on tainted `HttpContent`/`HttpClient` receivers.
4. Four fixture pairs authored from real pre/post-fix OpenTelemetry DLLs:
   - `otelcontrib-55m9-{prefix,postfix}` — GHSA-55m9-299j-53c7 (`HttpJsonPostTransport`)
   - `otelcontrib-vc24-{prefix,postfix}` — GHSA-vc24-j8c5-2vw4 (`AzureVmMetaDataRequestor`)
5. Validator `SinkApis` closed vocab and coupling rules updated for the two new values.
6. Phase 2: broad scan of 7 HTTP-adjacent OpenTelemetry contrib packages — analysis artifact, no new code.

## Non-goals

- Detecting HTTP request body DoS (we're the client, we control the request).
- Modeling `HttpClient` as globally tainted (the `taint_from_external_returns` annotation is per-source-entry, not global).
- Fixing walker traversal depth to reach `ReadInternationalTextChunk` (separate issue).
- Scanning the core `opentelemetry-dotnet` repo (deferred; contrib is the priority).

---

## Architecture

### Component 1: `taint_from_external_returns` source annotation

**Files:** `tools/TaintAnalyzer/RulesDocument.cs`, `tools/TaintAnalyzer/TaintWalker.cs`, `tools/TaintAnalyzer/Program.cs`

`SourceMethodEntry` gains one new optional field:

```csharp
public List<string>? TaintFromExternalReturns { get; init; }
```

YAML shape (backward-compatible — field is optional):

```yaml
source_methods:
  - signature: SomeNamespace.HttpJsonPostTransport::SendExportRequest(System.Net.Http.HttpRequestMessage)
    taint_from_external_returns:
      - HttpClient::Send
      - HttpClient::SendAsync
```

Each entry is matched as `DeclaringType.Name::MethodName` — class name without namespace, matches any overload. Matching logic in `HandleCall`'s external branch:

```csharp
bool matchesTaintSource = _taintFromExternalReturns.Any(entry =>
{
    var sep = entry.IndexOf("::", StringComparison.Ordinal);
    if (sep < 0) return callee.Name == entry;
    return callee.DeclaringType.Name == entry[..sep]
        && callee.Name == entry[(sep + 2)..];
});
if (!IsVoidReturn(callee) && (anyTaintedInput || matchesTaintSource))
{
    // push tainted return (existing path)
}
```

`TaintWalker` gains a public settable property `TaintFromExternalReturns` backed by a private field (defaulting to `Array.Empty<string>()`). `Program.cs` sets it before each `WalkWithSeed` call:

```csharp
walker.TaintFromExternalReturns = entry.TaintFromExternalReturns
    ?? (IReadOnlyList<string>)Array.Empty<string>();
```

Setting via property (rather than threading through `WalkWithSeed`) keeps the existing call-chain signature unchanged and is safe because the walker is constructed fresh per analysis run in `Program.cs`.

The identity hop at the external call boundary is still emitted normally (the `_taintFromExternalReturns` match only affects the tainted-return push, not the hop emission).

**Tests:** Two new unit tests in `TaintWalkerTests.cs`:
- One sets `walker.TaintFromExternalReturns = ["HttpClient::GetStringAsync"]` and walks a fixture method that calls `System.Net.Http.HttpClient.GetStringAsync(url)` on an untainted receiver, asserting the return is treated as tainted (sink fires).
- One leaves `TaintFromExternalReturns` empty and asserts the same call produces no taint (guard).

The fixture class in `Fixtures.cs` references `System.Net.Http.HttpClient` (already in .NET BCL); no new project references needed.

### Component 2: HTTP content read sinks

**Files:** `tools/TaintAnalyzer/HopRecord.cs` (`SinkApi` enum), `tools/TaintAnalyzer/SinkShapes.cs`, `tools/ValidateFixture/FixtureValidator.cs`

Two new `SinkApi` values:

```csharp
HttpContentRead,  // HttpContent.ReadAsStringAsync / ReadAsByteArrayAsync / ReadAsStreamAsync
HttpClientRead,   // HttpClient.GetStringAsync / GetByteArrayAsync / GetStreamAsync
```

Both under `SinkKind.Allocation` — semantically unbounded allocations, implicit inside BCL.

**Design note — unconditional match:** Unlike existing sinks (which require a tainted operand), `MatchHttpRead` fires on any call to the listed methods regardless of receiver taint. This handles the Azure case (`httpClient` is a fresh untainted local) and the OneCollector case (where `response.Content` is tainted). Noise from firing in unrelated code is controlled by source-entry selection — these sinks only matter when the walker was started from an HTTP handler entry point.

New matcher in `SinkShapes.cs`:

```csharp
public static SinkMatch? MatchHttpRead(Instruction instruction, SymbolicStack stack)
{
    if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt)) return null;
    var mr = (MethodReference)instruction.Operand;
    var typeName = mr.DeclaringType.Name;
    var methodName = mr.Name;

    SinkApi? api = (typeName, methodName) switch
    {
        ("HttpContent", "ReadAsStringAsync" or "ReadAsByteArrayAsync" or "ReadAsStreamAsync")
            => SinkApi.HttpContentRead,
        ("HttpClient", "GetStringAsync" or "GetByteArrayAsync" or "GetStreamAsync")
            => SinkApi.HttpClientRead,
        _ => null
    };
    if (api is null) return null;

    // No receiver taint check — the call itself is the dangerous operation regardless of
    // whether the HttpClient/HttpContent is tracked as tainted. Noise is controlled by
    // source-entry selection in rules.yaml (only active inside HTTP handler walks).
    // Retrieve receiver provenance for the trace; may be untainted in the Azure case.
    int paramCount = mr.Parameters.Count;
    if (stack.Depth < paramCount + 1) return null;
    var receiver = stack.Peek(paramCount);
    var provenance = receiver.Tainted ? receiver.Provenance : mr.DeclaringType.Name;

    return new SinkMatch
    {
        Kind = SinkKind.Allocation,
        Api = api.Value,
        SizeProvenance = provenance, // response object or type name; no explicit size in IL
    };
}
```

`SinkMatch` (or equivalent) carries `SizeExpression = receiver.Provenance` — the tainted `HttpContent`/`HttpClient` object's provenance string. This becomes the `size_expression` in the trace YAML, pointing at the tainted response object rather than a numeric size (since no explicit size is visible in the library IL).

Validator: `SinkApis` closed vocab in `FixtureValidator.cs` extended with `http_content_read` and `http_client_read`. FX015 (invalid sink.api) and FX024 (kind/api coupling) updated — both new values are valid under `SinkKind.Allocation`.

**Tests:** New validator tests in `FixtureValidatorTests.cs` for FX015/FX024 with the new api values.

### Component 3: Fixture pairs

**Four new fixture directories:**

```
fixtures/otelcontrib-55m9-prefix/
    rules.yaml    ← source = HttpJsonPostTransport::SendExportRequest, taint_from_external_returns
    trace.yaml    ← pre-fix trace with HttpContentRead sink, no sanitizer
fixtures/otelcontrib-55m9-postfix/
    rules.yaml    ← same source
    trace.yaml    ← post-fix trace with 4 MiB sanitizer hop on path

fixtures/otelcontrib-vc24-prefix/
    rules.yaml    ← source = AzureVmMetaDataRequestor::GetAzureVmMetaData, taint_from_external_returns
    trace.yaml    ← pre-fix trace with HttpClientRead sink, no sanitizer
fixtures/otelcontrib-vc24-postfix/
    rules.yaml    ← same source
    trace.yaml    ← post-fix trace with sanitizer
```

**DLL build strategy:**

Clone `opentelemetry-dotnet-contrib` at two commits — the parent of PR #4117 merge (pre-fix OneCollector) and the parent of PR #4121 merge (pre-fix Azure) — plus the post-fix tagged releases. Build Debug + portable PDB (same flags as ImageSharp fixtures: `<DebugType>portable</DebugType>`, `<Optimize>false</Optimize>`). Store as `artifacts/<sha>/` directories with a `README.md` provenance note. Two build scripts: `scripts/build-otelcontrib-55m9.sh` and `scripts/build-otelcontrib-vc24.sh`, each building only the affected csproj in isolation.

**Ground-truth strategy:** After the analyzer is implemented, run it against the pre/post-fix DLLs and use the output as verbatim ground truth (same pattern as all previous fixtures). Hand-author the `vuln_id`, `fix_commit`, `fix_pr`, `description` header fields.

---

## Phase 2: Broad scan of HTTP-adjacent packages

**No code changes.** After Phase 1 lands, build and scan these packages from `opentelemetry-dotnet-contrib` at `main`:

| Package | Entry-point class | Rationale |
|---------|------------------|-----------|
| `OpenTelemetry.Exporter.Zipkin` | `ZipkinExporter` or transport class | HTTP exporter to Zipkin backend |
| `OpenTelemetry.Exporter.Jaeger` | `JaegerExporter` | HTTP/Thrift exporter |
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` | OTLP HTTP transport | High-traffic exporter |
| `OpenTelemetry.Resources.AWS` | `AWSEC2MetaDataRequestor` or similar | EC2/EKS metadata endpoint |
| `OpenTelemetry.Resources.GCP` | GCP metadata requestor | GCP metadata endpoint |
| `OpenTelemetry.Resources.Container` | Docker/K8s metadata reader | Container runtime metadata |
| `OpenTelemetry.Instrumentation.Http` | Response processing | Wraps HttpClient |

For each: write a `rules.yaml` with the identified entry point + `taint_from_external_returns: [HttpClient::Send, HttpClient::SendAsync, HttpClient::GetStringAsync, HttpClient::GetByteArrayAsync]`, build the package DLL at `main`, run the analyzer, triage each sink document.

**Output:** A triage report in `docs/` noting package, vulnerable method, finding classification (confirmed / false-positive / needs-investigation), and whether responsible disclosure is warranted.

---

## Definitions of Done

| # | Criterion |
|---|-----------|
| DoD-1 | `taint_from_external_returns` parsed from YAML and threaded to `HandleCall`; unit test passes |
| DoD-2 | `MatchHttpRead` fires on tainted `HttpContent`/`HttpClient` receivers; validator tests updated |
| DoD-3 | `otelcontrib-55m9-prefix` and `otelcontrib-vc24-prefix` fixtures: `--compare` non-strict exits 0, trace contains `http_content_read` / `http_client_read` sink with no sanitizer |
| DoD-4 | `otelcontrib-55m9-postfix` and `otelcontrib-vc24-postfix` fixtures: `--compare` non-strict exits 0, trace contains sanitizer hop on path |
| DoD-5 | All existing fixtures still pass `--compare` non-strict (no regression) |
| DoD-6 | Build clean, all tests green |
| DoD-7 | Phase 2 triage report committed to `docs/` |

---

## Plan parameters (for writing-plans)

**Branch model:** `milestone-h` off main.

**Artifact paths (new):**
- Pre-fix OneCollector: `artifacts/<sha-before-4117>/src/OpenTelemetry.Exporter.OneCollector/...`
- Post-fix OneCollector: `artifacts/<sha-1.15.1>/src/OpenTelemetry.Exporter.OneCollector/...`
- Pre-fix Azure: `artifacts/<sha-before-4121>/src/OpenTelemetry.Resources.Azure/...`
- Post-fix Azure: `artifacts/<sha-1.15.1-beta.1>/src/OpenTelemetry.Resources.Azure/...`

**Baseline (pre-H):** 189 tests, 6/6 non-strict, 6/6 strict.

**Task ordering:** Component 1 (source annotation) → Component 2 (sink shapes) → DLL builds → fixture pairs → Phase 2 scan. Component 1 and 2 can be developed in parallel but Component 1 must land before the fixture ground truths can be generated.

---

## Revision history

- **2026-04-29 (approved).** Initial spec. Option B (per-source-entry `taint_from_external_returns`) selected over global external-taint-source list and `seed_this_fields` workaround. Phase 2 scoped to HTTP-adjacent contrib packages only (7 packages).
