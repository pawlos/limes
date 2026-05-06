# OpenTelemetry Contrib HTTP DoS Broad Scan — 2026-04-29 (milestone-I rerun)

**Rerun date:** 2026-05-06 (after milestone-I MatchValueClamps + Math.Min/Clamp recognizer landed).

## Methodology

Same DLLs and rules as the original 2026-04-29 scan
(`docs/otelcontrib-phase2-scan-2026-04-29.md`). Only the analyzer changed.

Rules files created in `/tmp/otel-scan/<DIR>/rules.yaml` for each package
(restored from the source-method signatures in the original report):
- AWS: `ResourceDetectorUtils::SendOutRequest(...)`, seeded `HttpClient::Send/SendAsync/GetStringAsync/GetByteArrayAsync`
- Azure: `AzureVmMetaDataRequestor::GetAzureVmMetaDataResponseDefault()`, seeded `HttpClient::GetStringAsync/GetByteArrayAsync`
- OneCollector: `HttpJsonPostTransport::Send(TransportSendRequest&)`, seeded `HttpClient::Send/SendAsync/IHttpClient::Send`

## Changes in milestone-I that affect these results

Three improvements landed together:

1. **`SanitizerShapes.MatchValueClamps`** — extended `ClassifyArmForClamp` to recognise
   `ldarg.X; callvirt get_Prop; [conv.*]` as a valid clamp arm (the real OTel code uses
   `stream.Length` via a property getter, not a bare `ldarg`). `OperandProvenance` was
   extended to synthesize `"receiver.Property"` names for getter call chains.

2. **Clamp-untaint timing** — moved the ternary-clamp join check to run **before**
   `StepInstruction` rather than after. This ensures that when the join point is a `stloc`
   (as in `GetBufferLength`), the local variable receives the untainted value instead of
   the tainted one.

3. **`HandleCall` return-taint signal** — for in-assembly callees the analyzer now trusts
   `calleeSummary.ReturnsTainted` as the primary signal instead of the previous
   over-approximation (`bitmask != 0`). This lets a properly-sanitized callee like
   `GetBufferLength` (which has a clamp on its return path) propagate an untainted return
   to the caller, preventing the `array_pool_rent` sink from firing on the caller's
   `ArrayPool.Rent(length)` call.

   A prerequisite for the over-approximation change: `ldelem.*` instructions are now
   handled explicitly (propagate array taint to element), so methods like `ReadByte(byte[], int)`
   correctly mark their return as tainted when the array argument is tainted.

## Results (delta vs 2026-04-29)

| Package | 2026-04-29 finding | 2026-05-06 finding |
|---------|-------------------|--------------------|
| `OpenTelemetry.Resources.AWS` | `array_pool_rent` (false-positive in `HttpClientHelpers`) | **empty** (clamp recognised; `GetBufferLength` returns untainted) |
| `OpenTelemetry.Resources.Azure` | `array_pool_rent` (false-positive in `HttpClientHelpers`) | **empty** (clamp recognised; `GetBufferLength` returns untainted) |
| `OpenTelemetry.Exporter.OneCollector` | `http_content_read` (false-positive in `HttpClientHelpers.TryGetResponseBodyAsString`) | **http_content_read still fires** (see note below) |
| `OpenTelemetry.Resources.Gcp` | no-sink | no-sink |
| `OpenTelemetry.Resources.Container` | no-sink | no-sink |
| `OpenTelemetry.Instrumentation.Http` | no-sink | no-sink |
| `OpenTelemetry.Instrumentation.AWS` | no-sink | no-sink |

### Note on OneCollector `http_content_read`

The OneCollector FP is a **different sink type** (`http_content_read`, fired by `MatchHttpRead`
on `ReadAsStreamAsync`) rather than `array_pool_rent`. The ternary-clamp fix targets
`ArrayPool.Rent` allocations bounded by `GetBufferLength`; it does not suppress the
`MatchHttpRead` unconditional sink that fires on any call to `HttpContent.ReadAsStreamAsync`.

The finding is the **same pre-existing false-positive** documented in the 2026-04-29 report:
`HttpJsonPostTransport.Send` → `HttpClientHelpers.TryGetResponseBodyAsString` →
`GetResponseBodyAsString(allowTruncation=true, limit=4 MiB)` → `ReadAsStreamAsync`.
The actual read is bounded at 4 MiB by the subsequent `GetBufferLength` + buffer-loop
pattern; no new vulnerability. The fix requires a context-aware `MatchHttpRead` that
recognises bounded read loops — deferred to a future milestone.

## Summary

3 false-positives examined; 2 fully resolved (`array_pool_rent` in AWS and Azure). The
OneCollector `http_content_read` FP persists unchanged — it is a pre-existing limitation
of `MatchHttpRead` firing unconditionally rather than a new regression from milestone-I.

The originally-disclosed CVEs (GHSA-55m9 / GHSA-vc24) remain confirmed-fixed on main;
the milestone-H fixture pair `otelcontrib-{55m9,vc24}-{prefix,postfix}` continues to
pass `--compare` non-strict (the pre-fix fixtures' genuine unbounded reads still fire;
the sanitizer correctly does NOT over-untaint).
