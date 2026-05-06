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

Two improvements from milestone-I task 14 landed and were subsequently partially reverted:

1. **`SanitizerShapes.MatchValueClamps`** — extended `ClassifyArmForClamp` to recognise
   `ldarg.X; callvirt get_Prop; [conv.*]` as a valid clamp arm (the real OTel code uses
   `stream.Length` via a property getter, not a bare `ldarg`). `OperandProvenance` was
   extended to synthesize `"receiver.Property"` names for getter call chains.

2. **Clamp-untaint timing** — moved the ternary-clamp join check to run **before**
   `StepInstruction` rather than after. This ensures that when the join point is a `stloc`
   (as in `GetBufferLength`), the local variable receives the untainted value instead of
   the tainted one.

**Reverted in milestone-I Task 14 regression fix:**

3. **`HandleCall` return-taint signal** — an earlier commit (a88b636) changed `HandleCall`
   to trust `calleeSummary.ReturnsTainted` as the primary signal instead of the
   over-approximation (`bitmask != 0`). This was reverted because it regressed the
   otelcontrib-55m9-prefix milestone-H fixture (the GHSA-55m9 path relies on
   over-approximation propagating taint through `Send → ReadAsStringAsync`). Without item 3,
   a tainted argument to `GetBufferLength` still causes the `array_pool_rent` caller sink
   to fire (over-approximation: any tainted arg → tainted return).

## Results (post-revert, 2026-05-06)

| Package | 2026-04-29 finding | 2026-05-06 finding (post-revert) |
|---------|-------------------|----------------------------------|
| `OpenTelemetry.Resources.AWS` | `array_pool_rent` FP in `HttpClientHelpers` | **`array_pool_rent` still fires** — over-approximation propagates through `GetBufferLength` caller |
| `OpenTelemetry.Resources.Azure` | `array_pool_rent` FP in `HttpClientHelpers` | **empty** — Azure path resolved by clamp-timing fix alone |
| `OpenTelemetry.Exporter.OneCollector` | `http_content_read` FP in `HttpClientHelpers.TryGetResponseBodyAsString` | **`http_content_read` still fires** — pre-existing `MatchHttpRead` limitation |
| `OpenTelemetry.Resources.Gcp` | no-sink | no-sink |
| `OpenTelemetry.Resources.Container` | no-sink | no-sink |
| `OpenTelemetry.Instrumentation.Http` | no-sink | no-sink |
| `OpenTelemetry.Instrumentation.AWS` | no-sink | no-sink |

### Note on AWS `array_pool_rent`

The AWS FP persists because the over-approximation (`bitmask != 0 || calleeSummary.ReturnsTainted`)
is required to avoid a worse regression (55m9 milestone-H fixture). The full fix requires a
context-aware `HandleCall` that can distinguish sanitized-return callees from unsanitized ones
without breaking the over-approximation for the 55m9 call chain — deferred to a future milestone.

### Note on Azure (empty)

The Azure package's `GetBufferLength` call chain is resolved by the clamp-timing fix alone
(items 1+2). The property-getter arm recognition and pre-step join timing are sufficient to
untaint the ternary-clamp result at the stloc join point inside the Azure DLL's version of
`GetBufferLength`, so the return is computed as untainted before the array allocation.

### Note on OneCollector `http_content_read`

The OneCollector FP is a **different sink type** (`http_content_read`, fired by `MatchHttpRead`
on `ReadAsStreamAsync`) rather than `array_pool_rent`. The ternary-clamp fix does not suppress
the `MatchHttpRead` unconditional sink that fires on any call to `HttpContent.ReadAsStreamAsync`.

The finding is the **same pre-existing false-positive** documented in the 2026-04-29 report:
`HttpJsonPostTransport.Send` → `HttpClientHelpers.TryGetResponseBodyAsString` →
`GetResponseBodyAsString(allowTruncation=true, limit=4 MiB)` → `ReadAsStreamAsync`.
The actual read is bounded at 4 MiB by the subsequent `GetBufferLength` + buffer-loop
pattern; no new vulnerability. The fix requires a context-aware `MatchHttpRead` that
recognises bounded read loops — deferred to a future milestone.

## Summary

3 false-positives examined; 1 fully resolved (`array_pool_rent` in Azure). The AWS
`array_pool_rent` FP and OneCollector `http_content_read` FP persist — both are pre-existing
limitations requiring deferred work (context-aware `HandleCall` for AWS; bounded `MatchHttpRead`
for OneCollector).

The originally-disclosed CVEs (GHSA-55m9 / GHSA-vc24) remain confirmed-fixed on main;
the milestone-H fixture pair `otelcontrib-{55m9,vc24}-{prefix,postfix}` continues to
pass `--compare` non-strict (the pre-fix fixtures' genuine unbounded reads still fire;
the sanitizer correctly does NOT over-untaint).
