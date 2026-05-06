# OpenTelemetry Core HTTP DoS Broad Scan — 2026-04-29 (milestone-I rerun)

**Rerun date:** 2026-05-06 (after milestone-I MatchValueClamps + Math.Min/Clamp recognizer landed).

## Methodology

Same rules as the original 2026-04-29 scan (`docs/otelcore-scan-2026-04-29.md`).
DLL rebuilt from `opentelemetry-dotnet` @ commit `bc1fbe65e6977e4b70328ca926f812340772d6f7`
targeting `net8.0` (same SDK as the original scan):

```
git clone https://github.com/open-telemetry/opentelemetry-dotnet.git /tmp/otel-core-scan-build
git -C /tmp/otel-core-scan-build fetch --depth 1 origin bc1fbe65e6977e4b70328ca926f812340772d6f7
git -C /tmp/otel-core-scan-build checkout bc1fbe65e6977e4b70328ca926f812340772d6f7
dotnet build .../OpenTelemetry.Exporter.OpenTelemetryProtocol.csproj \
    -c Debug --framework net8.0 -p:DebugType=portable -p:DebugSymbols=true -p:Optimize=false
```

Rules used:
- `/tmp/otel-core-scan/rules-otlp-http.yaml` — `OtlpHttpExportClient::SendExportRequest`
- `/tmp/otel-core-scan/rules-otlp-grpc.yaml` — `OtlpGrpcExportClient::SendExportRequest`

## Changes in milestone-I that affect these results

See `docs/otelcontrib-phase2-scan-2026-04-29-addendum.md` for the full explanation.
In summary: `MatchValueClamps` now correctly handles the `stream.Length < limit ?
(int)stream.Length : limit` pattern inside `HttpClientHelpers.GetBufferLength` (clamp-arm
recognition + pre-step untaint timing), but the `HandleCall` over-approximation change was
reverted to preserve the GHSA-55m9 fixture. With the revert, `array_pool_rent` findings
that require `HandleCall` to propagate a sanitized callee return still fire.

## Results (post-revert, 2026-05-06)

| Package | 2026-04-29 finding | 2026-05-06 finding (post-revert) |
|---------|-------------------|----------------------------------|
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/HTTP) | `array_pool_rent` FP in `HttpClientHelpers` | **`array_pool_rent` still fires** — over-approximation in `HandleCall` |
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/gRPC) | `array_pool_rent` FP in `HttpClientHelpers` | **`array_pool_rent` still fires** — over-approximation in `HandleCall` |
| `OpenTelemetry.Exporter.Zipkin` | no-sink (rules-validator gap with byref signature) | not re-scanned — Zipkin deferred (same limitation as original) |

### Note on OTLP `array_pool_rent` persistence

Both OTLP/HTTP and OTLP/gRPC findings persist because suppressing them requires `HandleCall`
to trust the callee's sanitized-return summary (`calleeSummary.ReturnsTainted`) instead of the
over-approximation (`bitmask != 0`). That change (commit a88b636 item 4) was reverted because
it regressed the GHSA-55m9 milestone-H fixture. A context-aware fix that distinguishes
sanitized-return paths from genuine untaint-propagation paths is deferred to a future milestone.

## Summary

Both `array_pool_rent` false-positives persist in the post-revert analyzer. The
`MatchValueClamps` clamp-arm + timing improvements (items 1+2 from a88b636) are kept, but
without item 4 (`HandleCall` callee-summary trust) the `array_pool_rent` caller sink still
fires when any tainted argument is passed to `GetBufferLength`. The fix is deferred pending
a non-regressing `HandleCall` solution. Zipkin remains deferred (rules-format validator
limitation documented in the original report).
