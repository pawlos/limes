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
(int)stream.Length : limit` pattern inside `HttpClientHelpers.GetBufferLength`, and
`HandleCall` trusts the callee's sanitized-return summary so the `array_pool_rent`
sink no longer fires when `GetBufferLength` is called with tainted arguments.

## Results (delta vs 2026-04-29)

| Package | 2026-04-29 finding | 2026-05-06 finding |
|---------|-------------------|--------------------|
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/HTTP) | `array_pool_rent` (false-positive in `HttpClientHelpers`) | **empty** (clamp recognised) |
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/gRPC) | `array_pool_rent` (false-positive in `HttpClientHelpers`) | **empty** (clamp recognised) |
| `OpenTelemetry.Exporter.Zipkin` | no-sink (rules-validator gap with byref signature) | not re-scanned — Zipkin deferred (same limitation as original) |

## Summary

2 `array_pool_rent` false-positives → 0. The shared `HttpClientHelpers.GetBufferLength`
clamp is now recognised by the extended `MatchValueClamps` matcher, and `HandleCall`
correctly propagates the untainted return to the caller, suppressing the `array_pool_rent`
sink. Zipkin remains deferred (rules-format validator limitation documented in the original
report). No new vulnerabilities surfaced.
