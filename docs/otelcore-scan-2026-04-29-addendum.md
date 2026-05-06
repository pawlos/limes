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

## Changes in milestone-I + milestone-J that affect these results

See `docs/otelcontrib-phase2-scan-2026-04-29-addendum.md` for the full explanation.
In summary: milestone-I added clamp-arm recognition + pre-step untaint timing, and
milestone-J added the `AppliedValueClamp` summary signal that lets `HandleCall` trust
the callee's bounded-return result without over-approximating. The combined fix
preserves the GHSA-55m9 fixture (which fires only throw-shape sanitisers, not value
clamps) and eliminates the OTLP `array_pool_rent` FPs.

## Results (post-milestone-J, 2026-05-06)

| Package | 2026-04-29 finding | 2026-05-06 finding (post-milestone-J) |
|---------|-------------------|----------------------------------|
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/HTTP) | `array_pool_rent` FP in `HttpClientHelpers` | **empty** — eliminated by milestone-J `AppliedValueClamp` |
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/gRPC) | `array_pool_rent` FP in `HttpClientHelpers` | **empty** — eliminated by milestone-J `AppliedValueClamp` |
| `OpenTelemetry.Exporter.Zipkin` | no-sink (rules-validator gap with byref signature) | not re-scanned — Zipkin deferred (same limitation as original) |

### Milestone-J update — both OTLP FPs eliminated

The milestone-I revert was reversed by milestone-J's surgical fix: `MethodSummary` now
carries an `AppliedValueClamp` flag set when `MatchValueClamps` actually untaints a slot.
`HandleCall` skips the `bitmask != 0` over-approximation iff the callee's summary reports
`AppliedValueClamp == true`, distinguishing "genuinely sanitized return" from "incidentally
untainted return that the over-approximation needs to compensate for." The 55m9 path stays
green because `BuildRequestContent` doesn't fire a value-clamp (only a throw-shape sanitizer);
the OTLP path goes empty because `GetBufferLength` does fire a value-clamp.

## Summary

Both `array_pool_rent` false-positives eliminated by milestone-J. Zipkin remains deferred
(rules-format validator limitation documented in the original report).
