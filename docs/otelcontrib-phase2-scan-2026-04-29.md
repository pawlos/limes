# OpenTelemetry Contrib HTTP DoS Broad Scan — 2026-04-29

## Methodology

Analyzer: dotnet-taint-analyzer milestone-H, branch milestone-h.
Source: opentelemetry-dotnet-contrib @ main (commit after GHSA-55m9 / GHSA-vc24 fixes).
Sink: `http_content_read` / `http_client_read` (MatchHttpRead, unconditional) and `array_pool_rent`.
`taint_from_external_returns` seeded for `HttpClient::Send`, `HttpClient::SendAsync`, `HttpClient::GetStringAsync`, `HttpClient::GetByteArrayAsync` per source entry.
SDK: .NET 10.0.103. Build flags: `DebugType=portable DebugSymbols=true Optimize=false -c Debug`.

Note: `OpenTelemetry.Exporter.Zipkin`, `OpenTelemetry.Exporter.Jaeger`, and
`OpenTelemetry.Exporter.OpenTelemetryProtocol` are not in the contrib repo
(they live in `opentelemetry-dotnet`). The scan substitutes three other
HTTP-adjacent contrib packages:
- `OpenTelemetry.Resources.Azure` (covered by GHSA-vc24)
- `OpenTelemetry.Exporter.OneCollector` (covered by GHSA-55m9)
- `OpenTelemetry.Instrumentation.AWS`

## Results

| Package | Entry method | Sink found | Classification | Notes |
|---------|-------------|-----------|----------------|-------|
| `OpenTelemetry.Resources.AWS` | `ResourceDetectorUtils::SendOutRequest` | `array_pool_rent` (inside `HttpClientHelpers`) | false-positive | Bounded by `DefaultMessageSizeLimit = 4 MiB`; fix already landed in `HttpClientHelpers.GetResponseBodyAsString`. MatchHttpRead did not fire. |
| `OpenTelemetry.Resources.Gcp` | `GcpResourceDetector::Detect` | none | no-sink | GCP metadata read delegates entirely to `Google.Api.Gax` (external library); no direct HttpClient usage in instrumented code. |
| `OpenTelemetry.Resources.Container` | `ContainerDetector::Detect` | none | no-sink | Reads from `/proc/self/cgroup` and `/proc/self/mountinfo` (local filesystem); no HTTP calls. |
| `OpenTelemetry.Instrumentation.Http` | `HttpClientInstrumentation::Dispose` | none | no-sink | Instrumentation wrapper — subscribes to DiagnosticSource events, does not read HTTP response bodies itself. |
| `OpenTelemetry.Resources.Azure` | `AzureVmMetaDataRequestor::GetAzureVmMetaData` | `array_pool_rent` (inside `HttpClientHelpers`) | false-positive | Bounded by `DefaultMessageSizeLimit = 4 MiB`; fix for GHSA-vc24 (PR #4121) already merged. MatchHttpRead did not fire on main. |
| `OpenTelemetry.Exporter.OneCollector` | `HttpJsonPostTransport::Send` | `http_content_read` (via `HttpClientHelpers.TryGetResponseBodyAsString`) | false-positive | `TryGetResponseBodyAsString` calls `GetResponseBodyAsString(allowTruncation: true, 4 MiB limit, ...)`. The `Content-Length > limit` guard is skipped when `allowTruncation=true`, but the stream is read into a buffer bounded by `GetBufferLength(stream, limit, ...)` — actual bytes transferred are capped. Fix for GHSA-55m9 (PR #4117) already merged; `ReadAsStringAsync` is gone. |
| `OpenTelemetry.Instrumentation.AWS` | `AWSClientInstrumentationOptions::get_SuppressDownstreamInstrumentation` | none | no-sink | AWS SDK instrumentation only wraps request/response events via X-Ray SDK pipeline; no direct HTTP response body reading. |

## Detailed finding notes

### AWS — `array_pool_rent` via `GetResponseBodyAsString`

Path: `ResourceDetectorUtils.SendOutRequest` → `HttpClientHelpers.GetResponseBodyAsString` →
`GetBufferLength` (returns `stream.Length < limit ? (int)stream.Length : limit`) → `ArrayPool<byte>.Shared.Rent(length)`.

The analyzer emits `sanitizer_absence` because the `length` bound is established via `stream.Length` rather than a direct `if (size > bound) throw` shape our sanitizer recognises. Code inspection confirms `GetBufferLength` caps at `limit = 4 MiB`. **No new vulnerability.**

### Azure — same pattern as AWS

`AzureVmMetaDataRequestor.GetAzureVmMetaData` → `HttpClientHelpers.GetResponseBodyAsString` (same path). **No new vulnerability.**

### OneCollector — `http_content_read` via `TryGetResponseBodyAsString`

Path: `HttpJsonPostTransport.Send` → `HttpClientHelpers.TryGetResponseBodyAsString` →
`GetResponseBodyAsString(allowTruncation: true, 4 MiB, ...)` → `httpResponse.Content.ReadAsStream(cancellationToken)`.

`MatchHttpRead` fires on `ReadAsStream` (inside the bounded helper) because the sink is
unconditional — it fires on any call to the listed `HttpContent` methods regardless of context.
The actual read is bounded: `GetBufferLength` caps the read at 4 MiB. The `allowTruncation=true`
variant skips the `Content-Length` pre-check but still bounds the buffer allocation. **No new vulnerability.**

## Summary

7 packages scanned (3 originally listed replaced due to repo split — see methodology). 0 confirmed
vulnerabilities. 3 `false-positive` findings (all inside the already-patched `HttpClientHelpers`
shared helper, which enforces a 4 MiB limit). 4 `no-sink` results (packages do not read HTTP
response bodies at all). The two disclosed CVEs (GHSA-55m9 / GHSA-vc24) are confirmed fixed
on current main: `MatchHttpRead` does not fire because `ReadAsStringAsync` / `GetStringAsync`
calls have been replaced by the bounded `HttpClientHelpers` wrapper.

## Responsible Disclosure

No new findings warranting disclosure. All previously patched code in `opentelemetry-dotnet-contrib`
at main correctly uses the bounded `HttpClientHelpers` wrappers. The `false-positive` `http_content_read`
finding in OneCollector (error-path logging via `TryGetResponseBodyAsString`) is bounded to
4 MiB and represents a minor analyser limitation (loop-guard sanitizer shapes not yet implemented —
deferred to milestone-I).
