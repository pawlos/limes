# OpenTelemetry Core HTTP DoS Broad Scan — 2026-04-29

## Methodology

Analyzer: dotnet-taint-analyzer milestone-H, branch `main` (post-milestone-H merge).
Source: `opentelemetry-dotnet` @ commit `bc1fbe65e6977e4b70328ca926f812340772d6f7`
(default branch `main`, latest commit "[Exporter.Prometheus] Fix reader tracking (#7190)").
Repo cloned shallowly to `/tmp/otel-core-repo`.

This is the Phase 2b companion scan to `docs/otelcontrib-phase2-scan-2026-04-29.md`.
The three packages originally listed for the contrib scan
(`OpenTelemetry.Exporter.Zipkin`, `OpenTelemetry.Exporter.Jaeger`,
`OpenTelemetry.Exporter.OpenTelemetryProtocol`) actually live in the *core* repo,
not contrib. This scan covers them. Note: `OpenTelemetry.Exporter.Jaeger` no
longer exists in the core repo at this commit — Jaeger has been removed in
favour of OTLP.

Sinks: `http_content_read` / `http_client_read` (`MatchHttpRead`, unconditional
on `(HttpContent, ReadAs*Async)` and `(HttpClient, Get*Async)`), and
`array_pool_rent`.
`taint_from_external_returns` seeded for `HttpClient::Send`,
`HttpClient::SendAsync`, `HttpClient::GetStringAsync`,
`HttpClient::GetByteArrayAsync` per source entry.
SDK: .NET 10.0.203 (installed locally to satisfy the repo's `global.json`;
analyzer was built originally on 10.0.103, both are compatible). Build flags:
`DebugType=portable DebugSymbols=true Optimize=false -c Debug --framework net10.0`.

Candidates identified by grepping `src/` for `HttpClient`, `HttpResponseMessage`,
`ReadAs*`, and outbound-HTTP usage. Only two `src/` packages perform outbound
HTTP traffic that reads response bodies:

- `OpenTelemetry.Exporter.Zipkin`
- `OpenTelemetry.Exporter.OpenTelemetryProtocol` (both OTLP/HTTP and OTLP/gRPC
  export-client variants)

`OpenTelemetry.Exporter.Prometheus.HttpListener` and
`OpenTelemetry.Exporter.Prometheus.AspNetCore` are *server-side* (they expose
metrics via an HttpListener / AspNetCore endpoint); they do not act as HTTP
clients reading attacker-controlled bodies, so they were excluded from the
scan. The remaining `src/` packages
(`OpenTelemetry`, `OpenTelemetry.Api`, `OpenTelemetry.Api.ProviderBuilderExtensions`,
`OpenTelemetry.Exporter.Console`, `OpenTelemetry.Exporter.InMemory`,
`OpenTelemetry.Extensions.Hosting`, `OpenTelemetry.Extensions.Propagators`,
`OpenTelemetry.Shims.OpenTracing`) contain no `HttpClient` or `ReadAs*` usage.

Analyzer invocations were of the form

```
dotnet run --project tools/TaintAnalyzer -- \
  <built.dll> --rules <rules.yaml> --output <out.yaml>
```

Working rules and traces are stored in `/tmp/otel-core-scan/`.

## Results

| Package | Entry method | Sink found | Classification | Notes |
|---------|-------------|-----------|----------------|-------|
| `OpenTelemetry.Exporter.Zipkin` | `ZipkinExporter::Export` | none | no-sink (analyzer-error) | Source signature contains a byref `in Batch<Activity>&` parameter whose Cecil short-form ParameterType FullName carries an embedded space (`Batch\`1<...>& modreq(...)`) which the rules-file validator rejects (`no spaces allowed in source_methods entries`). Manual review confirms the method only calls `EnsureSuccessStatusCode()` and never reads the response body — no sink would have been reached anyway. |
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/HTTP) | `OtlpHttpExportClient::SendExportRequest` | `array_pool_rent` (in `HttpClientHelpers.GetResponseBodyAsString`) | false-positive | Bounded by `DefaultMessageSizeLimit = 4 MiB` in `Shared/HttpClientHelpers.cs` (identical helper to contrib). `MatchHttpRead` did **not** fire — net10 path uses sync `ReadAsStream(cancellationToken)`, not `ReadAsStreamAsync`. Only the `array_pool_rent` sanitizer-absence finding inside the bounded helper is reported. |
| `OpenTelemetry.Exporter.OpenTelemetryProtocol` (OTLP/gRPC) | `OtlpGrpcExportClient::SendExportRequest` | `array_pool_rent` (in `HttpClientHelpers.GetResponseBodyAsString`) | false-positive | Same `HttpClientHelpers` path on the error log branch (`TryGetResponseBody` → `TryGetResponseBodyAsString`, 4 MiB cap). The success path has its own `ReadAsStream(cancellationToken)` at `OtlpGrpcExportClient.cs:87` that is **not** matched by `MatchHttpRead` and only consumes one byte (`ReadByte()`) from a `ResponseHeadersRead` stream — bounded de facto. |

## Detailed finding notes

### Zipkin — no body read at all

`ZipkinExporter.Export` (file `ZipkinExporter.cs`, lines 62–101) sends a POST
request via `HttpClient.Send` / `SendAsync` and only inspects the result via
`response.EnsureSuccessStatusCode()`. The response body is never read. There
is no opportunity for an attacker-controlled response to influence local
allocation size.

The analyzer could not be driven from this entry method because the rules-file
signature validator forbids spaces in source signatures, but Cecil's
`ParameterType.FullName` for an `in Batch<Activity>` parameter contains a
literal space between `&` and `modreq(...)`. This is an analyzer rules-format
limitation, not a code defect; recorded as `analyzer-error` per scan policy.
Manual review of the method body confirms no sink is reachable, so the
classification is **no-sink** for the package.

### OTLP/HTTP — `array_pool_rent` via `HttpClientHelpers`

Path: `OtlpHttpExportClient.SendExportRequest` →
(non-2xx error branch) `OtlpExportClient.TryGetResponseBody` →
`HttpClientHelpers.TryGetResponseBodyAsString(allowTruncation: true, 4 MiB, ...)` →
`GetBufferLength(stream, limit, ContentLength)` →
`ArrayPool<byte>.Shared.Rent(length)` (HttpClientHelpers.cs:60).

`GetBufferLength` caps `length` at `limit = 4 MiB` (the same shared helper
analysed in the contrib scan; `Shared/HttpClientHelpers.cs` is byte-identical to
the contrib version, including the 4 MiB constant on line 14). The analyzer
emits `sanitizer_absence` because the `length` bound is established via
`stream.Length < limit ? (int)stream.Length : limit` rather than the
`if (size > bound) throw` shape recognised by the loop-guard sanitizer (a known
analyzer limitation deferred to milestone-I — see contrib scan note). **No new
vulnerability.**

`MatchHttpRead` did not fire for the OTLP HTTP path because the helper uses the
synchronous `httpResponse.Content.ReadAsStream(cancellationToken)` overload on
net10, and the unconditional sink only matches the `*Async` variants
(`ReadAsStringAsync`, `ReadAsByteArrayAsync`, `ReadAsStreamAsync`). Code
inspection of the helper confirms the sync read is bounded by the same 4 MiB
cap.

### OTLP/gRPC — same helper, plus a one-byte success-path read

The error branch at `OtlpGrpcExportClient.cs:156` follows the same
`TryGetResponseBody` → `HttpClientHelpers` path as OTLP/HTTP (4 MiB cap).

The success branch at `OtlpGrpcExportClient.cs:87` calls
`httpResponse.Content.ReadAsStream(cancellationToken)` and then
`responseStream.ReadByte()` — exactly one byte is consumed. The export client
sets `CompletionOption => HttpCompletionOption.ResponseHeadersRead`
(`OtlpExportClient.cs:62`), so `HttpClient.Send/SendAsync` returns before the
response body has been buffered into memory; reading a single byte from the
network stream cannot trigger an unbounded allocation regardless of how large
the server's response is. **No new vulnerability.**

## Summary

Three packages scanned (Zipkin, OTLP/HTTP, OTLP/gRPC). Zero confirmed
vulnerabilities. Two `false-positive` findings, both inside the shared
`HttpClientHelpers.GetResponseBodyAsString` helper (4 MiB cap, identical to
contrib's copy). One `no-sink` package (Zipkin — never reads response body).
The Zipkin entry was technically `analyzer-error` due to a rules-file signature
validator limitation (no spaces allowed, but Cecil short-form for `in T&`
parameters contains a space); manual code review confirms no sink is
reachable, so the package's true classification is **no-sink**.

The `MatchHttpRead` unconditional sink (added in milestone-H) did **not** fire
on any of these packages because the OTLP code uses the synchronous net10
`ReadAsStream(CancellationToken)` overload (not matched) inside the bounded
helper, and Zipkin reads no body at all. The `array_pool_rent` finding is the
same shape as the AWS / Azure / OneCollector findings already documented in
the contrib scan and represents a known loop-guard sanitizer limitation, not
a vulnerability.

## Responsible Disclosure

No new findings warranting disclosure. The OTLP exporter's HTTP and gRPC paths
correctly cap response-body reads at 4 MiB via `HttpClientHelpers`. The Zipkin
exporter does not read response bodies at all. The single byte read on the
gRPC success path is bounded by `HttpCompletionOption.ResponseHeadersRead` and
the explicit single-`ReadByte` call site.

Two minor analyzer issues observed, both already-known and out-of-scope for
this scan:

1. The rules-file signature validator forbids spaces in source signatures, but
   Cecil's short-form FullName for `in T&` (byref + `InAttribute` modreq)
   parameters contains an embedded space. This blocks targeting any method
   whose only public entrypoint takes a `readonly ref struct` / `in` byref
   argument from rules.yaml. Possible future fix: strip the
   ` modreq(...)` suffix in `BuildShortSignature` (or relax the
   `no-spaces` rule for parenthesised modreq tails).
2. `MatchHttpRead` only matches `*Async` variants of the response-read APIs.
   `ReadAsStream(CancellationToken)` (sync, net10+) is not matched. For the
   helper-bounded paths analysed here this is benign, but the asymmetry could
   cause false-negatives in other codebases that call the sync overload
   directly without a 4 MiB cap. Worth tracking in milestone-I scope.
