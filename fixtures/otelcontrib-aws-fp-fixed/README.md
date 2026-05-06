# otelcontrib-aws-fp-fixed

Locks the milestone-J elimination of the AWS `array_pool_rent` false-positive into the regular `--compare` test suite.

Source: `opentelemetry-dotnet-contrib`'s `OpenTelemetry.Resources.AWS` package, built from any recent `main` commit that retains the `Shared/HttpClientHelpers.GetBufferLength` ternary-clamp shape (substantively unchanged since the 2026-04-29 scan).

## Pre-milestone-J behaviour

Without milestone-J, the analyzer reported `array_pool_rent` (false-positive) at `HttpClientHelpers.cs:170` — see `docs/otelcontrib-phase2-scan-2026-04-29.md` table row for `OpenTelemetry.Resources.AWS`. The clamp at `GetBufferLength` correctly bounded `stream.Length`, but the over-approximation in `HandleCall` re-tainted the helper's return value because the caller's `stream` argument was tainted, causing `array_pool_rent` to fire on the subsequent `ArrayPool<byte>.Shared.Rent(length)` call.

## Post-milestone-J expected behaviour

Empty findings. The milestone-J `AppliedValueClamp` summary flag fires inside `GetBufferLength` (the ternary clamp matched and untainted the joined value). `HandleCall`'s caller-side check sees `AppliedValueClamp=true` on the callee summary and trusts `ReturnsTainted=false`, so the over-approximation is suppressed and `array_pool_rent` no longer fires.

## Materialize

```
bash scripts/materialize-otelcontrib-aws-fp.sh
```

Builds `OpenTelemetry.Resources.AWS.dll` into `artifacts/<sha>/`. The expected SHA is pinned in the script; update it if the AWS source's `GetBufferLength` shape changes.
