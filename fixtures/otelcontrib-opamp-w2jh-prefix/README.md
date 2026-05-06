# otelcontrib-opamp-w2jh-prefix

Source: opentelemetry-dotnet-contrib @ commit `d6e87d8af403554107671e98e1913a3b2dfe141a`
(parent of fix `bf1fad4`).

Advisory: GHSA-w2jh-77fq-7gp8 / CVE-2026-42348.

Vulnerable code: `src/OpenTelemetry.OpAmp.Client/Internal/Transport/Http/PlainHttpTransport.cs:51`
— `ReadAsByteArrayAsync` on the HTTP response body with no size cap.

Materialize:

    bash scripts/materialize-otelcontrib-opamp.sh

Expected analyzer behaviour: `MatchHttpRead` fires (sink `http_content_read`).
The source rule names the user-facing async method; `AsyncStateMachineResolver`
redirects to `<SendAsync>d__7\`1::MoveNext`.
