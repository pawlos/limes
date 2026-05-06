# otelcontrib-opamp-w2jh-postfix

Source: opentelemetry-dotnet-contrib @ commit `bf1fad4fa298ff451cda0efb0ee9c7a7eb46212a`
(fix commit "[OpAMP] Apply response size limits for oversized responses (#4116)").

Advisory: GHSA-w2jh-77fq-7gp8 / CVE-2026-42348.

Materialize:

    bash scripts/materialize-otelcontrib-opamp.sh

Expected analyzer behaviour: empty findings. The fix replaces unbounded
`ReadAsByteArrayAsync` with `ReadBoundedResponseAsync`, which uses
`ReadAsStreamAsync` + bounded `Stream.ReadAsync` into an `ArrayPool` rented
buffer sized by `TransportConstants.MaxMessageSize` (128 KiB constant).
