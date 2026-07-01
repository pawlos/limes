# Limes

A static **taint analyzer for compiled .NET assemblies**. Limes reads IL directly
(via [Mono.Cecil](https://github.com/jbevain/cecil) — no source required), tracks
attacker-controllable values from *source* methods through the call graph, and reports
when they reach a dangerous *sink*. It emits a machine-readable YAML trace of the full
source → propagator → sink path.

It targets four vulnerability classes:

- **CWE-770 — unbounded resource allocation / HTTP DoS.** A length or count read from
  an untrusted stream flows into an allocation (`new T[n]`, `ArrayPool.Rent`, `stackalloc`,
  `Span` slice/index, HTTP body read) without a bound check.
- **CWE-89 — SQL injection.** A string value reaches a SQL command sink
  (`DbCommand.CommandText`, command-builder append) without passing a recognized sanitizer.
- **CWE-835 — infinite loop.** A loop reads from a `PipeReader`/`Stream`/`Socket` but never
  inspects the completion signal (`ReadResult.IsCompleted`, a zero byte-count), so a peer
  that stops sending can spin it forever. Structural — not a taint flow.
- **CWE-674 — uncontrolled recursion.** A method calls itself while walking untrusted input
  (e.g. resolving a `$ref` chain) with no visited-set or depth-limit guard, so a circular
  input overflows the stack. Structural — not a taint flow.

## Why it exists

Limes was built to find — and reproduce — real DoS and injection bugs in widely-used
.NET libraries. Findings driven by this tool to date include:

| Library | Issue | Class |
|---|---|---|
| **SixLabors.ImageSharp** | BMP decoder unbounded allocations (#3074, #3079) | CWE-770 |
| **MPCS** (`Microsoft.Psi`-style) | `DateTime` `stackalloc` over-allocation (3.0.3–3.1.4) | CWE-770 |
| **protobuf-net** | string/bytes field OOM (≤ 3.2.56) | CWE-789 |
| **Marten** | `FullTextWhereFragment` SQL injection (GHSA-vmw2-qwm8-x84c) | CWE-89 |
| **NBMP** | parameter-shape DoS | CWE-770 |
| **CoreWCF** | framing-handshake infinite loop (GHSA-p86g-xrr2-pf7c) | CWE-835 |
| **NAudio** | `LoopStream.Read` empty-source infinite loop (#1338) | CWE-835 |
| **Microsoft.OpenApi** | circular `$ref` stack overflow (GHSA-v5pm-xwqc-g5wc, ≤ 2.7.4 / ≤ 3.5.3) | CWE-674 |

Each is captured as a locked fixture (see [`fixtures/`](fixtures/)) with `prefix`
(vulnerable) and `postfix` (patched) variants, so the analyzer is regression-tested
against both the bug and its fix.

## How it works

1. **Load** — `AssemblyContext` opens the target `.dll` and (when available) its `.pdb`
   so traces carry real file/line locations.
2. **Seed** — each source method's parameters (and optionally `this`-fields) are marked tainted.
3. **Walk** — `TaintWalker` performs a symbolic-stack IL walk, following taint across method
   calls through a `CallGraph`. It resolves `async`/iterator state machines back to their
   user-facing method, and handles virtual dispatch.
4. **Match** — `SinkShapes` recognizes sink call patterns; `SanitizerShapes` recognizes
   bound checks and sanitizers that clear taint.
5. **Emit** — `TraceEmitter` writes a YAML document with the `source`, the reached `sink`,
   and the full `path` of hops between them.

Supported sink kinds: `Allocation` (`new_array`, `array_pool_rent`, `stackalloc`),
`SpanAccess` (`span_slice`, `span_index`), HTTP body reads, and `SqlInjection`
(`sql_command_text`, `sql_command_builder_append`).

The CWE-835 loop detector (`--scan-profile loop`) is a separate structural pass
(`LoopTerminationAnalyzer`) — it does not use the taint walker. It resolves a method's
async state machine, detects loop back-edges in the IL, and flags a read call inside a loop
whose completion signal is never consumed within that loop. It reports the dangerous *idiom*,
not provable non-termination.

The CWE-674 recursion detector (`--scan-profile recursion`) is a sibling structural pass
(`RecursionTerminationAnalyzer`). It flags recursion whose body carries no termination guard —
neither a visited-set / cycle tracker (`HashSet`/`Dictionary` `Add`/`Contains`) nor a recursion
depth cap (a counter compared against a constant). Property getters are candidates here (unlike
the loop profile), because recursive `$ref` resolution is commonly written as one. It detects
two shapes:

- **direct self-recursion** — a method that calls itself (`recursion: self`);
- **mutual recursion** — a call-graph cycle of two or more methods, e.g. A → B → A
  (`recursion: mutual`, with the cycle members listed). This runs an iterative Tarjan
  strongly-connected-components pass (`MethodCallGraph` + `StronglyConnectedComponents`) over
  the in-assembly call graph, scoped to the candidate surface; a cycle is cleared when any
  member carries a guard.

## Requirements

- **.NET SDK 10.0** (pinned in [`global.json`](global.json); rolls forward to latest feature band)

## Build

```bash
dotnet build TaintAnalyzer.sln
```

## Usage

The tool runs in two modes against a target assembly.

### Rules mode — analyze known entry points

Provide a `rules.yaml` that names the source methods to seed:

```bash
dotnet run --project tools/TaintAnalyzer -- <target.dll> \
    --rules rules.yaml \
    --output trace.yaml
```

```yaml
# rules.yaml
vuln_id: imagesharp-3074
source_methods:
  - SixLabors.ImageSharp.Formats.Bmp.BmpDecoderCore::Decode(SixLabors.ImageSharp.IO.BufferedReadStream,System.Threading.CancellationToken)
```

### Scan mode — auto-enumerate entry points

`--scan` discovers candidate source methods from the assembly's own signatures —
no hand-written rules needed — and is the basis for scanning unfamiliar libraries.

```bash
# DoS scan (default profile): byte-stream sources → allocation sinks
dotnet run --project tools/TaintAnalyzer -- <target.dll> --scan --progress

# SQL-injection scan: string sources gated on transitive reach to a SQL sink
dotnet run --project tools/TaintAnalyzer -- <target.dll> --scan --scan-profile sqli

# Loop-termination scan (CWE-835): read loops with no completion check
dotnet run --project tools/TaintAnalyzer -- <target.dll> --scan --scan-profile loop

# Recursion scan (CWE-674): self-recursion with no cycle/depth guard
dotnet run --project tools/TaintAnalyzer -- <target.dll> --scan --scan-profile recursion

# Emit the enumerated entry points as a rules.yaml (terminal — no analysis)
dotnet run --project tools/TaintAnalyzer -- <target.dll> --scan --emit-rules discovered-rules.yaml
```

### Flags

| Flag | Description |
|---|---|
| `--rules <path>` | Analyze the source methods listed in a rules YAML (mutually exclusive with `--scan`). |
| `--scan` | Auto-enumerate source methods from the assembly. |
| `--scan-profile dos\|sqli\|loop\|recursion` | Selects what `--scan` enumerates and reports (default `dos`). `loop` finds read loops with no completion check (CWE-835); `recursion` finds self-recursion with no cycle/depth guard (CWE-674). Requires `--scan`. |
| `--output <path>` | Write the trace YAML to a file instead of stdout. |
| `--emit-rules <path>` | (scan only) Write enumerated entry points as a rules YAML and exit. |
| `--enumerator-config <path>` | (scan only) Override the entry-point enumeration config. |
| `--include-this-field` | (scan only) Also seed `this`-fields as tainted. |
| `--include-virtual-overrides` | (scan only) Surface virtual-override implementations as entry points. |
| `--no-symbols` | Don't load the `.pdb` (traces omit file/line). |
| `--progress` | Print scan progress/timing to stderr. |

Exit codes: `0` success · `1` runtime error (assembly/rules not found, unresolved method) ·
`2` usage error.

## Repository layout

```
tools/TaintAnalyzer/            Analyzer engine + CLI (this is the tool)
tools/TaintAnalyzer.Tests/      Unit + end-to-end tests
tools/ValidateFixture/          Fixture trace-validation helper
fixtures/                       Locked source/rules/trace per finding (prefix = vuln, postfix = fix)
samples/                        Standalone proof-of-concept projects
scripts/                        materialize-*.sh / build-*.sh — reconstruct fixture inputs
docs/                           Scan reports and disclosure drafts
artifacts/                      Materialized third-party source trees (gitignored)
```

## Testing

```bash
dotnet test TaintAnalyzer.sln
```

The suite includes per-fixture end-to-end runs that assert the analyzer's output matches
each fixture's locked expectation — `trace.yaml` for taint findings, `findings.yaml` for the
structural loop (CWE-835) and recursion (CWE-674) passes — covering both vulnerable and
patched variants.

## License

[MIT](LICENSE) © Paweł Łukasik
