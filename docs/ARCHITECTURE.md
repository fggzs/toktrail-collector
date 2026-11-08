# Collector architecture and adapter extension

The collector separates source parsing, common collection orchestration, durable local state, and remote synchronization. Source packages own their business rules and fixtures. The common pipeline resolves sources through the same explicit registry used by CLI discovery and grant validation.

## Package ownership

| Package | Responsibility |
| --- | --- |
| `cmd/toktrail` | CLI flags, command dispatch, and user-facing output |
| `internal/app` | Collection, diagnostics, and status workflows |
| `internal/source/adapter` | `contract.go` defines record and loader contracts; `record.go` validates counters and totals; `privacy.go` owns upload privacy policy |
| `internal/source/jsonl` | Deterministic file enumeration, bounded line reading, and strict object decoding |
| `internal/source/usagejson` | Usage JSON decoding and privacy projection |
| `internal/source/codexjsonl` | Codex event parsing, cumulative counter deltas, and export replay filtering |
| `internal/source/claudecodejsonl` | Claude Code assistant usage parsing, message intervals, and progress integrity |
| `internal/source/registry` | Validated descriptors and an explicit compiled-in source list |
| `internal/source/pipeline` | Scan summaries, preview rows, export preparation, and bounded batch splitting |
| `internal/local` | Grants, process lock, durable state, export journal, outbox, progress, and quarantine |
| `internal/bind` | Device binding and persistence of the binding receipt |
| `internal/connect` | One-step connect orchestration: ticket validation, server config fetch, device bind, tool probing, grants configuration, scheduler install, and initial collection |
| `internal/syncclient` | Fresh server consent checks, upload, retry accounting, ACKs, and recovery |
| `internal/scheduler` | User-scope scheduler plans and installation |
| `internal/distribution` | Strict manifest, version, signature, hash and artifact-name protocol; no build orchestration or installation |
| `internal/installer` | Bounded download, archive extraction, verification, safe binary replacement and explicit in-place upgrade |
| `cmd/toktrail-installer` | User-facing install and verification commands |
| `cmd/toktrail-release` | Maintainer commands and compatibility entry point; `build` delegates to the shell script |
| `tools/release` | Maintainer-only archive assembly, manifest and capabilities signing, and pinned bootstrap generation; consumes built binaries |
| `scripts/release.sh` | Shared local/CI cross-compilation and assembly entry point |
| `.github/workflows/release.yml` | Tag validation, tests, six-target matrix, protected signing and automatic GitHub Release publication |

The dependency direction for source collection is:

```text
CLI / app workflows
        |
        v
     pipeline ------> adapter (shared contracts and policy)
        |
        v
     registry ------> usagejson / codexjsonl / claudecodejsonl
                              |
                              v
                         adapter + jsonl
```

Source packages may depend on durable local ledgers needed by their parsing rules. Local grants use the registry to validate source identifiers; source packages must therefore avoid importing grants or the application workflows. Upload validation depends only on shared adapter contracts and privacy policy.

## Runtime flow

1. A manual command selects a source and input explicitly. A periodic collection run acquires the process lock and refreshes device consent before scanning. A bound device contacts the server even when it has no enabled grants, so an explicitly authorized managed source can be provisioned. An unbound device does not make this request.
2. A device marked as managed may add only the compiled-in default paths for its explicitly authorized tools. A legacy unmanaged device filters its existing local grants but never adds sources automatically. Pause, revocation, or a failed refresh after the new protocol was observed stops local reads; a first-ever network failure retains legacy local behavior.
3. The pipeline resolves the descriptor, validates common options, and calls its loader. The loader owns source-specific input rules, parsing, and local progress interpretation.
4. Scan and preview present local results. Export additionally invokes the descriptor's optional `FilterForExport` hook. Codex uses that hook to exclude records already represented in outbox or quarantine history.
5. Export splitting preserves record identity and associates message interval updates with the corresponding child batch. Limits remain 500 records and 768 KiB per compact export envelope. An oversized singleton fails closed.
6. Before starting a new durable export transaction, `exportcommit` asks the registry to run the descriptor's optional `ValidateCommit` hook. Claude uses it to catch progress-state loss between preparation and commit. The existing export journal freezes batch content and message updates for idempotent recovery.
7. Synchronization validates the upload whitelist and fetches fresh `GET /v1/devices/self` consent state before uploading. The latest scope is checked locally before any batch POST: out-of-scope records are quarantined and permitted records are rebatched through the durable journal. The server also enforces the revision and scope on ingest. A scope change after preflight can still race network transmission; the server prevents stale-revision data from being committed but cannot recall bytes already sent.

## Adding a source

1. Create a package under `internal/source/<name>` and implement its real parser there. Keep synthetic source fixtures, parser tests, and source-specific state rules in the same package.
2. Return an `adapter.Adapter` descriptor with a stable source identifier, description, and `Load` function. Use `FilterForExport` only for export-specific filtering, and `ValidateCommit` for integrity checks that must run again at the transaction boundary.
3. Produce `adapter.Record` values that satisfy shared validation and privacy policy. Preserve unknown token counters as unknown; validate all decimal counters as uint64. Preserve reliably attributable recorded model identifiers without a public allowlist; never infer backend identities.
4. Add the descriptor to the explicit production list in `internal/source/registry`. Discovery, grant validation, and the common scan/preview/export path then see the same source list. Registration uses no `init()` side effects.
5. Test the parser's semantics and privacy projection. Exercise the descriptor with `registry.New` and `pipeline.New` to verify scan, preview, export preparation, filtering, and any commit integrity hook. Tests must use the production implementations of registry and pipeline, without a separate loader dispatch switch.
6. Run formatting, the full offline test suite, vet, all three command builds, and the release end-to-end check described in [Contributing](../CONTRIBUTING.md).

Registry construction rejects empty identifiers and duplicate registrations. Registry enumeration returns a copy, so callers cannot change the production source list by mutating a discovery result. Unsupported identifiers fail with `unsupported source %q` rather than falling back to another parser.

## Compatibility boundaries

Source identifiers and their discovery order are `usage-json`, `codex-jsonl`, `claude-code-jsonl`, `deepseek-harness`, `workbuddy-jsonl`, `qwen-jsonl`, `kimi-cli-jsonl`, `kimi-code-jsonl`, `zcode-sqlite`, `hermes-sqlite`, `openclaw-sqlite`, `pi-jsonl`, `omp-jsonl`, and `codebuddy-json`. Record keys, grouping hashes, adapter version strings, batch identifiers, and persistent ledger formats remain stable. The files `adapter-cursors.json`, `outbox.json`, `scope-quarantine.json`, and `export-transaction.json` retain their existing formats.

When the device-grant protocol supplies an explicit tool list, an existing generic `usage-json` grant is conservatively skipped because its file can contain records for arbitrary tools and the source cannot be mapped to a single authorized tool before reading. Its files, progress, and outbox are not deleted. Unrestricted or legacy-server scopes retain the previous behavior. To collect a supported tool under a restricted scope, use its explicitly authorized built-in source.

JSONL sources share sorted file discovery, optional hidden-file exclusion, `json.Number` decoding, rejection of trailing JSON, and a 16 MiB line limit. Each source retains its own event semantics. Include-cache totals remain input + cache read + cache write + output; exclude-cache totals remain input + output.

The device-grant protocol adds fields to device self responses and an acknowledgement endpoint. Older collectors retain their existing upload path, while server-side ingest enforces each device's effective scope.

The grant-ack body carries an optional capability report alongside `consentRevision`/`applyState`/`collectorVersion`: `supportedTools` lists the tool names actually registered in the collector build (canonical registry names, sorted, never local paths) and `pendingReasons` lists one closed-code entry per restricted tool (`unsupported_tool`, `missing_input`, `disabled`) — `[]` explicitly when nothing is restricted; the field is omitted entirely when a restriction has no closed code (the server reads "reasons unknown", never a complete or partial receipt). Tool names are limited to `^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$`, so no path can travel in a tool or reason field, and reason classification matches the fixed reason-text prefixes (never substrings) so directory names containing classification words cannot flip a code. An older server that rejects the unknown fields with HTTP 400/422 gets exactly one retry with the legacy payload; that fallback is recorded locally as "capabilities not reported" (never faked, retried on the next run) and surfaced as a run note. The local ack cache treats the capability payload, the reason codes, and reason completeness as part of the ack key: a changed registered-tool list, pending-reason set, or completeness re-acks the same consent revision.

## Release and installation dependencies

```text
GitHub Actions / local operator
          |
          v
   scripts/release.sh --------> go build cmd/toktrail + cmd/toktrail-installer
          |
          v
     tools/release ----------> distribution

cmd/toktrail-installer ------> installer ------> distribution
cmd/toktrail-release --------> distribution + installer
          |
          +-- build compatibility delegates to scripts/release.sh
```

The distributed installer has no dependency on archive creation, signing-key generation, bootstrap rendering or cross-compilation. Bootstrap templates live in `tools/release/templates`, and Go embeds them only to substitute version/public-key/hash pins. The maintainer CLI remains available without creating another repository or service. Manifest schema 1 and legacy installer filenames preserve existing setup integration. See [Release and installation](RELEASE.md) for commands, CI environment configuration and the trust boundary.
