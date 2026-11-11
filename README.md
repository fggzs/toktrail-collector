# TokTrail Collector

[中文](README.zh-CN.md)

TokTrail Collector is a local-first Go CLI for collecting privacy-filtered token usage metadata from supported local developer tools.

The collector is designed so that local inspection stays useful without an account: `scan`, `preview`, `export`, and diagnostics work offline. Uploading requires an explicit device binding and a fresh server-side consent preflight.

## What it collects

Supported sources in the current implementation:

- Codex session JSONL (`codex-jsonl`).
- Claude Code session JSONL (`claude-code-jsonl`).
- DeepSeek Harness session JSONL (`deepseek-harness`).
- WorkBuddy AI session JSONL (`workbuddy-jsonl`): passive JSONL only.
- Qwen Code / Qwen CLI chat JSONL (`qwen-jsonl`): passive `api_response`/`usageMetadata` counters only.
- Kimi CLI wire JSONL (`kimi-cli-jsonl`): passive `StatusUpdate.token_usage` counters only.
- Kimi Code wire JSONL (`kimi-code-jsonl`): passive turn-scoped `usage.record` counters only.
- ZCode SQLite (`zcode-sqlite`): passive `model_usage` table counters only.
- Hermes Agent SQLite (`hermes-sqlite`): passive `state.db` usage table counters only.
- OpenClaw SQLite (`openclaw-sqlite`): passive `transcript_events.event_json` usage events only.
- Pi session JSONL (`pi-jsonl`): assistant message plus usage/model_usage entry counters only.
- Oh My Pi session JSONL (`omp-jsonl`): same format as Pi, read under `~/.omp`.
- CodeBuddy IDE session history (`codebuddy-history`): passive per-request usage counters from `index.json` files under the CodeBuddy IDE local data directory, plus the recorded model identifier and legacy turn timestamps resolved from the per-message files; completed requests only, conversation bodies are never read.
- OpenCode CLI session SQLite (`opencode-sqlite`): passive assistant-message usage counters from `~/.local/share/opencode/opencode.db`; message bodies are never read.
- Synthetic/free-form `usage-json` fixtures for integration and compatibility testing.

The collector uploads token usage counters, stable privacy-safe record identifiers, and source-specific model identifiers described below. It must not upload prompts, message bodies, raw session IDs, raw message IDs, or absolute local paths.

## Privacy and consent model

TokTrail Collector keeps three permissions separate:

1. **Local read grant**: which local paths scheduled collection may read.
2. **Upload consent**: whether a bound device may upload usage records to a TokTrail-compatible server.
3. **Public leaderboard consent**: whether projected usage can appear publicly.

Important invariants:

- `scan`, `preview`, and `export` do not require a TokTrail account.
- Scheduled collection reads only paths explicitly enabled through `sources` or `service install --grant`.
- A scheduled run with no enabled source grants performs no scan and no network request.
- `sync` performs `GET /v1/devices/self` before uploading and sends the learned consent revision with the ingest request.
- Unknown token counters remain unknown; they are not silently coerced to zero.
- Recorded model identifiers, including private names and local aliases, are preserved and uploaded when attribution is reliable. Missing or ambiguous attribution is `unknown`. Invalid identifiers are reported rather than silently changed. Identifiers are nonempty UTF-8 strings of at most 128 bytes without control characters; no aliases are resolved to backend identities. The leaderboard controls public disclosure.

## Repository layout

```text
cmd/toktrail/            Main collector CLI
cmd/toktrail-installer/  User installer and verifier
cmd/toktrail-release/    Maintainer CLI and legacy command compatibility
scripts/release.sh      Local and CI build orchestration
.github/workflows/      Tests and tag-driven releases
tools/release/          Archive assembly, signing, bootstrap templates and release E2E
internal/source/
  adapter/              Shared record contracts, validation, token and privacy helpers
  jsonl/                Shared JSONL file discovery, line reading, and decoding
  usagejson/            usage-json parser and tests
  codexjsonl/            Codex parser, replay filtering, and tests
  claudecodejsonl/       Claude Code parser, interval integrity, and tests
  deepseekharness/       DeepSeek Harness parser and tests
  workbuddyjsonl/        WorkBuddy JSONL parser and tests
  qwenjsonl/             Qwen Code / Qwen CLI JSONL parser and tests
  kimiwire/              Kimi CLI / Kimi Code wire JSONL parser and tests
  zcodesqlite/           ZCode SQLite parser and tests
  hermessqlite/          Hermes Agent SQLite parser and tests
  openclawsqlite/        OpenClaw SQLite parser and tests
  piwire/                Pi / Oh My Pi session JSONL parser and tests
  registry/             Explicit compiled-in adapter registry
  pipeline/             Scan, preview, export, and batch splitting
internal/local/         Local state, grants, outbox, commit, progress, lock, and quarantine
internal/app/           Application workflows: collection, diagnostics, and status
internal/bind/          Device binding
internal/connect/       One-step connect orchestration
internal/syncclient/    Server sync, ACK handling, reorganization, and recovery
internal/distribution/  Manifest, version, signature, hash and naming protocol
internal/installer/     Download, verification, extraction and safe binary replacement
internal/scheduler/     launchd, systemd user timer, and Windows Task Scheduler plans
docs/                   Architecture, release, and scheduling design notes
```

See [Architecture and adapter extension](docs/ARCHITECTURE.md) for dependency rules and the source extension path.

## Command surface

Common commands:

- `toktrail version` prints the collector version.
- `toktrail help` prints the available command surface.
- `toktrail connect '<URL>'` binds the device, applies the current authorization, installs the scheduled service, and resynchronizes authorized usage.
- `toktrail scan` summarizes local records without account or network access.
- `toktrail preview` validates and previews local records.
- `toktrail export` writes a server ingest batch and registers it in the local outbox.
- `toktrail bind` generates or reuses a local device secret and binds the device to a server-issued ticket.
- `toktrail status` checks the current bound device state.
- `toktrail sync` uploads either an explicit batch or the oldest pending local outbox batch.
- `toktrail resync --all --dry-run` previews archived, already-synced device batches for currently enabled local grants without network or writes. This is only the archive plan: it does not scan sources, inspect recoverable records, or verify remote consent.
- `toktrail resync --all` asks for confirmation, then scans enabled sources, recovers records eligible under current authorization, drains pending batches, and retransmits archived history. Cursor account usage receives a full-window sync when enabled. `--yes` skips the prompt; `--max-batches N` limits archive retransmissions in one invocation. Incomplete work is reported and can be resumed.
- `toktrail resync --all --force-recollect --dry-run` reads live device authorization and its reset plan, then scans every enabled, authorized local source from an empty baseline. Unlike ordinary resync dry-run, this performs read-only network requests and temporary isolated scanning; it never resets or uploads.
- `toktrail resync --all --force-recollect` explicitly clears this device's previous ordinary history and rebuilds it from the current sources under current authorization. The device identity, credentials and Cursor account state are preserved. Old records outside the current scope, or no longer available in source logs, will not be restored. Review the plan and confirm the prompt; `--expected-device ID` guards against running on the wrong bound machine, and `--max-batches N` limits uploads before a resumable stop. If interrupted, run the same command to resume: it never resets the server twice for the same job. The server and leaderboard must support `device-usage-reset`; old clients or old state backups cannot replay pre-reset batches into the new data epoch. A successful completion is server-side; the website projection follows asynchronously. Rejected settled batches cannot be corrected by repeated resumes: fix the cause, remove only `force-recollect.json` from this device's state directory to abandon the incomplete task, then explicitly confirm a new recollection. Preserve the installed new-epoch state and isolated archives; never restore old batch payloads.
- The current authorization determines what can be uploaded; narrowing it does not delete previously uploaded history. Deletion and revocation are managed on the leaderboard. Missing source data or archives cannot be reconstructed reliably, and cross-device deduplication is not guaranteed; preserve the collector state directory on reinstall.
- `toktrail sources` manages explicit local read grants for scheduled collection.
- `toktrail periodic` collects from enabled grants and drains a bounded number of pending batches.
- `toktrail service` installs or uninstalls the user-level scheduled task.
- `toktrail privacy` and `toktrail doctor` provide local diagnostics.

### Output and verbosity

- `connect`, `periodic`, and `resync` print concise English progress by default. Long-running phases emit a periodic human-readable status line; interactive confirmations are always shown in full.
- `--verbose` adds detail for the current run only. It changes what is printed, never what is authorized, scanned, uploaded, or confirmed: authorization, sync behavior, budget handling, and exit codes are identical with and without it.
- `connect` and `periodic` keep `--json` (exactly one stable result object on stdout; human text moves to stderr) and `--progress-json` (collection progress events as JSON Lines on stderr). Stderr is not pure JSONL: it may also carry human text and interactive prompts, so consumers must identify event lines by the top-level `"type":"collection_progress"` field. These machine interfaces are documented by their schemas and tests; their formats do not change with `--verbose`.
- Human-readable text — default output and `--verbose` output alike — is not a machine interface. It may be reworded between releases; scripts should consume `--json` / `--progress-json` instead of parsing human lines.
- Before sharing command output or logs, check them for local metadata (paths, device or account identifiers, batch ids, server URLs) and prefer the redacted `--json` summary.

## Quick start for local development

Build and inspect the CLI:

```sh
go run ./cmd/toktrail version
go run ./cmd/toktrail help
```

Scan and export Codex usage from a local directory:

```sh
go run ./cmd/toktrail scan --source codex-jsonl --input ~/.codex/sessions
go run ./cmd/toktrail export --source codex-jsonl --input ~/.codex/sessions --out ./codex-batch.json --batch codex-demo-1
```

Codex uses one streaming JSONL projection path: large message bodies, images and tool output are validated without being materialized, rather than passing through the shared reader's 16 MiB line limit. Model, timestamp and counter validation, physical line numbers and deduplication keys remain unchanged; malformed logs still fail explicitly instead of being silently skipped. No line-size tuning is required.

Scan and export Claude Code usage from a local directory:

```sh
go run ./cmd/toktrail scan --source claude-code-jsonl --input ~/.claude/projects
go run ./cmd/toktrail export --source claude-code-jsonl --input ~/.claude/projects --out ./claude-batch.json --batch claude-demo-1
```

Scan and export DeepSeek Harness usage from a local directory:

```sh
go run ./cmd/toktrail scan --source deepseek-harness --input ~/.dsh/sessions
go run ./cmd/toktrail export --source deepseek-harness --input ~/.dsh/sessions --out ./deepseek-batch.json --batch deepseek-demo-1
```

Scan and export WorkBuddy usage from a local directory:

```sh
go run ./cmd/toktrail scan --source workbuddy-jsonl --input ~/.workbuddy-ai/projects
go run ./cmd/toktrail export --source workbuddy-jsonl --input ~/.workbuddy-ai/projects --out ./workbuddy-batch.json --batch workbuddy-demo-1
```

Scan and export Qwen Code / Qwen CLI usage from a local directory:

```sh
go run ./cmd/toktrail scan --source qwen-jsonl --input ~/.qwen/projects
go run ./cmd/toktrail export --source qwen-jsonl --input ~/.qwen/projects --out ./qwen-batch.json --batch qwen-demo-1
```

Qwen specifics:

- The source passively reads Qwen Code / Qwen CLI chat JSONL only; it does not read runtime session IPC tokens, settings, credentials, or unrelated directories.
- Newer logs prefer `systemPayload.uiEvent.event.name = "qwen-code.api_response"`; when a file has no such events, the loader falls back to `assistant.usageMetadata` so the same main call is not counted twice.
- `promptTokenCount` / `input_token_count` includes cache read. The collector uploads net input plus `cacheRead`. Qwen logs do not reliably expose cache write, so the first version records it as `0` and never infers it from prices or prompt deltas.
- The default directory is `~/.qwen/projects`; old `~/.qwen/tmp/...` layouts and `~/.qwen/usage*.jsonl` ledgers are not authoritative sources yet and need later real-sample validation.

Scan and export Kimi CLI usage from a local directory:

```sh
go run ./cmd/toktrail scan --source kimi-cli-jsonl --input ~/.kimi/sessions
go run ./cmd/toktrail export --source kimi-cli-jsonl --input ~/.kimi/sessions --out ./kimi-cli-batch.json --batch kimi-cli-demo-1
```

Scan and export Kimi Code usage from a local directory:

```sh
go run ./cmd/toktrail scan --source kimi-code-jsonl --input ~/.kimi-code/sessions
go run ./cmd/toktrail export --source kimi-code-jsonl --input ~/.kimi-code/sessions --out ./kimi-code-batch.json --batch kimi-code-demo-1
```

Kimi specifics:

- Kimi CLI and Kimi Code are separate sources: `kimi-cli-jsonl` and `kimi-code-jsonl`. Their default roots are `~/.kimi/sessions` and `~/.kimi-code/sessions`.
- Kimi CLI reads `StatusUpdate.token_usage` from `wire.jsonl`; Kimi Code reads turn-scoped `usage.record` and skips session-scoped records pending real-sample validation of that scope.
- Counters map as `input_other`/`inputOther` → `input`, `input_cache_read`/`inputCacheRead` → `cacheRead`, `input_cache_creation`/`inputCacheCreation` → `cacheWrite`, and `output` → `output`.
- Kimi Desktop embedded runtime paths and archives are not default grants; validate real samples before granting them explicitly.

Scan and export ZCode usage from a local directory:

```sh
go run ./cmd/toktrail scan --source zcode-sqlite --input ~/.zcode/cli/db
go run ./cmd/toktrail export --source zcode-sqlite --input ~/.zcode/cli/db --out ./zcode-batch.json --batch zcode-demo-1
```

ZCode specifics:

- The source reads only ZCode local SQLite `model_usage` tables. The default grant directory is `~/.zcode/cli/db`, and every `*.sqlite` file in that directory is read.
- `input_tokens` includes cache read/write; the collector uploads net `input`, `cacheRead`, and `cacheWrite` separately.
- Reads use a read-only immutable SQLite DSN to avoid creating sidecar files in the live ZCode directory. WAL-only commits may appear on the next scheduled read after checkpointing.
- `rollout/model-io-*.jsonl`, `usage-archive.sqlite`, and `history-freeze.sqlite` are not included in the first version; validate real samples before extending the source.

Scan and export Hermes Agent usage from a local directory:

```sh
go run ./cmd/toktrail scan --source hermes-sqlite --input ~/.hermes
go run ./cmd/toktrail export --source hermes-sqlite --input ~/.hermes --out ./hermes-batch.json --batch hermes-demo-1
```

Hermes specifics:

- The source reads only Hermes Agent local `state.db` usage tables. It prefers `session_model_usage` and falls back to `sessions` summary counters for older schemas.
- Hermes counters are cumulative session/model snapshots, so the collector uploads `kind="cumulative"` records and lets the server derive deltas by stable group/reset keys.
- The default grant directory is `~/.hermes`; profile directories such as `~/.hermes/profiles/<name>/state.db` are not discovered automatically in the first version.
- The source does not read `auth.json`, messages, FTS tables, logs, or legacy session JSONL, so credentials and conversation bodies stay out of the collector.

Scan and export OpenClaw usage from a local directory:

```sh
go run ./cmd/toktrail scan --source openclaw-sqlite --input ~/.openclaw/agents
go run ./cmd/toktrail export --source openclaw-sqlite --input ~/.openclaw/agents --out ./openclaw-batch.json --batch openclaw-demo-1
```

OpenClaw specifics:

- The source recursively discovers `openclaw-agent.sqlite` files and reads only `transcript_events.event_json` rows that carry usage.
- The default grant directory is `~/.openclaw/agents`; legacy JSONL and archive artifacts are not authoritative in the first version.
- Compressed `event_zstd` rows are reported and skipped in this first version; add zstd decoding before relying on compressed stores for complete totals.
- Credentials, control-plane state, and non-usage transcript content are not uploaded; records contain counts, model, time, and a hashed event identity.

Scan and export Pi usage from a local directory:

```sh
go run ./cmd/toktrail scan --source pi-jsonl --input ~/.pi/agent/sessions
go run ./cmd/toktrail export --source pi-jsonl --input ~/.pi/agent/sessions --out ./pi-batch.json --batch pi-demo-1
```

Scan and export Oh My Pi usage from a local directory:

```sh
go run ./cmd/toktrail scan --source omp-jsonl --input ~/.omp/agent/sessions
go run ./cmd/toktrail export --source omp-jsonl --input ~/.omp/agent/sessions --out ./omp-batch.json --batch omp-demo-1
```

Scan and export CodeBuddy IDE usage from a local directory:

```sh
# POSIX: $XDG_DATA_HOME/CodeBuddyExtension/Data (default ~/.local/share/...)
go run ./cmd/toktrail scan --source codebuddy-history --input "$HOME/.local/share/CodeBuddyExtension/Data"
go run ./cmd/toktrail export --source codebuddy-history --input "$HOME/.local/share/CodeBuddyExtension/Data" --out ./codebuddy-batch.json --batch codebuddy-demo-1

# Windows: ~/AppData/Local/CodeBuddyExtension/Data
go run ./cmd/toktrail scan --source codebuddy-history --input "~/AppData/Local/CodeBuddyExtension/Data"
go run ./cmd/toktrail export --source codebuddy-history --input "~/AppData/Local/CodeBuddyExtension/Data" --out ./codebuddy-batch.json --batch codebuddy-demo-1
```

Scan and export OpenCode usage from a local directory:

```sh
go run ./cmd/toktrail scan --source opencode-sqlite --input ~/.local/share/opencode
go run ./cmd/toktrail export --source opencode-sqlite --input ~/.local/share/opencode --out ./opencode-batch.json --batch opencode-demo-1
```

OpenCode specifics:

- OpenCode stores every conversation message in one SQLite database at `~/.local/share/opencode/opencode.db`. The adapter reads only assistant rows in the `session_message` table, which is the current layout's authoritative message store and a superset of the legacy `message` table, so reading it alone avoids double counting.
- OpenCode usage uses OpenAI-style disjoint buckets: `tokens.input` excludes cache reads, `tokens.cache.read`/`write` are listed separately, and `tokens.reasoning` is an informational subset of `output` that is not uploaded separately. The four uploaded buckets are verbatim `input`/`cacheRead`/`cacheWrite`/`output`.
- Reads use a read-only immutable SQLite DSN to avoid creating sidecar files in the live OpenCode directory. WAL-only commits may appear on the next scheduled read after checkpointing.
- The `model` field is recorded as `providerID/modelID` when attribution is present; messages without it report `unknown`.

CodeBuddy specifics:

- CodeBuddy IDE (CodeBuddy CN) stores one `index.json` per conversation under `<CodeBuddyExtension data>/<userId>/CodeBuddyIDE/<userId>/history/<workspace>/<conversation>/`. The adapter discovers every index proven to be a conversation below the granted path and reads its `requests[].usage` counters plus, only for a directory grant, the small per-message files needed for model attribution; message bodies are never interpreted, retained or exported, and a single-file grant reads no sibling file. The data directory follows the XDG base spec on POSIX hosts (`$XDG_DATA_HOME/CodeBuddyExtension/Data`, default `~/.local/share/CodeBuddyExtension/Data`) and is `~/AppData/Local/CodeBuddyExtension/Data` on Windows; both layouts are probed, in that order.
- Only `state == "complete"` requests are collected. Running requests publish partial usage snapshots that would double count once the request completes, and canceled requests lack a `startedAt` timestamp.
- CodeBuddy semantics verified against real histories: `inputTokens` is the total prompt, split three ways as `cacheTokens` (cache read) + `cachedWriteTokens` (cache write) + `cachedMissTokens` (uncached). The adapter uploads the uncached share as `input`, `cacheTokens` as `cacheRead` and `cachedWriteTokens` as `cacheWrite`, so the three buckets add back up to the recorded prompt. `totalTokens` must equal `inputTokens + outputTokens`, the recorded split must not exceed `inputTokens`, and a non-zero `cachedMissTokens` must make the three shares sum exactly to `inputTokens`; legacy rows with all three cache fields absent upload the whole prompt as uncached (`cacheRead=0`, `cacheWrite=0`), while partial splits remain quarantined rather than discarding recorded cache usage.
- `startedAt` (epoch milliseconds, seconds tolerated) is the only accepted clock value: a request without a valid `startedAt` is quarantined rather than dated from a message file modification time, which restores and plain copies rewrite.
- Older conversations keep `{"inputTokens":null,...}` placeholders for turns that never recorded counts; those rows account for nothing and are skipped, not quarantined.
- The request index records no model identifier. It is read from the per-message files (`extra.modelId`): a turn is attributed only when every assistant message naming its `extra.requestId` reports the same model, and a turn that keeps the model on its single user message is accepted only when that message's own `extra.requestId` equals the request id. A mixed, unnamed or unreadable set reports `unknown` with a value-free local issue and still exports its counters.

Pi / Oh My Pi specifics:

- Pi (badlogic/pi-mono, now earendil-works/pi) and Oh My Pi (omp, a can1357 fork) write the same JSONL session format. They register as two separate sources, `pi-jsonl` and `omp-jsonl`, with default roots `~/.pi/agent/sessions` and `~/.omp/agent/sessions`.
- Session files are append-only trees (a header line followed by entries with id/parentId/timestamp). The collector reads assistant message `usage` plus standalone `usage` / `model_usage` entries (Oh My Pi calls outside the conversation flow such as title generation); each is a per-request delta.
- The four usage buckets are `input`/`output`/`cacheRead`/`cacheWrite` (OpenAI convention: disjoint, input excludes cache). The collector uploads them verbatim with no arithmetic; `reasoningTokens` is an informational subset of output and is not uploaded separately.
- Both products read the same `PI_CODING_AGENT_DIR`/`PI_CODING_AGENT_SESSION_DIR` environment variable names; honoring them from two sources could scan one directory twice, so the first version ignores them and uses the fixed default paths only.
- /fork copies the active branch into a new session file, which can re-count historical requests; branch and reset semantics need real-sample validation. Oh My Pi profile directories (`~/.omp/profiles/<name>/agent/sessions`) are not discovered automatically and need an explicit grant.

WorkBuddy specifics:

- The source is passive JSONL only: it reads the session JSONL files WorkBuddy appends to and never writes to them.
- It does not cover the WorkBuddy SQLite history database; usage recorded only there is not collected.
- Recorded request model identifiers are included in uploads when they can be attributed reliably; they do not imply a verified backend identity.
- Both `connect` and scheduled grant sync prefer `~/.workbuddy-ai/projects` and fall back to `~/.workbuddy/projects` only when the preferred directory is absent. They do not automatically merge the two directories. On Windows, `~` is the home directory of the account running the collector.
- Scheduled grant sync preserves existing grants for known default layouts and manual disable decisions. `connect` still reapplies the current authorization; add custom or non-standard paths afterward with `toktrail sources enable --source workbuddy-jsonl --input <path>` and re-check them after reconnecting.

Bind and sync against a local development server:

```sh
TOKTRAIL_BIND_TICKET=dev-ticket go run ./cmd/toktrail bind \
  --server http://127.0.0.1:3211 \
  --application leaderboard-local \
  --subject demo-user \
  --device-name my-mac

TOKTRAIL_BIND_TICKET=dev-ticket go run ./cmd/toktrail status \
  --server http://127.0.0.1:3211

go run ./cmd/toktrail sync --server http://127.0.0.1:3211
```

`TOKTRAIL_BIND_TICKET=dev-ticket` is a local placeholder. Production deployments should provide one-time bind tickets through their own account and setup flow.

## Scheduled collection

Scheduled collection is opt-in. Enable explicit source grants before installing a user-level task:

```sh
go run ./cmd/toktrail service install \
  --grant codex-jsonl=$HOME/.codex/sessions \
  --grant claude-code-jsonl=$HOME/.claude/projects \
  --grant deepseek-harness=$HOME/.dsh/sessions \
  --grant workbuddy-jsonl=$HOME/.workbuddy-ai/projects \
  --grant qwen-jsonl=$HOME/.qwen/projects \
  --grant kimi-cli-jsonl=$HOME/.kimi/sessions \
  --grant kimi-code-jsonl=$HOME/.kimi-code/sessions \
  --grant zcode-sqlite=$HOME/.zcode/cli/db \
  --grant hermes-sqlite=$HOME/.hermes \
  --grant openclaw-sqlite=$HOME/.openclaw/agents \
  --grant pi-jsonl=$HOME/.pi/agent/sessions \
  --grant omp-jsonl=$HOME/.omp/agent/sessions \
  --grant codebuddy-history=$HOME/.local/share/CodeBuddyExtension/Data \
  --grant opencode-sqlite=$HOME/.local/share/opencode \
  --interval 30m
```

The installed task runs only:

```text
<toktrail binary> periodic --state-dir <absolute state dir>
```

No server URL or secret appears on the scheduler command line. See [Scheduled collection](docs/SCHEDULING.md) for the full model and platform notes. Windows uses the bundled `toktrail-background.exe` to collect without a console window. After installing the complete new release, migrate an existing task with `toktrail service refresh`; binding and grants stay unchanged. See the [Windows 10/11 test plan](docs/WINDOWS_BACKGROUND_TEST_PLAN.zh-CN.md).

## Signed releases and installation

GitHub Actions and `scripts/release.sh` build six platform targets. Maintainer tooling assembles archives and signs the manifest; the standalone installer verifies signatures and SHA-256 hashes before replacement. The tag workflow automatically publishes the GitHub Release after the configured environment approval and all signing and verification steps succeed. Prerelease tags are published as prereleases and do not become Latest. The installer and bootstrap scripts also support an explicit in-place `upgrade` that reuses the original install path, keeps the previous binary as `<binary>.previous`, and never touches state, grants, outbox, device binding or scheduler registration. See [Release and installation](docs/RELEASE.md).

Production operators must provide their own release signing keys, trusted public-key distribution channel, download hosting, and any platform-specific notarization or code signing.

## Development checks

Run these before committing:

```sh
gofmt -l cmd internal tools
GOCACHE="$PWD/.gocache" GOPROXY=off go test ./...
GOCACHE="$PWD/.gocache" GOPROXY=off go vet ./...
```

The release end-to-end test is slower and gated explicitly:

```sh
GOCACHE="$PWD/.gocache" GOPROXY=off TOKTRAIL_RELEASE_E2E=1 go test ./tools/release/ -run '^TestEndToEndRelease$' -count=1 -v
```

## Known Cursor limitations (account-level network source)

- The desktop login state is read strictly read-only (SQLite `mode=ro`, auth keys only); the credential stays in memory and never reaches disk, logs, or uploads.
- The state database's WAL content is immutable but not readable in every state: already-checkpointed logins read fine at any time; a freshly created login may live only in the WAL until Cursor itself closes and checkpoints it. The error messages state this honestly — no claim is made that every login state is readable.
- An unattended scheduled run can never complete the first-time authorization: the local confirmation must be given interactively via connect or `toktrail cursor enable`.
- Account-level totals are aggregated by Cursor and may include usage from other machines. The first version supports one Cursor account source per user with one designated collector device; takeover is a website-side reassignment — the collector never claims an occupied executor slot.

## Contributing and security

- See [CONTRIBUTING.md](CONTRIBUTING.md) for development rules and pull request expectations.
- See [SECURITY.md](SECURITY.md) before reporting vulnerabilities or privacy issues.

## License

MIT. See [LICENSE](LICENSE).
