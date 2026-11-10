package recollect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

// upload.go drains the installed rebuild batches through the ordinary
// syncclient send path — one Run per frozen batch, selected by
// PreferBatchID so the ACK lands in the installed outbox (the batch is
// marked synced, the export cursor confirmed, and per-message intervals
// advance to their pending to-states). Every upload carries the job's
// AllowedResetRequestID so the reset-journal guard lets the rebuild's own
// sends through while every ordinary entrypoint stays blocked; the
// data-epoch fences are NOT bypassed (each batch must carry the epoch the
// journal transition installed, and the live server epoch must match it).
// No Cursor orchestration is ever invoked here.
//
// Scope drift never re-plans the frozen artifacts: a pass that observes a
// changed live scope stops resumable with the plan untouched, and records
// the live scope excluded in the meantime are quarantined recoverable by
// syncclient's own gate — the same command drains them once the
// authorization covers them again.

// uploadOutcome folds one upload phase's counters.
type uploadOutcome struct {
	uploads         int
	uploadedBatches int
	uploadedRecords int
	accepted        int
	rejected        int
	replays         int
	blocked         int
	failed          int
	stopped         string
}

// preflightSelfOnce performs one fresh, preflight-accounted device self
// fetch against the real state — the run-level epoch and scope check
// before the upload phase. The attempt accounting write happens first: if
// it fails, zero HTTP traffic of any kind occurs. A dry run never reaches
// this path.
func preflightSelfOnce(ctx context.Context, store statedir.Store, serverURL string, client *http.Client, nowFunc func() time.Time) (syncclient.SelfStatus, error) {
	stateDir := store.Dir()
	if stateDir != "" {
		if _, err := outbox.New(stateDir).RecordPreflightAttempt(nowFunc().UTC()); err != nil {
			return syncclient.SelfStatus{}, fmt.Errorf("cannot persist preflight attempt accounting before the authorization check; no HTTP request was made and the job stays resumable: %w", err)
		}
	}
	return syncclient.FetchDeviceSelf(ctx, store, syncclient.Options{ServerURL: serverURL, HTTPClient: client})
}

// verifyUploadEpoch checks the live self snapshot against the job's
// installed epoch before uploads (and before the completion write): the
// server must still sit at the epoch this rebuild's receipt installed.
// Anything else means another reset moved the device, and this job's
// batches — stamped with the installed epoch — can never upload.
func verifyUploadEpoch(self syncclient.SelfStatus, j job) error {
	liveEpoch, err := selfEpoch(self)
	if err != nil {
		return err
	}
	if liveEpoch != j.NextDataEpoch {
		return fmt.Errorf("%w: the server reports data epoch %d but this rebuild installed epoch %d; another usage reset moved the device's epoch — remove %s and the recollect directories it names to abandon this job and start a fresh force recollection", syncclient.ErrEpochStale, liveEpoch, j.NextDataEpoch, journalPath(j.StateDir))
	}
	return nil
}

// uploadBatches drains the frozen batches. The caller holds the runlock,
// the journal is past the install, and every batch file is installed and
// hash-verified. Batches already done are skipped; a batch whose outbox
// entry became synced by an ACK whose journal write crashed converges to
// done; a reorganized entry is a deterministic blocked outcome; anything
// else uploads once. The pass stops (resumable) on the first rejection,
// authorization stop, epoch fence, budget bound, or observed scope drift.
func uploadBatches(ctx context.Context, store statedir.Store, client *http.Client, j *job, opt Options, res *Result, emit func(ProgressEvent)) (uploadOutcome, error) {
	out := uploadOutcome{}
	ledger := outbox.New(j.StateDir)
	book, err := ledger.Load()
	if err != nil {
		return out, err
	}
	entries := make(map[string]outbox.BatchEntry, len(book.Batches))
	for _, entry := range book.Batches {
		entries[entry.BatchID] = entry
	}
	for idx := range j.Batches {
		b := &j.Batches[idx]
		if b.Outcome == outcomeDone {
			res.Plan.DoneInJob++
			continue
		}
		if budget := opt.uploadBudget(); budget > 0 && out.uploads >= budget {
			out.stopped = fmt.Sprintf("upload budget reached (%d upload(s) this run); re-run the same command to continue the rebuild", budget)
			break
		}
		entry, ok := entries[b.BatchID]
		if !ok {
			return out, fmt.Errorf("the installed outbox does not list the frozen batch %s; the rebuild state diverged, failing closed", b.BatchID)
		}
		switch entry.Status {
		case outbox.StatusSynced:
			// An ACK whose journal write crashed: converge to done. The
			// outbox entry carries the receipt counts.
			b.Outcome = outcomeDone
			b.Uploads = append(b.Uploads[:0], jobUpload{
				UploadBatchID:   b.BatchID,
				ReceiptStatus:   entry.ReceiptStatus,
				AcceptedRecords: entry.AcceptedRecords,
				RejectedRecords: entry.RejectedRecords,
				SyncedAt:        entry.SyncedAt,
			})
			if err := saveJob(j.StateDir, *j, opt.now()); err != nil {
				return out, err
			}
			res.Plan.DoneInJob++
			continue
		case outbox.StatusReorganized:
			// A live-scope reorganization redistributed this batch; its
			// in-scope records moved to a child batch, everything else is
			// quarantined recoverable. The frozen batch is terminally
			// blocked for this job; the drain phase below settles its
			// records.
			b.Outcome = outcomeBlocked
			b.BlockedReason = "the live consent scope reorganized this batch; its in-scope records moved to a derived batch and the rest are quarantined recoverable"
			if err := saveJob(j.StateDir, *j, opt.now()); err != nil {
				return out, err
			}
			out.blocked++
			res.Blocked++
			emit(ProgressEvent{BatchID: b.BatchID, Outcome: outcomeBlocked, Records: b.Records, Err: b.BlockedReason})
			continue
		}
		b.Attempts++
		runRes, runErr := syncclient.Run(ctx, store, syncclient.Options{
			ServerURL:             j.ServerURL,
			StateDir:              j.StateDir,
			PreferBatchID:         b.BatchID,
			HTTPClient:            client,
			AllowedResetRequestID: j.RequestID,
		})
		if runErr != nil {
			switch {
			case errors.Is(runErr, syncclient.ErrDeviceRevoked), errors.Is(runErr, syncclient.ErrSubjectDeleted):
				if err := saveJob(j.StateDir, *j, opt.now()); err != nil {
					return out, err
				}
				out.stopped = "device no longer authorized"
				return out, fmt.Errorf("the rebuild stopped; the job stays resumable and nothing further was sent: %w", runErr)
			case errors.Is(runErr, syncclient.ErrDevicePaused):
				if err := saveJob(j.StateDir, *j, opt.now()); err != nil {
					return out, err
				}
				out.stopped = "device paused"
				return out, fmt.Errorf("the rebuild stopped; the job stays resumable and nothing further was sent: %w", runErr)
			case errors.Is(runErr, syncclient.ErrEpochStale):
				if err := saveJob(j.StateDir, *j, opt.now()); err != nil {
					return out, err
				}
				out.stopped = "data epoch stale"
				return out, fmt.Errorf("the rebuild stopped on the data epoch fence: %w", runErr)
			case errors.Is(runErr, syncclient.ErrScopeChanged), errors.Is(runErr, syncclient.ErrOutsideScope):
				b.Outcome = outcomeBlocked
				b.BlockedReason = "the server rejected the batch under the live consent scope"
				if err := saveJob(j.StateDir, *j, opt.now()); err != nil {
					return out, err
				}
				out.blocked++
				res.Blocked++
				out.stopped = "server scope rejection"
				emit(ProgressEvent{BatchID: b.BatchID, Outcome: outcomeBlocked, Records: b.Records, Err: b.BlockedReason})
				return out, fmt.Errorf("the rebuild stopped after a server-side scope rejection; the frozen plan is untouched and the job stays resumable — restore the planned authorization and re-run the same command, which continues the frozen batches and drains the recoverable quarantine: %w", runErr)
			default:
				b.Outcome = outcomeFailed
				b.Error = runErr.Error()
				if err := saveJob(j.StateDir, *j, opt.now()); err != nil {
					return out, err
				}
				out.failed++
				out.stopped = "upload failed"
				emit(ProgressEvent{BatchID: b.BatchID, Outcome: outcomeFailed, Records: b.Records, Err: "upload failed"})
				return out, fmt.Errorf("the rebuild stopped after an upload failed; the job stays resumable and the failed batch is retried by the next run: %w", runErr)
			}
		}
		if runRes.Receipt.BatchID == "" {
			b.Outcome = outcomeFailed
			b.Error = "sync returned no batch receipt"
			if err := saveJob(j.StateDir, *j, opt.now()); err != nil {
				return out, err
			}
			out.failed++
			out.stopped = "upload failed"
			return out, errors.New("the rebuild stopped: an upload returned no batch receipt; the job stays resumable")
		}
		b.Outcome = outcomeDone
		b.Error = ""
		b.Uploads = append(b.Uploads, jobUpload{
			UploadBatchID:   runRes.Receipt.BatchID,
			ReceiptStatus:   runRes.Receipt.Status,
			AcceptedRecords: runRes.Receipt.AcceptedRecords,
			RejectedRecords: runRes.Receipt.RejectedRecords,
			Replay:          runRes.Receipt.Replay,
			SyncedAt:        runRes.Receipt.ReceivedAt,
		})
		if err := saveJob(j.StateDir, *j, opt.now()); err != nil {
			return out, err
		}
		out.uploads++
		out.uploadedBatches++
		out.uploadedRecords += runRes.Receipt.AcceptedRecords + runRes.Receipt.RejectedRecords
		out.accepted += runRes.Receipt.AcceptedRecords
		out.rejected += runRes.Receipt.RejectedRecords
		if runRes.Receipt.Replay {
			out.replays++
		}
		res.Uploads++
		res.UploadedBatches++
		res.UploadedRecords += runRes.Receipt.AcceptedRecords + runRes.Receipt.RejectedRecords
		res.AcceptedRecords += runRes.Receipt.AcceptedRecords
		res.RejectedRecords += runRes.Receipt.RejectedRecords
		if runRes.Receipt.Replay {
			res.ReplayReceipts++
		}
		res.Plan.DoneInJob++
		emit(ProgressEvent{
			BatchID:       b.BatchID,
			UploadBatchID: runRes.Receipt.BatchID,
			Outcome:       outcomeDone,
			Records:       b.Records,
			Uploaded:      runRes.Receipt.AcceptedRecords + runRes.Receipt.RejectedRecords,
			Accepted:      runRes.Receipt.AcceptedRecords,
			Rejected:      runRes.Receipt.RejectedRecords,
			Replay:        runRes.Receipt.Replay,
		})
		// A receipt with rejections stops the pass immediately: the
		// server refused part of the rebuild, and completing the marker
		// over rejected records would misreport the rebuild.
		if runRes.Receipt.RejectedRecords > 0 {
			out.stopped = "records rejected"
			return out, fmt.Errorf("the rebuild stopped: the server rejected %d record(s) of a frozen batch; those records were NOT rebuilt. The completion marker will not be sent. Fix the cause, then remove %s to abandon this incomplete task and start a new explicitly confirmed force recollection; keep the installed new-epoch state and never restore old batches", runRes.Receipt.RejectedRecords, journalPath(j.StateDir))
		}
		// A changed live scope does not stop the pass mid-run either:
		// every later upload re-checks the live consent per record
		// (out-of-scope records are quarantined recoverable) and the
		// drain phase settles them. The frozen plan is never re-scoped.
	}
	return out, nil
}

// drainRecoveryBatches settles everything the frozen plan left behind in
// the installed outbox and quarantine store: derived children of a
// live-scope reorganization, re-pended recovery batches, and any record
// the scan itself quarantined as outside the live authorization. It keeps
// draining through the ordinary syncclient path — every send re-checked
// against the live consent and epoch — until the outbox is empty and the
// quarantine store is either empty or held (nothing currently
// recoverable). Ordinary collection stays journal-blocked the whole time,
// so this drain is the ONLY path that delivers those records.
func drainRecoveryBatches(ctx context.Context, store statedir.Store, client *http.Client, j *job, opt Options, res *Result, out *uploadOutcome) error {
	for {
		pending, err := pendingOutboxCount(j.StateDir)
		if err != nil {
			return err
		}
		quarantined, err := quarantineStoreCount(j.StateDir)
		if err != nil {
			return err
		}
		if pending == 0 && quarantined == 0 {
			return nil
		}
		if pending == 0 {
			// Recovery probe: one authorized self GET; recoverable
			// records are re-pended, everything else reports the settled
			// quarantine-held state.
			runRes, runErr := syncclient.Run(ctx, store, syncclient.Options{
				ServerURL:             j.ServerURL,
				StateDir:              j.StateDir,
				HTTPClient:            client,
				AllowedResetRequestID: j.RequestID,
			})
			if runErr != nil {
				if errors.Is(runErr, syncclient.ErrQuarantineHeld) {
					// Settled: nothing is recoverable under the live
					// authorization right now. The rebuild may complete;
					// the withheld records stay quarantined and are
					// delivered by later runs of this same command once
					// the authorization widens.
					return nil
				}
				return fmt.Errorf("the rebuild's quarantine drain stopped; the job stays resumable — re-run the same command: %w", runErr)
			}
			if runRes.Recovered == 0 {
				return nil
			}
			continue
		}
		if budget := opt.uploadBudget(); budget > 0 && out.uploads >= budget {
			out.stopped = fmt.Sprintf("upload budget reached (%d upload(s) this run); re-run the same command to continue the rebuild", budget)
			return errBudgetStop
		}
		runRes, runErr := syncclient.Run(ctx, store, syncclient.Options{
			ServerURL:             j.ServerURL,
			StateDir:              j.StateDir,
			HTTPClient:            client,
			AllowedResetRequestID: j.RequestID,
		})
		if runErr != nil {
			return fmt.Errorf("the rebuild's drain of a pending batch stopped; the job stays resumable — re-run the same command: %w", runErr)
		}
		out.uploads++
		out.uploadedRecords += runRes.Receipt.AcceptedRecords + runRes.Receipt.RejectedRecords
		out.accepted += runRes.Receipt.AcceptedRecords
		out.rejected += runRes.Receipt.RejectedRecords
		res.Uploads++
		res.UploadedRecords += runRes.Receipt.AcceptedRecords + runRes.Receipt.RejectedRecords
		res.AcceptedRecords += runRes.Receipt.AcceptedRecords
		res.RejectedRecords += runRes.Receipt.RejectedRecords
		if runRes.Receipt.RejectedRecords > 0 {
			return fmt.Errorf("the rebuild stopped: the server rejected %d record(s) of a derived recovery batch; those records were NOT rebuilt and the completion marker will not be sent. Fix the cause, then remove %s to abandon this incomplete task and start a new explicitly confirmed force recollection; keep the installed new-epoch state and never restore old batches", runRes.Receipt.RejectedRecords, journalPath(j.StateDir))
		}
	}
}

// errBudgetStop marks a drain stop that is a budget bound, not a failure.
var errBudgetStop = errors.New("rebuild drain reached the upload budget")

// quarantineStoreCount counts the recoverable quarantine store entries.
func quarantineStoreCount(stateDir string) (int, error) {
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// countJobRejected sums the server-rejected records across the job's
// recorded receipts.
func countJobRejected(j job) int {
	n := 0
	for _, b := range j.Batches {
		for _, u := range b.Uploads {
			n += u.RejectedRecords
		}
	}
	return n
}

// countNotDone counts the batches a resume run would still work on.
func countNotDone(j job) int {
	n := 0
	for _, b := range j.Batches {
		if b.Outcome != outcomeDone {
			n++
		}
	}
	return n
}

// countBlocked counts the deterministically blocked batches.
func countBlocked(j job) int {
	n := 0
	for _, b := range j.Batches {
		if b.Outcome == outcomeBlocked {
			n++
		}
	}
	return n
}

// auditOutboxSettled sums the rejected records across every SETTLED entry
// of the installed outbox — frozen batches, derived children of a
// live-scope reorganization, and quarantine-recovery batches alike. The
// completion gate uses it together with the journal's own receipts, so a
// rejected record anywhere in the new-epoch outbox (including a derived
// batch a later run never re-examines) can never hide behind a
// frozen-batches-only count and fake a completion.
func auditOutboxSettled(stateDir string) (int, error) {
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		return 0, err
	}
	rejected := 0
	for _, entry := range out.Batches {
		if entry.Status == outbox.StatusPending {
			continue
		}
		if entry.RejectedRecords > 0 {
			rejected += entry.RejectedRecords
		}
	}
	return rejected, nil
}

// pendingOutboxCount counts the real outbox's pending entries.
func pendingOutboxCount(stateDir string) (int, error) {
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, entry := range out.Batches {
		if entry.Status == outbox.StatusPending {
			n++
		}
	}
	return n, nil
}
