package syncclient

import (
	"fmt"
)

// epochValue normalizes a wire data epoch onto its integer value. A nil
// DataEpoch means a legacy server or a legacy pre-epoch batch: both are
// epoch 0, tolerated only while the locally locked device epoch is also
// 0.
func epochValue(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// CheckSelfDataEpoch validates a device self snapshot's data epoch
// against the locally locked device epoch. It is the shared fence behind
// the upload preflight, the tool-status preflight and the collection
// round's pre-scan gate, so every ordinary flow stops on the same
// condition: the server's epoch for this device differs from the local
// one (in either direction), the server stopped reporting an epoch the
// local state already advanced past, or the server reported a negative
// (invalid) epoch.
//
// A mismatch is the deliberate blocked state after a server-side usage
// reset the local device has not been force-recollected through: the
// local epoch never auto-advances from a self snapshot, so old outbox
// batches can never be relabeled with the new epoch. Only the
// force-recollect flow (initial bind or its journal transition) moves
// the local epoch.
//
// Legacy compatibility: a nil DataEpoch (old server) passes while the
// local epoch is 0, and any epoch passes while nothing was ever bound
// locally (stateEpoch 0 with a nil snapshot epoch is the pre-feature
// steady state).
func CheckSelfDataEpoch(self SelfStatus, stateEpoch int64) error {
	if self.DataEpoch != nil && *self.DataEpoch < 0 {
		return fmt.Errorf("%w: the server reported an invalid negative data epoch for this device; refusing to send or read under it", ErrEpochStale)
	}
	selfEpoch := epochValue(self.DataEpoch)
	if self.DataEpoch == nil && stateEpoch != 0 {
		return fmt.Errorf("%w: the server did not report a data epoch but the local device is at epoch %d; the device needs a force-recollect before anything is sent", ErrEpochStale, stateEpoch)
	}
	if selfEpoch != stateEpoch {
		return fmt.Errorf("%w: the server reports data epoch %d for this device but the local device is locked at epoch %d; the device needs a force-recollect before anything is sent", ErrEpochStale, selfEpoch, stateEpoch)
	}
	return nil
}

// checkBatchDataEpoch validates a batch's durable payload epoch against
// the locally locked device epoch before any attempt accounting, scope
// gate or HTTP traffic:
//
//   - state epoch > 0: the batch MUST carry a dataEpoch stamp equal to
//     the local epoch. A missing stamp (a pre-epoch legacy batch) or a
//     different epoch is stale data from before the reset — it stays
//     pending and is never relabeled.
//
//   - state epoch 0 (legacy or never reset): an unstamped batch and a
//     batch stamped 0 pass (the pre-feature steady state); a batch
//     stamped with a newer epoch is refused — a local device that has
//     not transitioned cannot vouch for post-reset data either.
func checkBatchDataEpoch(batch BatchRequest, stateEpoch int64) error {
	if stateEpoch == 0 {
		if batch.DataEpoch == nil || *batch.DataEpoch == 0 {
			return nil
		}
		return fmt.Errorf("%w: batch %s carries data epoch %d but the local device is still at epoch 0; the batch stays pending and was not uploaded", ErrEpochStale, batch.BatchID, *batch.DataEpoch)
	}
	if batch.DataEpoch == nil {
		return fmt.Errorf("%w: batch %s has no data epoch stamp but the local device is at epoch %d; the batch stays pending and was not uploaded (a legacy batch cannot be relabeled automatically)", ErrEpochStale, batch.BatchID, stateEpoch)
	}
	if *batch.DataEpoch != stateEpoch {
		return fmt.Errorf("%w: batch %s carries data epoch %d but the local device is at epoch %d; the batch stays pending and was not uploaded", ErrEpochStale, batch.BatchID, *batch.DataEpoch, stateEpoch)
	}
	return nil
}
