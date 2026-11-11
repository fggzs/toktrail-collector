package resync

// frozenDataEpoch stamps a newly derived override batch from the local
// durable baseline, never from a subsequently fetched remote status. Ordinary
// archive children instead retain the epoch already stored in their parent.
func frozenDataEpoch(epoch int64) *int64 {
	if epoch == 0 {
		return nil
	}
	value := epoch
	return &value
}
