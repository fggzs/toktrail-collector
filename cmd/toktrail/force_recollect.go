package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"toktrail-collector/internal/app/recollect"
	"toktrail-collector/internal/source/registry"
)

// The browser only supplies a guarded command. All destructive confirmation
// occurs here on the device whose original source files will be read.
func runForceRecollectWithIO(stateDir, serverURL, expectedDevice string, dryRun, yes bool, maxBatches int, verbose bool, input io.Reader, out io.Writer) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	printPlan := func(plan recollect.Plan) {
		if plan.Resumed {
			fmt.Fprintln(out, "force recollection: resume the existing reset; history will not be cleared again")
		} else {
			fmt.Fprintln(out, "force recollection: rebuild this device from current source data")
		}
		fmt.Fprintf(out, "device data epoch: %d -> %d\n", plan.OldDataEpoch, plan.NextDataEpoch)
		fmt.Fprintf(out, "previous server records: %d; current authorized scan: %d records in %d batches\n", plan.RemoteRecordCount, plan.PlannedRecords, len(plan.Batches))
		if len(plan.AllowedTools) == 0 {
			fmt.Fprintln(out, "authorization: all locally permitted tools")
		} else {
			fmt.Fprintf(out, "authorization: %d tool(s); only enabled local grants are read\n", len(plan.AllowedTools))
		}
		if plan.HistoryFrom == nil {
			fmt.Fprintln(out, "history authorization: all available local history")
		} else {
			fmt.Fprintf(out, "history authorization: from %s\n", plan.HistoryFrom.UTC().Format("2006-01-02T15:04:05Z"))
		}
		if plan.UploadUntil != nil {
			fmt.Fprintf(out, "upload boundary: before %s\n", plan.UploadUntil.UTC().Format("2006-01-02T15:04:05Z"))
		}
		for _, grant := range plan.Grants {
			label := "unknown source"
			if _, known := registry.Lookup(grant.Source); known {
				label = grant.Source
			}
			fmt.Fprintf(out, "  %s: %d record(s), diagnostics=%d, outsideScope=%d\n", label, grant.Records, grant.Issues, grant.OutOfScope)
		}
		if len(plan.ExcludedNotAllowed)+len(plan.ExcludedDisabled) > 0 {
			fmt.Fprintf(out, "excluded grants: disabled=%d notAllowed=%d (their previous server history is cleared)\n", len(plan.ExcludedDisabled), len(plan.ExcludedNotAllowed))
		}
		fmt.Fprintln(out, "WARNING: all previous ordinary usage for THIS device will be cleared, including records outside current authorization. Unreadable or deleted source history cannot be recovered. Rankings may temporarily decrease. Device identity and Cursor account history are preserved.")
		if dryRun {
			fmt.Fprintln(out, "dry-run: server authorization/plan and local sources were read; no reset or upload was performed")
		}
	}
	result, err := recollect.Run(ctx, recollect.Options{
		StateDir: stateDir, ServerURL: serverURL, ExpectedDeviceID: expectedDevice,
		DryRun: dryRun, MaxBatches: maxBatches,
		Confirm: func(plan recollect.Plan) error {
			printPlan(plan)
			if yes {
				return nil
			}
			return promptYesNo(input, out, "Clear previous ordinary device usage and recollect under current authorization?")
		},
		Progress: func(event recollect.ProgressEvent) {
			if verbose {
				fmt.Fprintf(out, "recollection upload: accepted=%d rejected=%d replay=%t\n", event.Accepted, event.Rejected, event.Replay)
			}
		},
	})
	if dryRun && err == nil {
		printPlan(result.Plan)
		return nil
	}
	if err != nil {
		if isResyncConfirmAbort(err) {
			return safeDisplayError(err, confirmAbortDisplayText(err))
		}
		if result.RejectedRecords > 0 || result.Stopped == "records rejected" {
			fmt.Fprintln(out, "Some rebuilt records were rejected. Retrying settled batches cannot correct them. After fixing the cause, remove only force-recollect.json from this device's state directory to abandon the incomplete task, then confirm a new force recollection. Keep the installed new-epoch state and isolated archives; never restore old batches.")
		} else {
			fmt.Fprintln(out, "force recollection stopped; review the run state before retrying the same command")
		}
		return safeDisplayError(err, "force recollection did not complete (details withheld; review the configuration and run state before continuing)")
	}
	if result.Completed {
		fmt.Fprintf(out, "force recollection complete on server: accepted=%d; website projection updates asynchronously\n", result.AcceptedRecords)
		return nil
	}
	fmt.Fprintf(out, "force recollection incomplete: %d batch(es) remaining; run the same command to resume without clearing history again\n", result.Remaining)
	return safeDisplayError(fmt.Errorf("force recollection incomplete"), "force recollection incomplete; resume the same command")
}
