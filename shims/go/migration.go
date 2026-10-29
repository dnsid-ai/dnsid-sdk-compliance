package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

type migrationLog struct {
	LR, Policy, Checkpoint string
	Entries                []c2spEntry
}

type migrationCase struct {
	Domain, OperationalThumbprint string
	Logs                          []migrationLog
	Target, MaxDepth              int
	At, BeforeGenesis             int64
}

// indexedSource resolves exact final-event references, which RebuildHistoryThrough reads.
type indexedSource struct{ vectorSource }

func (s indexedSource) ReadEvent(_ context.Context, ref dnsidlog.LogRef) (c2sptlog.ProvenEntry, error) {
	_, index, err := c2sptlog.ParseFinalEventRef(ref)
	if err != nil {
		return c2sptlog.ProvenEntry{}, err
	}
	for _, entry := range s.entries {
		if entry.Index == index {
			return entry, nil
		}
	}
	return c2sptlog.ProvenEntry{}, fmt.Errorf("no fixture entry at index %d", index)
}

// handleMigrationCase wires each log's client to the others through the
// SDK's own RebuildHistoryThrough, as the probe and SDK tests do.
func handleMigrationCase(raw json.RawMessage) map[string]any {
	var req migrationCase
	if err := json.Unmarshal(raw, &req); err != nil {
		return map[string]any{"ok": false, "error": "AdapterError", "message": err.Error()}
	}
	adapterError := func(err error) map[string]any {
		return map[string]any{"ok": false, "error": "AdapterError", "message": err.Error()}
	}
	ctx := context.Background()
	now := time.Unix(req.At, 0)
	clients := map[string]*c2sptlog.Client{}
	verifier := func(ctx context.Context, event dnsidlog.LogEvent) (c2sptlog.MigrationVerificationResult, error) {
		previous := clients[event.PreviousLog]
		if previous == nil {
			return c2sptlog.MigrationVerificationResult{}, fmt.Errorf("unknown previous log %q", event.PreviousLog)
		}
		return previous.RebuildHistoryThrough(ctx, req.Domain, dnsidlog.LogRef(event.FinalEntryRef))
	}
	for i, log := range req.Logs {
		policy, err := c2sptlog.ParsePolicy([]byte(log.Policy))
		if err != nil {
			return adapterError(err)
		}
		policy.Now = func() time.Time { return now }
		policy.MaxCheckpointAge = 24 * time.Hour
		source := indexedSource{vectorSource{checkpoint: []byte(log.Checkpoint), complete: true, global: true}}
		for _, item := range log.Entries {
			entry, err := base64.RawURLEncoding.DecodeString(item.Entry)
			if err != nil {
				return adapterError(err)
			}
			proof, err := base64.RawURLEncoding.DecodeString(item.Proof)
			if err != nil {
				return adapterError(err)
			}
			source.entries = append(source.entries, c2sptlog.ProvenEntry{Index: item.Index, Entry: entry, Proof: proof})
		}
		options := []c2sptlog.Option{c2sptlog.WithSource(source), c2sptlog.WithPolicy(policy), c2sptlog.WithMigrationVerifier(verifier)}
		if i == req.Target && req.MaxDepth > 0 {
			options = append(options, c2sptlog.WithMigrationVerificationLimits(c2sptlog.MigrationVerificationLimits{MaxDepth: req.MaxDepth}))
		}
		client, err := c2sptlog.New(log.LR, options...)
		if err != nil {
			return adapterError(err)
		}
		clients[log.LR] = client
	}
	lr := req.Logs[req.Target].LR
	target := clients[lr]
	events, err := target.RebuildHistory(ctx, req.Domain)
	if err != nil {
		return lifecycleErrJSON(err)
	}
	out := map[string]any{"ok": true, "eventCount": len(events)}
	if stamp, err := target.KeyTimestamp(ctx, req.Domain, req.OperationalThumbprint); err != nil {
		out["keyTimestamp"] = "error: " + err.Error()
	} else {
		out["keyTimestamp"] = stamp.Unix()
	}
	if evidence, err := target.VerifyNonRevocation(ctx, req.Domain, now); err != nil {
		out["loggedState"] = "error: " + err.Error()
	} else {
		out["loggedState"] = string(evidence.LoggedState)
	}
	_, err = target.VerifyNonRevocation(ctx, req.Domain, time.Unix(req.BeforeGenesis, 0))
	out["beforeGenesisRejected"] = err != nil
	if cutoff, err := target.RebuildHistoryThrough(ctx, req.Domain, dnsidlog.LogRef(lr+"@0")); err != nil {
		out["cutoffEventCount"] = "error: " + err.Error()
	} else {
		out["cutoffEventCount"] = len(cutoff.PriorHistory)
	}
	return out
}
