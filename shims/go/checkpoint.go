package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

type checkpointEvidence struct {
	Checkpoint string
	Entries    []c2spEntry
}

type checkpointCase struct {
	Policy, LR, Domain, Mode, Fault string
	Trusted                         *checkpointEvidence
	Candidate                       checkpointEvidence
	ScanEntries                     []c2spEntry
	Proof                           []string
}

type checkpointFaultStore struct {
	c2sptlog.TrustedC2spCheckpointStore
	fault *string
	cause error
}

func (s checkpointFaultStore) Load(origin string) (*c2sptlog.TrustedC2spCheckpoint, error) {
	if *s.fault == "load" {
		return nil, s.cause
	}
	return s.TrustedC2spCheckpointStore.Load(origin)
}
func (s checkpointFaultStore) CompareAndSwap(origin string, old *c2sptlog.TrustedC2spCheckpoint, next c2sptlog.TrustedC2spCheckpoint) (bool, error) {
	if *s.fault == "write" {
		return false, s.cause
	}
	return s.TrustedC2spCheckpointStore.CompareAndSwap(origin, old, next)
}

type checkpointScanSource struct {
	vectorSource
	scan [][]byte
}

func (s checkpointScanSource) FetchEntriesThrough(context.Context, c2sptlog.Reference, uint64) ([][]byte, error) {
	return s.scan, nil
}

type checkpointFetchFailure struct{ cause error }

func (e checkpointFetchFailure) Error() string   { return "injected fetch failure" }
func (e checkpointFetchFailure) Unwrap() error   { return e.cause }
func (e checkpointFetchFailure) Transient() bool { return true }

type checkpointProofSource struct {
	checkpointScanSource
	proof    [][]byte
	requests *int
	fault    string
	cause    error
}

func (s checkpointProofSource) FetchConsistencyProof(context.Context, c2sptlog.Reference, uint64, uint64) ([][]byte, error) {
	*s.requests += 1
	if s.fault == "proof-fetch" {
		return nil, checkpointFetchFailure{s.cause}
	}
	return s.proof, nil
}

func verifyCheckpointCase(req checkpointCase) map[string]any {
	adapterError := func(err error) map[string]any {
		return map[string]any{"ok": false, "error": "AdapterError", "message": err.Error()}
	}
	if req.Mode != "scan" && req.Mode != "proof" && req.Mode != "missing" {
		return adapterError(fmt.Errorf("unknown checkpoint mode"))
	}
	if req.Fault != "" && req.Fault != "load" && req.Fault != "write" && req.Fault != "proof-fetch" {
		return adapterError(fmt.Errorf("unknown checkpoint fault"))
	}
	policy, err := c2sptlog.ParsePolicy([]byte(req.Policy))
	if err != nil {
		return adapterError(err)
	}
	ref, err := c2sptlog.ParseReference(req.LR)
	if err != nil {
		return adapterError(err)
	}
	origin, err := ref.Origin()
	if err != nil {
		return adapterError(err)
	}
	base := c2sptlog.NewMemoryTrustedC2spCheckpointStore()
	fault := ""
	cause := errors.New("injected checkpoint dependency failure")
	store := checkpointFaultStore{base, &fault, cause}
	proofRequests := 0
	verify := func(evidence checkpointEvidence, mode string, scan []c2spEntry) error {
		source := vectorSource{checkpoint: []byte(evidence.Checkpoint), complete: true, global: true}
		for _, item := range evidence.Entries {
			entry, err := base64.RawURLEncoding.DecodeString(item.Entry)
			if err != nil {
				return err
			}
			proof, err := base64.RawURLEncoding.DecodeString(item.Proof)
			if err != nil {
				return err
			}
			source.entries = append(source.entries, c2sptlog.ProvenEntry{Index: item.Index, Entry: entry, Proof: proof})
		}
		full := checkpointScanSource{vectorSource: source}
		for _, item := range scan {
			entry, err := base64.RawURLEncoding.DecodeString(item.Entry)
			if err != nil {
				return err
			}
			full.scan = append(full.scan, entry)
		}
		var selected c2sptlog.Source = full
		if mode == "missing" {
			selected = source
		} else if mode == "proof" {
			proofSource := checkpointProofSource{checkpointScanSource: full, requests: &proofRequests, fault: fault, cause: cause}
			for _, node := range req.Proof {
				decoded, err := base64.RawURLEncoding.DecodeString(node)
				if err != nil {
					return err
				}
				proofSource.proof = append(proofSource.proof, decoded)
			}
			selected = proofSource
		}
		client, err := c2sptlog.New(req.LR, c2sptlog.WithSource(selected), c2sptlog.WithPolicy(policy), c2sptlog.WithTrustedCheckpointStore(store))
		if err != nil {
			return err
		}
		_, err = client.RebuildHistory(context.Background(), req.Domain)
		return err
	}
	if req.Trusted != nil {
		if err := verify(*req.Trusted, "scan", req.Trusted.Entries); err != nil {
			return adapterError(fmt.Errorf("trusted seed failed: %w", err))
		}
	}
	fault = req.Fault
	out := map[string]any{"ok": true}
	if err := verify(req.Candidate, req.Mode, req.ScanEntries); err != nil {
		out = map[string]any{"ok": false, "error": "CheckpointError", "message": err.Error(), "causePreserved": errors.Is(err, cause)}
		var root *dnsid.VerificationError
		var logErr *dnsidlog.VerificationError
		var continuity *c2sptlog.CheckpointAdvanceError
		if errors.As(err, &root) {
			out["errorCategory"] = string(root.Code())
		} else if errors.As(err, &logErr) {
			out["errorCategory"] = logErr.Code()
		} else if !errors.Is(err, cause) {
			out["error"] = "AdapterError"
		}
		var classified interface{ Transient() bool }
		if errors.As(err, &classified) {
			out["transient"] = classified.Transient()
		}
		if errors.As(err, &continuity) {
			categories := map[c2sptlog.CheckpointAdvanceErrorKind]string{
				c2sptlog.CheckpointAdvanceRollback: "LOG_ROLLBACK", c2sptlog.CheckpointAdvanceRootConflict: "LOG_FORK",
				c2sptlog.CheckpointAdvanceConsistencyFailed: "LOG_INCONSISTENT",
			}
			if category, ok := categories[continuity.Kind]; ok {
				out["errorCategory"] = category
				out["diagnostics"] = map[string]any{
					"origin": continuity.Origin, "trustedTreeSize": continuity.OldTreeSize, "observedTreeSize": continuity.NewTreeSize,
					"trustedRootHash":  base64.RawURLEncoding.EncodeToString(continuity.OldRootHash),
					"observedRootHash": base64.RawURLEncoding.EncodeToString(continuity.NewRootHash),
				}
				clear(continuity.OldRootHash)
				clear(continuity.NewRootHash)
			} else if continuity.Kind == c2sptlog.CheckpointAdvanceConsistencyUnavailable {
				out["condition"] = "consistency_unavailable"
			}
		}
	}
	stored, err := base.Load(origin)
	if err != nil {
		return adapterError(err)
	}
	out["stored"] = nil
	if stored != nil {
		out["stored"] = map[string]any{"origin": stored.Origin, "treeSize": stored.TreeSize,
			"rootHash": base64.RawURLEncoding.EncodeToString(stored.RootHash), "witnessTime": stored.WitnessTime.Unix()}
	}
	out["proofRequests"] = proofRequests
	out["proofRequested"] = proofRequests > 0
	return out
}

// Keep malformed adapter input separate from native verification rejections.
func handleCheckpointCase(raw json.RawMessage) map[string]any {
	var req checkpointCase
	if err := json.Unmarshal(raw, &req); err != nil {
		return map[string]any{"ok": false, "error": "AdapterError", "message": err.Error()}
	}
	return verifyCheckpointCase(req)
}
