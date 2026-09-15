package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"golang.org/x/mod/sumdb/note"
)

type vector struct {
	Bundle   string `json:"bundle"`
	Policy   string `json:"policy"`
	Expected struct {
		ActiveOperationalThumbprint string `json:"active_operational_thumbprint"`
		BundleSignerKID             string `json:"bundle_signer_kid"`
		EventCount                  int    `json:"event_count"`
		Status                      string `json:"status"`
	} `json:"expected"`
	Trust struct {
		BundleVerifierKey   string `json:"bundle_verifier_key"`
		CheckpointFreshness int64  `json:"checkpoint_freshness_ms"`
		MaxBundleLifetime   int64  `json:"max_bundle_lifetime_ms"`
		Now                 int64  `json:"now"`
	} `json:"trust"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: c2spverify VECTOR")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	check(err)
	var v vector
	check(json.Unmarshal(data, &v))
	verifier, err := note.NewVerifier(v.Trust.BundleVerifierKey)
	check(err)
	verified, err := c2sptlog.VerifyStreamBundle(
		context.Background(),
		[]byte(v.Bundle),
		c2sptlog.StreamBundleTrust{
			PolicyDocument:    []byte(v.Policy),
			BundleVerifier:    verifier,
			Now:               func() time.Time { return time.Unix(v.Trust.Now, 0).UTC() },
			MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond,
			MaxCheckpointAge:  time.Duration(v.Trust.CheckpointFreshness) * time.Millisecond,
		},
	)
	check(err)
	if len(verified.Events) != v.Expected.EventCount ||
		string(verified.Snapshot.HistoricalState) != v.Expected.Status ||
		verified.Snapshot.ActiveKeyThumbprint != v.Expected.ActiveOperationalThumbprint ||
		verified.SignerKeyID != v.Expected.BundleSignerKID {
		fmt.Fprintln(os.Stderr, "verified bundle result does not match vector expectations")
		os.Exit(1)
	}
	check(json.NewEncoder(os.Stdout).Encode(map[string]any{
		"sdk":                         "go",
		"eventCount":                  len(verified.Events),
		"status":                      verified.Snapshot.HistoricalState,
		"activeOperationalThumbprint": verified.Snapshot.ActiveKeyThumbprint,
		"bundleSignerKid":             verified.SignerKeyID,
	}))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
