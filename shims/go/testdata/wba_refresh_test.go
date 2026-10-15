package dnsid

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Uses the SDK's native core fixture; never substitutes a resolver verdict.
func TestComplianceWBARefreshRevocation(t *testing.T) {
	const domain = "agent.example.com"
	f := newCoalescingFixture(t, []string{domain}, nil)
	f.manager.verification.StatusCheckInterval = time.Minute
	if _, err := f.manager.VerifyDomain(context.Background(), domain); err != nil {
		t.Fatal(err)
	}
	f.https.responses[f.records[domain].StatusURI] = json.RawMessage(
		`{"state":"REVOKED","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","revocationReason":"keyCompromise"}`,
	)
	if _, err := f.manager.RefreshDomain(context.Background(), domain, VerifyDomainOpts{}); err == nil {
		t.Fatal("refresh accepted a revoked identity")
	} else if verificationErr, ok := err.(*VerificationError); !ok || verificationErr.Code() != VerificationCodeStatusNotActive {
		t.Fatalf("expected confirmed revocation, got %v", err)
	}
	if vd, err := f.manager.VerifyDomain(context.Background(), domain); err == nil {
		t.Fatalf("accepted cached %s after learning revocation", vd.Status().State)
	}
}
