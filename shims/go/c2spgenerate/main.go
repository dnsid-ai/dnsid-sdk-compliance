package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/dnsid-ai/dnsid-sdk-compliance/shims/go/internal/logeventcompat"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type keySpec struct {
	KID      string `json:"kid"`
	SeedByte byte   `json:"ed25519_seed_byte"`
}

type eventSpec struct {
	Type          string `json:"type"`
	Timestamp     int64  `json:"timestamp"`
	Reason        string `json:"reason"`
	PreviousLog   string `json:"previous_log"`
	NewLog        string `json:"new_log"`
	FinalEntryRef string `json:"final_entry_ref"`
}

type corpus struct {
	Domain       string `json:"domain"`
	GovernanceID string `json:"governance_id"`
	LR           string `json:"lr"`
	Keys         struct {
		Entity             keySpec `json:"entity"`
		OperationalInitial keySpec `json:"operational_initial"`
		OperationalRotated keySpec `json:"operational_rotated"`
	} `json:"keys"`
	Events map[string]eventSpec `json:"events"`
}

type bundleVector struct {
	Bundle string `json:"bundle"`
	Policy string `json:"policy"`
}

type rawBundle struct {
	Checkpoint string `json:"checkpoint"`
	Events     []struct {
		Entry string `json:"entry"`
		Index uint64 `json:"index"`
		Proof string `json:"proof"`
	} `json:"events"`
}

type fixedProvider struct {
	kid     string
	key     jwk.Key
	private ed25519.PrivateKey
}

func newFixedProvider(spec keySpec) (*fixedProvider, error) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = spec.SeedByte
	}
	private := ed25519.NewKeyFromSeed(seed)
	key, err := jwk.Import(private.Public())
	if err != nil {
		return nil, err
	}
	if err := key.Set(jwk.KeyIDKey, spec.KID); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		return nil, err
	}
	return &fixedProvider{kid: spec.KID, key: key, private: private}, nil
}

func (p *fixedProvider) JWK(kid ...string) jwk.Key {
	if len(kid) > 0 && kid[0] != p.kid {
		return nil
	}
	return p.key
}

func (p *fixedProvider) ListKeyIds() []string { return []string{p.kid} }

func (p *fixedProvider) Sign(payload []byte) (*dnsid.KeySignature, error) {
	return p.SignKey(p.kid, payload)
}

func (p *fixedProvider) SignKey(kid string, payload []byte) (*dnsid.KeySignature, error) {
	if kid != p.kid {
		return nil, fmt.Errorf("unexpected kid %q", kid)
	}
	return &dnsid.KeySignature{Kid: kid, Alg: dnsid.JoseAlgEdDSA, Signature: ed25519.Sign(p.private, payload)}, nil
}

func (p *fixedProvider) GenerateKey(dnsid.JoseAlg) (string, error) {
	return "", fmt.Errorf("not implemented")
}
func (p *fixedProvider) Activate(string) error  { return fmt.Errorf("not implemented") }
func (p *fixedProvider) Supersede(string) error { return fmt.Errorf("not implemented") }
func (p *fixedProvider) Purge(string) error     { return fmt.Errorf("not implemented") }

type singleEntrySource struct{ entry c2sptlog.ProvenEntry }

func (s singleEntrySource) ReadEvent(context.Context, dnsidlog.LogRef) (c2sptlog.ProvenEntry, error) {
	return s.entry, nil
}

func (s singleEntrySource) RebuildHistory(context.Context, c2sptlog.Reference, string) ([]c2sptlog.ProvenEntry, error) {
	return []c2sptlog.ProvenEntry{s.entry}, nil
}

func thumbprint(key jwk.Key) (string, error) {
	value, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func activeStateHash(domain, entityThumb, operationalThumb string) string {
	// This is the JCS encoding of the fixed protocol state object.
	canonical := fmt.Sprintf(
		`{"entity_thumb":%q,"fqdn":%q,"operational_thumb":%q,"status":"ACTIVE"}`,
		entityThumb,
		domain,
		operationalThumb,
	)
	digest := sha256.New()
	_, _ = digest.Write([]byte("dnsid-c2sp-state-v1"))
	_, _ = digest.Write([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: c2spgenerate CORPUS GOLDEN_BUNDLE")
		os.Exit(2)
	}
	var c corpus
	readJSON(os.Args[1], &c)
	if c.Events["issuance"].Type != "ISSUANCE" || c.Events["rotation"].Type != "KEY_ROTATION" {
		fail(fmt.Errorf("corpus is missing issuance or rotation"))
	}

	entity := mustProvider(c.Keys.Entity)
	initial := mustProvider(c.Keys.OperationalInitial)
	rotated := mustProvider(c.Keys.OperationalRotated)
	entityThumb := mustThumb(entity.key)
	initialThumb := mustThumb(initial.key)
	rotatedThumb := mustThumb(rotated.key)

	client, err := c2sptlog.New(c.LR)
	check(err)
	issuanceEvent := dnsidlog.LogEvent{
		Type:         dnsidlog.LogEventIssuance,
		Domain:       c.Domain,
		GovernanceID: c.GovernanceID,
		Timestamp:    time.Unix(c.Events["issuance"].Timestamp, 0).UTC(),
	}
	logeventcompat.SetIssuance(&issuanceEvent, entity.key, entityThumb, initial.key, initialThumb)
	issuance, err := client.PrepareEvent(issuanceEvent)
	check(err)
	issuance, err = client.SignPreparedEvent(context.Background(), issuance, c2sptlog.SignerEntity, entity)
	check(err)
	issuance, err = client.SignPreparedEvent(context.Background(), issuance, c2sptlog.SignerOperationalCountersignature, initial)
	check(err)
	issuanceBytes, err := client.PreparedEntryBytes(context.Background(), issuance)
	check(err)

	var vector bundleVector
	readJSON(os.Args[2], &vector)
	var bundle rawBundle
	check(json.Unmarshal([]byte(vector.Bundle), &bundle))
	if len(bundle.Events) < 1 {
		fail(fmt.Errorf("golden bundle has no entries"))
	}
	proofHash, err := base64.RawURLEncoding.DecodeString(bundle.Events[0].Proof)
	check(err)
	checkpoint, err := base64.RawURLEncoding.DecodeString(bundle.Checkpoint)
	check(err)
	proof := []byte(fmt.Sprintf(
		"c2sp.org/tlog-proof@v1\nindex %d\n%s\n\n%s",
		bundle.Events[0].Index,
		base64.StdEncoding.EncodeToString(proofHash),
		checkpoint,
	))
	policy, err := c2sptlog.ParsePolicy([]byte(vector.Policy))
	check(err)
	source := singleEntrySource{entry: c2sptlog.ProvenEntry{
		Index: bundle.Events[0].Index,
		Entry: issuanceBytes,
		Proof: proof,
	}}
	client, err = c2sptlog.New(c.LR, c2sptlog.WithSource(source), c2sptlog.WithPolicy(policy))
	check(err)

	chain := c2sptlog.Chain{
		Sequence:          1,
		PreviousEventID:   issuance.EventID(),
		PreviousStateHash: activeStateHash(c.Domain, entityThumb, initialThumb),
	}
	rotationEvent := dnsidlog.LogEvent{
		Type:      dnsidlog.LogEventKeyRotation,
		Domain:    c.Domain,
		Timestamp: time.Unix(c.Events["rotation"].Timestamp, 0).UTC(),
	}
	logeventcompat.SetRotation(&rotationEvent, initial.kid, initialThumb, rotated.kid, rotated.key, rotatedThumb)
	rotation, err := client.PrepareEventWithChain(rotationEvent, chain)
	check(err)
	rotation, err = client.SignPreparedEvent(context.Background(), rotation, c2sptlog.SignerPreviousOperational, initial)
	check(err)
	rotation, err = client.SignPreparedEvent(context.Background(), rotation, c2sptlog.SignerNewOperational, rotated)
	check(err)
	rotationBytes, err := client.PreparedEntryBytes(context.Background(), rotation)
	check(err)
	entries := map[string]string{
		"issuance": base64.RawURLEncoding.EncodeToString(issuanceBytes),
		"rotation": base64.RawURLEncoding.EncodeToString(rotationBytes),
	}
	check(json.NewEncoder(os.Stdout).Encode(map[string]any{
		"sdk":     "go",
		"entries": entries,
	}))
}

func readJSON(path string, target any) {
	data, err := os.ReadFile(path)
	check(err)
	check(json.Unmarshal(data, target))
}

func mustProvider(spec keySpec) *fixedProvider {
	provider, err := newFixedProvider(spec)
	check(err)
	return provider
}

func mustThumb(key jwk.Key) string {
	value, err := thumbprint(key)
	check(err)
	return value
}

func check(err error) {
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
