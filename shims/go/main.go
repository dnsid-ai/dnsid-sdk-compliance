// Command dnsid-compliance-shim exposes the dnsid-go TXT record surface to the
// cross-SDK compliance harness. It reads a JSON array of requests on stdin and
// writes a JSON array of normalized results on stdout (see compliance-tests/README.md).
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/dnsid-ai/dnsid-sdk-compliance/shims/go/internal/logeventcompat"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type semanticEvent struct {
	Type, Domain, GovernanceID, InitialEntityPublicKey, InitialEntityThumbprint      string
	InitialOperationalPublicKey, InitialOperationalThumbprint                        string
	PreviousOperationalThumbprint, NewOperationalPublicKey, NewOperationalThumbprint string
	Reason, PreviousLog, NewLog, FinalEntryRef, Delegatee, Scope, Expiry, Timestamp  string
}

type c2spEntry struct {
	Index                  uint64 `json:"index"`
	Entry, Proof, EffectID string
}

type httpFixtureRequest struct {
	Method, URL string
	Headers     map[string]string
}

type txtRecordConfig struct {
	Domain, GovernanceID, LogRef, StatusURL, EKURL, KUURL   string
	PublishProfile, PolicyFlags, MaxKeyAge, CapabilitiesURL string
}

type fixtureKey struct {
	Kid, Seed, X string
}

type request struct {
	Op                                            string          `json:"op"`
	Raw                                           string          `json:"raw"`
	IdentityFQDN                                  string          `json:"identity_fqdn"`
	Name                                          string          `json:"name"` // for normalize_fqdn
	JWK                                           json.RawMessage `json:"jwk"`
	JWKS                                          json.RawMessage `json:"jwks"`
	Kid                                           string          `json:"kid"`
	Domain, Operation, At, LR, Policy, Checkpoint string
	Events                                        []semanticEvent
	Entries                                       []c2spEntry
	CheckpointAccepted, CompleteThroughCheckpoint bool
	EntityJWK, OperationalJWK                     json.RawMessage
	PriorHistoryVerified                          *bool
	PriorAppliedEffectIDs                         []string
	CheckpointIntegrationTimeMs                   int64
	Status                                        json.RawMessage    `json:"status"`
	Request                                       httpFixtureRequest `json:"request"`
	SignatureInput                                string             `json:"signature_input"`
	Label                                         string             `json:"label"`
	Config                                        txtRecordConfig    `json:"config"`
	EntityKey                                     fixtureKey         `json:"entityKey"`
	OperationalKey                                fixtureKey         `json:"operationalKey"`
	SameKey                                       bool               `json:"sameKey"`
}

type fixtureKeyProvider struct {
	key           jwk.Key
	kid           string
	private       ed25519.PrivateKey
	signedPayload []byte
	signCalls     int
}

func newFixtureKeyProvider(fixture fixtureKey) (*fixtureKeyProvider, error) {
	seed, err := base64.RawURLEncoding.DecodeString(fixture.Seed)
	if err != nil {
		return nil, err
	}
	private := ed25519.NewKeyFromSeed(seed)
	key, err := jwk.Import(private.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	for name, value := range map[string]any{
		jwk.KeyIDKey: fixture.Kid, jwk.AlgorithmKey: "EdDSA", jwk.KeyUsageKey: "sig",
	} {
		if err := key.Set(name, value); err != nil {
			return nil, err
		}
	}
	return &fixtureKeyProvider{key: key, kid: fixture.Kid, private: private}, nil
}

func (p *fixtureKeyProvider) JWK(...string) jwk.Key { return p.key }
func (p *fixtureKeyProvider) ListKeyIds() []string  { return []string{p.kid} }
func (p *fixtureKeyProvider) Sign(payload []byte) (*dnsid.KeySignature, error) {
	p.signCalls++
	p.signedPayload = append([]byte(nil), payload...)
	return &dnsid.KeySignature{Kid: p.kid, Alg: dnsid.JoseAlgEdDSA, Signature: ed25519.Sign(p.private, payload)}, nil
}
func (p *fixtureKeyProvider) SignKey(_ string, payload []byte) (*dnsid.KeySignature, error) {
	return p.Sign(payload)
}
func (*fixtureKeyProvider) GenerateKey(dnsid.JoseAlg) (string, error) {
	return "", errors.New("not implemented")
}
func (*fixtureKeyProvider) Activate(string) error  { return errors.New("not implemented") }
func (*fixtureKeyProvider) Supersede(string) error { return errors.New("not implemented") }
func (*fixtureKeyProvider) Purge(string) error     { return errors.New("not implemented") }

func optional(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func recordJSON(r *dnsid.TXTRecord) map[string]any {
	var fl any
	if r.Flags != nil {
		fl = strings.Join(r.Flags, ",")
	}
	unknown := r.UnknownTags
	if unknown == nil {
		unknown = map[string]string{}
	}
	return map[string]any{
		"v":       r.Version,
		"gi":      optional(r.GovernanceID),
		"oi":      nil,
		"ek":      optional(r.EntityKeyURI),
		"ku":      optional(r.KeyURI),
		"lr":      optional(r.LogRef),
		"su":      optional(r.StatusURI),
		"sg":      optional(r.Signature),
		"fl":      fl,
		"ka":      optional(r.KeyAge),
		"cu":      optional(r.Capabilities),
		"unknown": unknown,
	}
}

func errJSON(err error) map[string]any {
	kind := "Error"
	var pe *dnsid.ParseError
	var ve *dnsid.ValidationError
	var ae *dnsid.ArgumentError
	switch {
	case errors.As(err, &pe):
		kind = "ParseError"
	case errors.As(err, &ve):
		kind = "ValidationError"
	case errors.As(err, &ae):
		kind = "ArgumentError"
	}
	return map[string]any{"ok": false, "error": kind, "message": err.Error()}
}

func parseJWKS(raw json.RawMessage) (*dnsid.JWKS, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("missing jwks")
	}
	return dnsid.ParseJWKS(raw)
}

func parseJWK(raw json.RawMessage) (*dnsid.JWK, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("missing jwk")
	}
	doc, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: []json.RawMessage{raw}})
	if err != nil {
		return nil, err
	}
	set, err := dnsid.ParseJWKS(doc)
	if err != nil {
		return nil, err
	}
	keys := set.SigningKeys()
	if len(keys) != 1 {
		return nil, fmt.Errorf("JWK is not a supported signing key")
	}
	return keys[0], nil
}

func handleCreateTXTRecord(req request) map[string]any {
	operationalFixture := req.OperationalKey
	if req.SameKey {
		operationalFixture = req.EntityKey
	}
	operational, err := newFixtureKeyProvider(operationalFixture)
	if err != nil {
		return errJSON(err)
	}
	var entity *fixtureKeyProvider
	if req.EntityKey.Seed != "" {
		entity, err = newFixtureKeyProvider(req.EntityKey)
		if err != nil {
			return errJSON(err)
		}
	}
	flags := []dnsid.PolicyFlag{}
	for _, flag := range strings.Split(req.Config.PolicyFlags, ",") {
		if flag != "" {
			flags = append(flags, dnsid.PolicyFlag(flag))
		}
	}
	options := []dnsid.IdentityManagerOption{}
	if entity != nil {
		options = append(options, dnsid.WithEntityKeyProvider(entity))
	}
	manager, err := newLocalIdentityManager(req.Config, flags, operational, options)
	if err != nil {
		return errJSON(err)
	}
	record, err := manager.CreateTXTRecord()
	if err != nil {
		return errJSON(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(record.Signature)
	if err != nil {
		return errJSON(err)
	}
	entityValid := ed25519.Verify(entity.private.Public().(ed25519.PublicKey), entity.signedPayload, signature)
	operationalValid := ed25519.Verify(operational.private.Public().(ed25519.PublicKey), entity.signedPayload, signature)
	source := "other"
	if entity.signCalls == 1 && operational.signCalls == 0 {
		source = "entity"
	}
	return map[string]any{
		"ok": true, "record": recordJSON(record), "signedPayload": string(entity.signedPayload),
		"signatureSource": source, "signatureVerified": entityValid && !operationalValid,
	}
}

func handle(req request) map[string]any {
	switch req.Op {
	case "sdk_conformance":
		metadata := dnsid.SDKConformance()
		metadata.VerificationProfiles["changed"] = "changed"
		metadata.LogBindings["changed"] = "changed"
		current := dnsid.SDKConformance()
		return map[string]any{
			"ok": true, "publishProfile": current.PublishProfile,
			"verificationProfiles": current.VerificationProfiles,
			"specificationStatus":  current.SpecificationStatus,
			"logBindings":          current.LogBindings, "knownDeviations": current.KnownDeviations,
			"immutable": current.VerificationProfiles["changed"] == "" && current.LogBindings["changed"] == "",
		}
	case "create_txt_record":
		return handleCreateTXTRecord(req)
	case "http_signature_base":
		msg, err := http.NewRequest(req.Request.Method, req.Request.URL, nil)
		if err == nil {
			for name, value := range req.Request.Headers {
				msg.Header.Set(name, value)
			}
			var inputs map[string]httpsig.SignatureParams
			inputs, err = httpsig.ParseSignatureInput(req.SignatureInput)
			if err == nil {
				params, ok := inputs[req.Label]
				if !ok {
					err = fmt.Errorf("signature label %q not found", req.Label)
				} else {
					var base string
					base, err = httpsig.BuildSignatureInput(msg, params)
					if err == nil {
						return map[string]any{"ok": true, "value": base}
					}
				}
			}
		}
		return map[string]any{"ok": false, "error": "ConformanceError", "message": err.Error()}
	case "lifecycle_vector":
		return handleLifecycleVector(req)
	case "c2sp_lifecycle_vector":
		return handleC2spLifecycleVector(req)
	case "c2sp_managed_trust_select":
		registry, err := c2sptlog.NewDnsidManagedVerificationRegistry(context.Background(), c2sptlog.DnsidManagedVerificationConfig{})
		if err == nil {
			var reader dnsidlog.LogReader
			reader, err = registry.NewReader(req.LR)
			if err == nil {
				if _, ok := reader.(*c2sptlog.Client); !ok {
					err = fmt.Errorf("managed trust selector was not accepted")
				}
			}
		}
		if err != nil {
			return map[string]any{"ok": false, "error": "ConformanceError", "message": err.Error()}
		}
		return map[string]any{"ok": true, "trustMode": "trust-profile"}
	case "agent_status_evaluate":
		var status dnsid.AgentStatus
		if err := json.Unmarshal(req.Status, &status); err != nil {
			return errJSON(dnsid.NewValidationError("dnsid: invalid lastTransitionAt", err))
		}
		if err := status.Validate(); err != nil {
			return errJSON(err)
		}
		return map[string]any{"ok": true, "state": status.State, "verificationAccepted": string(status.State) == string(dnsid.AgentStateActive)}
	case "parse":
		r, err := dnsid.ParseTXTRecord(req.Raw)
		if err != nil {
			return errJSON(err)
		}
		return map[string]any{"ok": true, "record": recordJSON(r)}
	case "canonical":
		r, err := dnsid.ParseTXTRecord(req.Raw)
		if err != nil {
			return errJSON(err)
		}
		return map[string]any{"ok": true, "value": r.Canonical()}
	case "roundtrip":
		r, err := dnsid.ParseTXTRecord(req.Raw)
		if err != nil {
			return errJSON(err)
		}
		serialized, err := r.MarshalTXT()
		if err != nil {
			return errJSON(err)
		}
		r2, err := dnsid.ParseTXTRecord(serialized)
		if err != nil {
			return map[string]any{"ok": false, "error": "RoundTripError", "message": "reparse failed: " + err.Error()}
		}
		return map[string]any{"ok": true, "record": recordJSON(r2), "value": serialized}
	case "validate":
		r, err := dnsid.ParseTXTRecord(req.Raw)
		if err != nil {
			return errJSON(err)
		}
		if err := r.Validate(req.IdentityFQDN); err != nil {
			return errJSON(err)
		}
		return map[string]any{"ok": true, "record": recordJSON(r)}
	case "normalize_fqdn":
		out, err := dnsid.NormalizeFQDN(req.Name)
		if err != nil {
			return errJSON(err)
		}
		return map[string]any{"ok": true, "value": out}
	case "jwk_thumbprint":
		key, err := parseJWK(req.JWK)
		if err != nil {
			return errJSON(err)
		}
		out, err := key.Thumbprint()
		if err != nil {
			return errJSON(err)
		}
		return map[string]any{"ok": true, "value": out}
	case "jwk_signature_alg":
		key, err := parseJWK(req.JWK)
		if err != nil {
			return errJSON(err)
		}
		alg := key.Alg()
		if alg == "" {
			return errJSON(fmt.Errorf("JWK has no supported signature algorithm"))
		}
		return map[string]any{"ok": true, "value": alg}
	case "jwks_validate":
		set, err := parseJWKS(req.JWKS)
		if err != nil {
			return errJSON(err)
		}
		if err := set.Validate(); err != nil {
			return errJSON(err)
		}
		return map[string]any{"ok": true}
	case "jwks_signing_keys":
		set, err := parseJWKS(req.JWKS)
		if err != nil {
			return errJSON(err)
		}
		keys := set.SigningKeys()
		kids := make([]string, len(keys))
		for i, key := range keys {
			kids[i] = key.Kid()
		}
		return map[string]any{"ok": true, "value": kids}
	case "jwks_key_by_id":
		set, err := parseJWKS(req.JWKS)
		if err != nil {
			return errJSON(err)
		}
		key := set.KeyByID(req.Kid)
		if key == nil {
			return map[string]any{"ok": true, "value": nil}
		}
		return map[string]any{"ok": true, "value": key.Kid()}
	default:
		return map[string]any{"ok": false, "error": "ShimError", "message": "unknown op: " + req.Op}
	}
}

func handleLifecycleVector(req request) map[string]any {
	keys := map[string]jwk.Key{}
	reverse := map[string]string{}
	key := func(ref string) jwk.Key {
		if ref == "" {
			return nil
		}
		label := strings.TrimPrefix(ref, "jwk:")
		if keys[label] == nil {
			value := dnsid.GenerateEd25519KeyProvider().JWK()
			keys[label] = value
			thumb := keyThumbprint(value)
			reverse[thumb] = label
		}
		return keys[label]
	}
	var events []dnsidlog.LogEvent
	for _, raw := range req.Events {
		timestamp, _ := time.Parse(time.RFC3339, raw.Timestamp)
		event := dnsidlog.LogEvent{Type: dnsidlog.LogEventType(raw.Type), Domain: raw.Domain, GovernanceID: raw.GovernanceID, Timestamp: timestamp, Reason: raw.Reason, PreviousLog: raw.PreviousLog, NewLog: raw.NewLog, FinalEntryRef: raw.FinalEntryRef, Delegatee: raw.Delegatee, Scope: raw.Scope}
		switch dnsidlog.LogEventType(raw.Type) {
		case dnsidlog.LogEventIssuance:
			var entityThumbprint, operationalThumbprint string
			if raw.InitialEntityThumbprint != "" {
				entityThumbprint = keyThumbprint(key("jwk:" + raw.InitialEntityThumbprint))
			}
			if raw.InitialOperationalThumbprint != "" {
				operationalThumbprint = keyThumbprint(key("jwk:" + raw.InitialOperationalThumbprint))
			}
			logeventcompat.SetIssuance(&event, key(raw.InitialEntityPublicKey), entityThumbprint, key(raw.InitialOperationalPublicKey), operationalThumbprint)
		case dnsidlog.LogEventKeyRotation:
			var previousThumbprint, newThumbprint string
			if raw.PreviousOperationalThumbprint != "" {
				previousThumbprint = keyThumbprint(key("jwk:" + raw.PreviousOperationalThumbprint))
			}
			if raw.NewOperationalThumbprint != "" {
				newThumbprint = keyThumbprint(key("jwk:" + raw.NewOperationalThumbprint))
			}
			logeventcompat.SetRotation(&event, "", previousThumbprint, "", key(raw.NewOperationalPublicKey), newThumbprint)
		}
		events = append(events, event)
	}
	at := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	if req.At != "" {
		at, _ = time.Parse(time.RFC3339, req.At)
	}
	snapshot, err := dnsidlog.NewDomainLog(req.Domain, events).SnapshotAt(at)
	if err != nil {
		return lifecycleErrJSON(err)
	}
	return map[string]any{"ok": true, "identityState": snapshot.HistoricalState, "activeOperationalThumbprint": reverse[snapshot.ActiveKeyThumbprint], "eventCount": len(snapshot.Events), "inheritedEventCount": 0, "governanceId": snapshot.GovernanceID, "keyBoundAt": snapshot.KeyBoundAt.Unix()}
}

func verifyNonRevocation(client *c2sptlog.Client, domain string, at time.Time) error {
	results := reflect.ValueOf(client).MethodByName("VerifyNonRevocation").Call([]reflect.Value{
		reflect.ValueOf(context.Background()), reflect.ValueOf(domain), reflect.ValueOf(at),
	})
	if result := results[len(results)-1]; !result.IsNil() {
		return result.Interface().(error)
	}
	return nil
}

func keyThumbprint(key jwk.Key) string {
	value, _ := key.Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(value)
}

var eventIndexRE = regexp.MustCompile(`event ([0-9]+):`)

func lifecycleErrJSON(err error) map[string]any {
	out := map[string]any{"ok": false, "error": "LifecycleError", "message": err.Error()}
	var rootErr *dnsid.VerificationError
	var logErr *dnsidlog.VerificationError
	if errors.As(err, &rootErr) {
		out["errorCategory"] = string(rootErr.Code())
	} else if errors.As(err, &logErr) {
		out["errorCategory"] = logErr.Code()
	}
	if match := eventIndexRE.FindStringSubmatch(err.Error()); len(match) == 2 {
		var index int
		_, _ = fmt.Sscanf(match[1], "%d", &index)
		out["failingEventIndex"] = index
	}
	return out
}

type vectorSource struct {
	entries    []c2sptlog.ProvenEntry
	checkpoint []byte
	complete   bool
	global     bool
}

func (s vectorSource) ReadEvent(context.Context, dnsidlog.LogRef) (c2sptlog.ProvenEntry, error) {
	return s.entries[0], nil
}
func (s vectorSource) RebuildHistory(context.Context, c2sptlog.Reference, string) ([]c2sptlog.ProvenEntry, error) {
	return append([]c2sptlog.ProvenEntry(nil), s.entries...), nil
}
func (s vectorSource) RebuildCompleteHistory(context.Context, c2sptlog.Reference, string) (c2sptlog.CompleteHistoryResult, error) {
	if !s.complete {
		return c2sptlog.CompleteHistoryResult{}, errors.New("incomplete")
	}
	return c2sptlog.CompleteHistoryResult{
		Entries: s.entries, Checkpoint: s.checkpoint, CompleteThrough: uint64(len(s.entries)), CompletenessMode: "compliance-vector",
	}, nil
}
func (s vectorSource) GlobalCandidates() bool { return s.global }

func migrationVerifierOption(req request) (c2sptlog.Option, error) {
	if req.PriorHistoryVerified == nil || !*req.PriorHistoryVerified {
		return nil, nil
	}
	entityKey, err := jwk.ParseKey(req.EntityJWK)
	if err != nil {
		return nil, err
	}
	operationalKey, err := jwk.ParseKey(req.OperationalJWK)
	if err != nil {
		return nil, err
	}
	prior := dnsidlog.LogEvent{
		Type:         dnsidlog.LogEventIssuance,
		Domain:       req.Domain,
		GovernanceID: "example",
		Timestamp:    time.UnixMilli(req.CheckpointIntegrationTimeMs).Add(-2 * time.Hour),
	}
	logeventcompat.SetIssuance(&prior, entityKey, keyThumbprint(entityKey), operationalKey, keyThumbprint(operationalKey))
	return c2sptlog.WithMigrationVerifier(func(context.Context, dnsidlog.LogEvent) (c2sptlog.MigrationVerificationResult, error) {
		return c2sptlog.MigrationVerificationResult{
			EntityKey:            entityKey,
			ActiveOperationalKey: operationalKey,
			PriorHistory:         []dnsidlog.LogEvent{prior},
		}, nil
	}), nil
}

func handleC2spLifecycleVector(req request) map[string]any {
	policy, err := c2sptlog.ParsePolicy([]byte(req.Policy))
	if err != nil {
		return lifecycleErrJSON(err)
	}
	if !req.CompleteThroughCheckpoint {
		policy.MaxCheckpointAge = 24 * time.Hour
	}
	entries := make([]c2sptlog.ProvenEntry, 0, len(req.Entries))
	effectByTime := map[int64]string{}
	for _, item := range req.Entries {
		entry, err := base64.RawURLEncoding.DecodeString(item.Entry)
		if err != nil {
			return lifecycleErrJSON(err)
		}
		proof, err := base64.RawURLEncoding.DecodeString(item.Proof)
		if err != nil {
			return lifecycleErrJSON(err)
		}
		entries = append(entries, c2sptlog.ProvenEntry{Index: item.Index, Entry: entry, Proof: proof})
		var object map[string]any
		if json.Unmarshal(entry, &object) == nil {
			if ts, ok := object["ts"].(float64); ok {
				effectByTime[int64(ts)] = item.EffectID
			}
		}
	}
	source := vectorSource{entries: entries, checkpoint: []byte(req.Checkpoint), complete: req.CompleteThroughCheckpoint, global: req.CheckpointAccepted}
	if !req.CheckpointAccepted {
		source.global = false
		if len(source.entries) > 0 {
			source.entries[0].Proof = []byte("invalid")
		}
	}
	options := []c2sptlog.Option{c2sptlog.WithSource(source), c2sptlog.WithPolicy(policy)}
	migrationOption, err := migrationVerifierOption(req)
	if err != nil {
		return lifecycleErrJSON(err)
	}
	if migrationOption != nil {
		options = append(options, migrationOption)
	}
	client, err := c2sptlog.New(req.LR, options...)
	if err != nil {
		return lifecycleErrJSON(err)
	}
	if !req.CompleteThroughCheckpoint {
		if err := verifyNonRevocation(client, req.Domain, time.UnixMilli(req.CheckpointIntegrationTimeMs)); err != nil {
			return lifecycleErrJSON(err)
		}
	}
	events, err := client.RebuildHistory(context.Background(), req.Domain)
	if err != nil {
		out := lifecycleErrJSON(err)
		for i := range entries {
			prefixSource := vectorSource{entries: entries[:i+1], checkpoint: []byte(req.Checkpoint), complete: true, global: true}
			prefixOptions := []c2sptlog.Option{c2sptlog.WithSource(prefixSource), c2sptlog.WithPolicy(policy)}
			if migrationOption != nil {
				prefixOptions = append(prefixOptions, migrationOption)
			}
			prefixClient, prefixErr := c2sptlog.New(req.LR, prefixOptions...)
			if prefixErr == nil {
				_, prefixErr = prefixClient.RebuildHistory(context.Background(), req.Domain)
			}
			if prefixErr != nil {
				out["failingCandidateIndex"] = i
				break
			}
		}
		return out
	}
	applied := make([]string, 0, len(events))
	for _, event := range events {
		if id := effectByTime[event.Timestamp.Unix()]; id != "" {
			applied = append(applied, id)
		}
	}
	ignored := []int{}
	used := map[string]int{}
	for _, id := range applied {
		used[id]++
	}
	for i, item := range req.Entries {
		if used[item.EffectID] > 0 {
			used[item.EffectID]--
			continue
		}
		ignored = append(ignored, i)
	}
	out := map[string]any{"ok": true, "appliedEffectIds": applied, "ignoredCandidateIndexes": ignored}
	if req.PriorHistoryVerified != nil && *req.PriorHistoryVerified {
		out["stitchedEffectIds"] = append(append([]string(nil), req.PriorAppliedEffectIDs...), applied...)
	}
	if len(events) > 0 {
		switch events[len(events)-1].Type {
		case dnsidlog.LogEventRevocation:
			out["identityState"] = "REVOKED"
		case dnsidlog.LogEventRetirement:
			out["identityState"] = "RETIRED"
		}
	}
	return out
}

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var reqs []request
	if err := json.Unmarshal(in, &reqs); err != nil {
		fmt.Fprintln(os.Stderr, "bad request JSON:", err)
		os.Exit(2)
	}
	results := make([]map[string]any, len(reqs))
	for i, r := range reqs {
		results[i] = handle(r)
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
