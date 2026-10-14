package webbotauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	"github.com/dnsid-ai/dnsid-go/internal/netguard"
)

type wbaAdapterMessage struct {
	Method     string
	URL        string
	Status     int
	Headers    map[string]string
	BodyBase64 *string
}

func (m wbaAdapterMessage) body(t *testing.T) []byte {
	t.Helper()
	if m.BodyBase64 == nil {
		return nil
	}
	body, err := base64.StdEncoding.DecodeString(*m.BodyBase64)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (m wbaAdapterMessage) request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(m.Method, m.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.BodyBase64 != nil {
		req.Body = io.NopCloser(bytes.NewReader(m.body(t)))
	}
	for name, value := range m.Headers {
		req.Header.Set(name, value)
	}
	return req
}

type wbaAdapterScenario struct {
	Now, FinishedAt                                int64
	ClockSkew                                      int64
	SignerDomain, TrustedDiscoveryURI              string
	DNSidExists, AcceptanceAllowed                 bool
	CurrentKu                                      []map[string]any
	CacheHit                                       bool
	ResolvedAddresses                              []string
	DirectoryTLSValid, RequiresMTLS                bool
	ReplayEnabled, NonceSeen, ReplayStoreAvailable bool
}

// shortcut: reuse the SDK's native identity fixture helpers, replace this bridge when
// public deterministic clock and discovery-transport injection are available.
func TestComplianceWBAAdapter(t *testing.T) {
	var requests []struct {
		Key                map[string]any
		Request, Directory wbaAdapterMessage
		Verification       struct {
			wbaAdapterScenario
			RequiredComponents []string
			ConfigMutation     struct{ ClockSkew *int64 }
			Redirects          []struct {
				URL               string
				ResolvedAddresses []string
			}
			DNSTTL           *int
			DirectoryStatus  int
			DirectoryTimeout bool
			TimeoutMs        int
		}
	}
	data, err := os.ReadFile(os.Getenv("DNSID_WBA_INPUT"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &requests); err != nil {
		t.Fatal(err)
	}
	results := make([]map[string]any, len(requests))
	for i, req := range requests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			s := req.Verification
			req.Key["d"], req.Key["alg"], req.Key["use"] = req.Key["seed"], "EdDSA", "sig"
			delete(req.Key, "seed")
			keyJSON, _ := json.Marshal(req.Key)
			keyPath := filepath.Join(t.TempDir(), "key.json")
			if err := os.WriteFile(keyPath, keyJSON, 0600); err != nil {
				t.Fatal(err)
			}
			kp, err := dnsid.NewLocalKeyProvider(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			f := newWBAFixtureWithKey(t, !s.AcceptanceAllowed && !s.CacheHit, s.RequiresMTLS, s.SignerDomain, kp)
			if s.DNSTTL != nil {
				f.dns.ttl = time.Duration(*s.DNSTTL) * time.Second
			}
			cfg := Config{}.WithClockSkew(time.Duration(s.ClockSkew) * time.Second)
			f.checker = NewVerifier(f.manager, cfg)
			var clock atomic.Int64
			clock.Store(s.Now)
			f.checker.now = func() time.Time { return time.Unix(clock.Load(), 0) }
			if s.ConfigMutation.ClockSkew != nil {
				cfg.ClockSkew = time.Duration(*s.ConfigMutation.ClockSkew) * time.Second
			}
			f.opts.SignerDomain = s.SignerDomain
			f.opts.DirectoryURL = s.TrustedDiscoveryURI + DirectoryPath
			for _, c := range s.RequiredComponents {
				f.opts.RequiredComponents = append(f.opts.RequiredComponents, httpsig.ComponentIdentifier{Name: c})
			}
			var discoveries atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				discoveries.Add(1)
				clock.Store(s.FinishedAt)
				if s.DirectoryTimeout {
					<-r.Context().Done()
					return
				}
				if len(s.Redirects) > 0 {
					w.Header().Set("Location", s.Redirects[0].URL)
					w.WriteHeader(http.StatusFound)
					return
				}
				for name, value := range req.Directory.Headers {
					w.Header().Set(name, value)
				}
				status := req.Directory.Status
				if s.DirectoryStatus != 0 {
					status = s.DirectoryStatus
				}
				w.WriteHeader(status)
				_, _ = w.Write(req.Directory.body(t))
			}))
			cert, err := tls.LoadX509KeyPair(filepath.Join(os.Getenv("DNSID_WBA_TLS"), "wba-cert.pem"), filepath.Join(os.Getenv("DNSID_WBA_TLS"), "wba-key.pem"))
			if err != nil {
				t.Fatal(err)
			}
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			server.StartTLS()
			defer server.Close()
			base := server.Client().Transport.(*http.Transport).Clone()
			roots := x509.NewCertPool()
			if s.DirectoryTLSValid {
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				roots.AddCert(leaf)
			}
			base.TLSClientConfig = &tls.Config{RootCAs: roots}
			resolve := func(context.Context, string) ([]net.IPAddr, error) {
				addresses := s.ResolvedAddresses
				if discoveries.Load() > 0 && len(s.Redirects) > 0 {
					addresses = s.Redirects[0].ResolvedAddresses
				}
				out := make([]net.IPAddr, len(addresses))
				for i, address := range addresses {
					out[i] = net.IPAddr{IP: net.ParseIP(address)}
				}
				return out, nil
			}
			transport := netguard.SafeDialerTransportFrom(base, resolve, func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}, netguard.Policy{})
			transport.DisableCompression = true
			defer transport.CloseIdleConnections()
			f.checker.client.Transport = transport
			seen := map[string]bool{}
			var replayErr error
			if s.ReplayEnabled {
				f.opts.Replay = func(_ context.Context, domain, keyID, nonce string, until time.Time) error {
					if !s.ReplayStoreAvailable {
						replayErr = errors.New("fixture replay store unavailable")
						return replayErr
					}
					key := domain + "/" + keyID + "/" + nonce
					if seen[key] {
						replayErr = errors.New("fixture nonce already used")
						return replayErr
					}
					seen[key] = true
					return nil
				}
			}
			if s.CacheHit || s.NonceSeen {
				if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), req.Request.request(t), f.opts); err != nil {
					results[i] = map[string]any{"ok": false, "error": "AdapterError", "message": "warm-up failed: " + err.Error()}
					return
				}
			}
			if !s.DNSidExists {
				f.dns.record = nil
			}
			if s.CacheHit && !s.AcceptanceAllowed {
				f.checker.resolver = newWBAFixtureWithKey(t, true, false, s.SignerDomain, kp).manager
			}
			keys := make([]map[string]any, len(s.CurrentKu))
			for i, public := range s.CurrentKu {
				key := map[string]any{"alg": "EdDSA", "kid": "fixture-ku"}
				for name, value := range public {
					key[name] = value
				}
				keys[i] = key
			}
			ku, _ := json.Marshal(map[string]any{"keys": keys})
			if s.DNSidExists {
				f.https.documents[f.dns.record.KeyURI] = ku
			}
			f.manager.EvictDomain(s.SignerDomain)
			clock.Store(s.Now)
			ctx := context.Background()
			if s.TimeoutMs > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(s.TimeoutMs)*time.Millisecond)
				defer cancel()
			}
			vd, err := f.checker.VerifyWebBotAuthSignedRequest(ctx, req.Request.request(t), f.opts)
			if err == nil {
				results[i] = map[string]any{"ok": true, "signerDomain": vd.Domain(), "discoveryRequests": discoveries.Load()}
				return
			}
			result := map[string]any{"ok": false, "error": "AdapterError", "message": err.Error(), "discoveryRequests": discoveries.Load()}
			var verificationErr *dnsid.VerificationError
			var argumentErr *dnsid.ArgumentError
			if errors.As(err, &argumentErr) {
				result["error"] = "ArgumentError"
			} else if errors.As(err, &verificationErr) {
				result["error"], result["nativeError"], result["code"], result["transient"] = "ConformanceError", "VerificationError", verificationErr.Code(), verificationErr.Transient()
			} else if replayErr != nil && errors.Is(err, replayErr) {
				result["error"], result["nativeError"] = "ConformanceError", "ReplayPolicyError"
			}
			results[i] = result
		})
	}
	output, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("DNSID_WBA_OUTPUT"), output, 0600); err != nil {
		t.Fatal(err)
	}
}
