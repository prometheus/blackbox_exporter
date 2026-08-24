// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"
)

const (
	testLeafSubject = "CN=Test Leaf,O=Example Org"
	testCASubject   = "CN=Test CA,O=Example Org"
)

func validCRLWindow() (time.Time, time.Time) {
	return time.Now().Add(-1 * time.Hour), time.Now().Add(24 * time.Hour)
}

func TestCheckChainCRL(t *testing.T) {
	tests := []struct {
		name string
		// setup returns the chain to check and the CRL URL expected on the leaf result.
		setup         func(t *testing.T) (chain []*x509.Certificate, crlURL string)
		ctx           func(t *testing.T) context.Context
		wantAvailable bool
		wantRevoked   bool
		wantStale     bool
		wantFetchErr  bool
	}{
		{
			name: "valid cert",
			setup: func(t *testing.T) ([]*x509.Certificate, string) {
				ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
				thisUpdate, nextUpdate := validCRLWindow()
				srv := newCRLServer(t, createCRL(t, ca, caKey, thisUpdate, nextUpdate))
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 100, CRLURL: srv.URL}, ca, caKey)
				return []*x509.Certificate{leaf, ca}, srv.URL
			},
			wantAvailable: true,
		},
		{
			name: "revoked cert",
			setup: func(t *testing.T) ([]*x509.Certificate, string) {
				ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
				thisUpdate, nextUpdate := validCRLWindow()
				srv := newCRLServer(t, createCRL(t, ca, caKey, thisUpdate, nextUpdate, 200))
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 200, CRLURL: srv.URL}, ca, caKey)
				return []*x509.Certificate{leaf, ca}, srv.URL
			},
			wantAvailable: true,
			wantRevoked:   true,
		},
		{
			name: "no CRL distribution points",
			setup: func(t *testing.T) ([]*x509.Certificate, string) {
				ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 300}, ca, caKey)
				return []*x509.Certificate{leaf, ca}, ""
			},
		},
		{
			name: "stale CRL",
			setup: func(t *testing.T) ([]*x509.Certificate, string) {
				ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
				srv := newCRLServer(t, createCRL(t, ca, caKey, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)))
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 400, CRLURL: srv.URL}, ca, caKey)
				return []*x509.Certificate{leaf, ca}, srv.URL
			},
			wantAvailable: true,
			wantStale:     true,
		},
		{
			name: "CRL not yet valid",
			setup: func(t *testing.T) ([]*x509.Certificate, string) {
				ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
				srv := newCRLServer(t, createCRL(t, ca, caKey, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour)))
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 450, CRLURL: srv.URL}, ca, caKey)
				return []*x509.Certificate{leaf, ca}, srv.URL
			},
			wantFetchErr: true,
		},
		{
			name: "CRL server returns an error",
			setup: func(t *testing.T) ([]*x509.Certificate, string) {
				ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
				t.Cleanup(srv.Close)
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 500, CRLURL: srv.URL}, ca, caKey)
				return []*x509.Certificate{leaf, ca}, srv.URL
			},
			wantFetchErr: true,
		},
		{
			name: "CRL URL unreachable",
			setup: func(t *testing.T) ([]*x509.Certificate, string) {
				ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
				// Start a server to obtain a valid URL, then close it so the
				// address refuses connections.
				srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
				srv.Close()
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 550, CRLURL: srv.URL}, ca, caKey)
				return []*x509.Certificate{leaf, ca}, srv.URL
			},
			wantFetchErr: true,
		},
		{
			name: "CRL fetch times out",
			setup: func(t *testing.T) ([]*x509.Certificate, string) {
				ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
				// Hangs until the client gives up, reproducing the real-world
				// "context deadline exceeded" against an unresponsive responder.
				srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					<-r.Context().Done()
				}))
				t.Cleanup(srv.Close)
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 560, CRLURL: srv.URL}, ca, caKey)
				return []*x509.Certificate{leaf, ca}, srv.URL
			},
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
			wantFetchErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain, crlURL := test.setup(t)

			ctx := context.Background()
			if test.ctx != nil {
				ctx = test.ctx(t)
			}

			results := checkChainCRL(ctx, chainState(chain...), nil, promslog.NewNopLogger())
			if len(results) != len(chain) {
				t.Fatalf("Expected %d cert results, got %d", len(chain), len(results))
			}

			leaf := results[0]
			if leaf.Available != test.wantAvailable {
				t.Errorf("Available = %v, want %v (err: %v)", leaf.Available, test.wantAvailable, leaf.FetchErr)
			}
			if leaf.Revoked != test.wantRevoked {
				t.Errorf("Revoked = %v, want %v", leaf.Revoked, test.wantRevoked)
			}
			if leaf.Stale != test.wantStale {
				t.Errorf("Stale = %v, want %v", leaf.Stale, test.wantStale)
			}
			if gotErr := leaf.FetchErr != nil; gotErr != test.wantFetchErr {
				t.Errorf("FetchErr = %v, want error: %v", leaf.FetchErr, test.wantFetchErr)
			}
			if leaf.CRLUrl != crlURL {
				t.Errorf("CRLUrl = %q, want %q", leaf.CRLUrl, crlURL)
			}
		})
	}
}

// TestCheckChainCRLIntermediate covers a root -> intermediate -> leaf chain,
// where each certificate is checked against the CRL of its own issuer.
func TestCheckChainCRLIntermediate(t *testing.T) {
	root, rootKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Root", Serial: 1, IsCA: true}, nil, nil)

	thisUpdate, nextUpdate := validCRLWindow()
	// The root revokes the intermediate; the intermediate revokes nothing.
	const intermediateSerial = 20
	rootCRL := newCRLServer(t, createCRL(t, root, rootKey, thisUpdate, nextUpdate, intermediateSerial))

	intermediate, intermediateKey := generateCRLTestCert(t,
		crlCertOptions{CommonName: "Test Intermediate", Serial: intermediateSerial, CRLURL: rootCRL.URL, IsCA: true}, root, rootKey)

	intermediateCRL := newCRLServer(t, createCRL(t, intermediate, intermediateKey, thisUpdate, nextUpdate))
	leaf, _ := generateCRLTestCert(t,
		crlCertOptions{CommonName: "Test Leaf", Serial: 30, CRLURL: intermediateCRL.URL}, intermediate, intermediateKey)

	results := checkChainCRL(context.Background(), chainState(leaf, intermediate, root), nil, promslog.NewNopLogger())
	if len(results) != 3 {
		t.Fatalf("Expected 3 cert results, got %d", len(results))
	}

	leafResult, intermediateResult, rootResult := results[0], results[1], results[2]

	if !leafResult.Available || leafResult.Revoked {
		t.Errorf("Leaf: Available = %v, Revoked = %v; want true/false (err: %v)",
			leafResult.Available, leafResult.Revoked, leafResult.FetchErr)
	}
	if leafResult.CRLUrl != intermediateCRL.URL {
		t.Errorf("Leaf CRLUrl = %q, want the intermediate CRL %q", leafResult.CRLUrl, intermediateCRL.URL)
	}

	// The intermediate must be checked against the root's CRL, which revokes it.
	if !intermediateResult.Available {
		t.Errorf("Intermediate: expected CRL to be available, got err: %v", intermediateResult.FetchErr)
	}
	if !intermediateResult.Revoked {
		t.Error("Intermediate: expected it to be reported as revoked")
	}
	if intermediateResult.CRLUrl != rootCRL.URL {
		t.Errorf("Intermediate CRLUrl = %q, want the root CRL %q", intermediateResult.CRLUrl, rootCRL.URL)
	}
	if intermediateResult.ChainPos != 1 {
		t.Errorf("Intermediate ChainPos = %d, want 1", intermediateResult.ChainPos)
	}

	// The root has no distribution point of its own, so it is skipped.
	if rootResult.Available {
		t.Error("Root: expected no CRL to be available")
	}

	registry := prometheus.NewRegistry()
	registerCRLMetrics(registry, results)
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	intermediateLabels := map[string]string{"subject": "CN=Test Intermediate,O=Example Org", "chain_pos": "1"}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_revoked", intermediateLabels); !ok || val != 1 {
		t.Errorf("Expected probe_ssl_crl_revoked=1 for the intermediate, got %v (found=%v)", val, ok)
	}
}

func TestRegisterCRLMetrics(t *testing.T) {
	ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
	thisUpdate, nextUpdate := validCRLWindow()

	tests := []struct {
		name          string
		setup         func(t *testing.T) []*x509.Certificate
		labels        map[string]string
		wantAvailable float64
		wantRevoked   float64
	}{
		{
			name: "valid cert reports available and not revoked",
			setup: func(t *testing.T) []*x509.Certificate {
				srv := newCRLServer(t, createCRL(t, ca, caKey, thisUpdate, nextUpdate))
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 600, CRLURL: srv.URL}, ca, caKey)
				return []*x509.Certificate{leaf, ca}
			},
			labels:        map[string]string{"subject": testLeafSubject, "issuer": testCASubject},
			wantAvailable: 1,
			wantRevoked:   0,
		},
		{
			name: "revoked cert reports revoked",
			setup: func(t *testing.T) []*x509.Certificate {
				srv := newCRLServer(t, createCRL(t, ca, caKey, thisUpdate, nextUpdate, 700))
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 700, CRLURL: srv.URL}, ca, caKey)
				return []*x509.Certificate{leaf, ca}
			},
			labels:        map[string]string{"subject": testLeafSubject, "issuer": testCASubject},
			wantAvailable: 1,
			wantRevoked:   1,
		},
		{
			name: "cert without distribution points reports an empty crl_url",
			setup: func(t *testing.T) []*x509.Certificate {
				leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 900}, ca, caKey)
				return []*x509.Certificate{leaf, ca}
			},
			labels:        map[string]string{"subject": testLeafSubject, "crl_url": ""},
			wantAvailable: 0,
			wantRevoked:   0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := test.setup(t)

			results := checkChainCRL(context.Background(), chainState(chain...), nil, promslog.NewNopLogger())

			registry := prometheus.NewRegistry()
			registerCRLMetrics(registry, results)

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}

			if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", test.labels); !ok || val != test.wantAvailable {
				t.Errorf("probe_ssl_crl_available = %v (found=%v), want %v", val, ok, test.wantAvailable)
			}
			if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_revoked", test.labels); !ok || val != test.wantRevoked {
				t.Errorf("probe_ssl_crl_revoked = %v (found=%v), want %v", val, ok, test.wantRevoked)
			}
			if _, ok := getMetricValue(mfs, "probe_ssl_crl_fetch_time_seconds"); !ok {
				t.Error("Expected probe_ssl_crl_fetch_time_seconds metric")
			}
		})
	}
}

// TestRegisterCRLMetricsCRLUrlLabel asserts the crl_url label carries the
// distribution point that was actually used.
func TestRegisterCRLMetricsCRLUrlLabel(t *testing.T) {
	ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
	thisUpdate, nextUpdate := validCRLWindow()
	srv := newCRLServer(t, createCRL(t, ca, caKey, thisUpdate, nextUpdate))
	leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 800, CRLURL: srv.URL}, ca, caKey)

	results := checkChainCRL(context.Background(), chainState(leaf, ca), nil, promslog.NewNopLogger())

	registry := prometheus.NewRegistry()
	registerCRLMetrics(registry, results)
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	labels := map[string]string{"subject": testLeafSubject, "crl_url": srv.URL}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", labels); !ok || val != 1 {
		t.Errorf("Expected probe_ssl_crl_available=1 with crl_url=%q, got %v (found=%v)", srv.URL, val, ok)
	}
}

// TestCheckChainCRLUsesProxy asserts the CRL fetch honours the probe's proxy
// configuration. The distribution point uses an unresolvable host, so the fetch
// can only succeed by going through the proxy.
func TestCheckChainCRLUsesProxy(t *testing.T) {
	ca, caKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test CA", Serial: 1, IsCA: true}, nil, nil)
	thisUpdate, nextUpdate := validCRLWindow()
	crlDER := createCRL(t, ca, caKey, thisUpdate, nextUpdate)

	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.Header().Set("Content-Type", "application/pkix-crl")
		if _, err := w.Write(crlDER); err != nil {
			t.Errorf("writing CRL response: %s", err)
		}
	}))
	t.Cleanup(proxy.Close)

	// .invalid never resolves (RFC 2606).
	const crlURL = "http://crl.invalid/root.crl"
	leaf, _ := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 1400, CRLURL: crlURL}, ca, caKey)

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parsing proxy URL: %s", err)
	}
	proxyConfig := &pconfig.ProxyConfig{ProxyURL: pconfig.URL{URL: proxyURL}}

	results := checkChainCRL(context.Background(), chainState(leaf, ca), proxyConfig, promslog.NewNopLogger())
	if !results[0].Available {
		t.Errorf("Expected the CRL to be fetched through the proxy, got err: %v", results[0].FetchErr)
	}
	if got := proxied.Load(); got == 0 {
		t.Error("Expected the proxy to receive the CRL request")
	}

	// Without the proxy the same distribution point must fail, which proves the
	// success above came from the proxy rather than from direct connectivity.
	direct := checkChainCRL(context.Background(), chainState(leaf, ca), nil, promslog.NewNopLogger())
	if direct[0].Available {
		t.Error("Expected the unresolvable distribution point to fail without a proxy")
	}
}
