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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

// createTestCA generates a self-signed CA certificate and key.
func createTestCA() (*x509.Certificate, *rsa.PrivateKey) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}
	return ca, caKey
}

// createTestLeafCert generates a leaf certificate signed by the CA.
func createTestLeafCert(ca *x509.Certificate, caKey *rsa.PrivateKey, serial *big.Int, crlURL string) (*x509.Certificate, *rsa.PrivateKey) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if crlURL != "" {
		leafTemplate.CRLDistributionPoints = []string{crlURL}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		panic(err)
	}
	return leaf, leafKey
}

// createTestCRL creates a DER-encoded CRL signed by the CA.
func createTestCRL(ca *x509.Certificate, caKey *rsa.PrivateKey, revokedSerials []*big.Int) []byte {
	var revokedEntries []x509.RevocationListEntry
	for _, serial := range revokedSerials {
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-1 * time.Hour),
		})
	}

	crlTemplate := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-1 * time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: revokedEntries,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca, caKey)
	if err != nil {
		panic(err)
	}
	return crlDER
}

// createStaleCRL creates a DER-encoded CRL that is past its NextUpdate.
func createStaleCRL(ca *x509.Certificate, caKey *rsa.PrivateKey) []byte {
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca, caKey)
	if err != nil {
		panic(err)
	}
	return crlDER
}

func getMetricValue(mfs []*dto.MetricFamily, name string) (float64, bool) {
	for _, mf := range mfs {
		if mf.GetName() == name {
			if len(mf.GetMetric()) > 0 {
				return mf.GetMetric()[0].GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

func getMetricWithLabels(mfs []*dto.MetricFamily, name string, labels map[string]string) (float64, bool) {
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			match := true
			for wantK, wantV := range labels {
				found := false
				for _, l := range m.GetLabel() {
					if l.GetName() == wantK && l.GetValue() == wantV {
						found = true
						break
					}
				}
				if !found {
					match = false
					break
				}
			}
			if match {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

func TestCheckChainCRL_ValidCert(t *testing.T) {
	ca, caKey := createTestCA()

	crlDER := createTestCRL(ca, caKey, nil)
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlDER)
	}))
	defer crlServer.Close()

	leaf, _ := createTestLeafCert(ca, caKey, big.NewInt(100), crlServer.URL)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	result := checkChainCRL(context.Background(), state, 5*time.Second, logger)

	if len(result) < 1 {
		t.Fatal("Expected at least 1 cert result")
	}
	leafResult := result[0]
	if !leafResult.Available {
		t.Error("Expected CRL to be available for leaf cert")
	}
	if leafResult.Revoked {
		t.Error("Expected leaf cert not to be revoked")
	}
	if leafResult.Stale {
		t.Error("Expected CRL not to be stale")
	}
	if leafResult.FetchErr != nil {
		t.Errorf("Unexpected fetch error: %v", leafResult.FetchErr)
	}
}

func TestCheckChainCRL_RevokedCert(t *testing.T) {
	ca, caKey := createTestCA()

	leafSerial := big.NewInt(200)
	crlDER := createTestCRL(ca, caKey, []*big.Int{leafSerial})
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlDER)
	}))
	defer crlServer.Close()

	leaf, _ := createTestLeafCert(ca, caKey, leafSerial, crlServer.URL)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	result := checkChainCRL(context.Background(), state, 5*time.Second, logger)

	leafResult := result[0]
	if !leafResult.Available {
		t.Error("Expected CRL to be available")
	}
	if !leafResult.Revoked {
		t.Error("Expected leaf cert to be revoked")
	}
}

func TestCheckChainCRL_NoCRLDistributionPoints(t *testing.T) {
	ca, caKey := createTestCA()

	leaf, _ := createTestLeafCert(ca, caKey, big.NewInt(300), "")

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	result := checkChainCRL(context.Background(), state, 5*time.Second, logger)

	leafResult := result[0]
	if leafResult.Available {
		t.Error("Expected CRL not to be available for cert without distribution points")
	}
	if leafResult.Revoked {
		t.Error("Expected cert without CRL to not be marked revoked")
	}
}

func TestCheckChainCRL_StaleCRL(t *testing.T) {
	ca, caKey := createTestCA()

	crlDER := createStaleCRL(ca, caKey)
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlDER)
	}))
	defer crlServer.Close()

	leaf, _ := createTestLeafCert(ca, caKey, big.NewInt(400), crlServer.URL)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	result := checkChainCRL(context.Background(), state, 5*time.Second, logger)

	leafResult := result[0]
	if !leafResult.Available {
		t.Error("Expected CRL to be available")
	}
	if !leafResult.Stale {
		t.Error("Expected CRL to be stale")
	}
}

func TestCheckChainCRL_FetchFailure(t *testing.T) {
	ca, caKey := createTestCA()

	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer crlServer.Close()

	leaf, _ := createTestLeafCert(ca, caKey, big.NewInt(500), crlServer.URL)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	result := checkChainCRL(context.Background(), state, 5*time.Second, logger)

	leafResult := result[0]
	if leafResult.Available {
		t.Error("Expected CRL not to be available on fetch failure")
	}
	if leafResult.FetchErr == nil {
		t.Error("Expected fetch error")
	}
}

func TestCheckChainCRL_UnreachableURL(t *testing.T) {
	ca, caKey := createTestCA()

	// Start a server to obtain a valid URL, then close it so the address
	// refuses connections — simulating an unreachable CRL distribution point.
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
	}))
	crlURL := crlServer.URL
	crlServer.Close()

	leaf, _ := createTestLeafCert(ca, caKey, big.NewInt(550), crlURL)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	result := checkChainCRL(context.Background(), state, 2*time.Second, logger)

	leafResult := result[0]
	if leafResult.Available {
		t.Error("Expected CRL not to be available for unreachable URL")
	}
	if leafResult.FetchErr == nil {
		t.Error("Expected fetch error for unreachable URL")
	}
	if leafResult.Revoked {
		t.Error("Expected cert not to be marked revoked when CRL is unreachable")
	}
	if leafResult.CRLUrl != crlURL {
		t.Errorf("Expected CRLUrl to record the attempted URL %q, got %q", crlURL, leafResult.CRLUrl)
	}

	// Metrics must still register and report the cert as unavailable.
	registry := prometheus.NewRegistry()
	registerCRLMetrics(registry, result)

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	labels := map[string]string{"subject": "CN=Test Leaf", "crl_url": crlURL}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", labels); !ok || val != 0 {
		t.Errorf("Expected probe_ssl_crl_available=0 for unreachable URL, got %v (found=%v)", val, ok)
	}
}

func TestCheckChainCRL_FetchTimeout(t *testing.T) {
	ca, caKey := createTestCA()

	// Server that hangs until the client gives up, forcing a timeout while
	// awaiting the response — reproduces the real-world "context deadline
	// exceeded" seen against slow/unresponsive CRL responders.
	crlServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer crlServer.Close()

	leaf, _ := createTestLeafCert(ca, caKey, big.NewInt(560), crlServer.URL)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	// Short context deadline so the hanging fetch is cancelled quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	logger := promslog.New(&promslog.Config{})
	result := checkChainCRL(ctx, state, 5*time.Second, logger)

	leafResult := result[0]
	if leafResult.Available {
		t.Error("Expected CRL not to be available on fetch timeout")
	}
	if leafResult.FetchErr == nil {
		t.Error("Expected fetch error on timeout")
	}
	if leafResult.Revoked {
		t.Error("Expected cert not to be marked revoked when CRL fetch times out")
	}
}

func TestRegisterCRLMetrics_ValidCert(t *testing.T) {
	ca, caKey := createTestCA()

	crlDER := createTestCRL(ca, caKey, nil)
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlDER)
	}))
	defer crlServer.Close()

	leaf, _ := createTestLeafCert(ca, caKey, big.NewInt(600), crlServer.URL)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	crlResult := checkChainCRL(context.Background(), state, 5*time.Second, logger)

	registry := prometheus.NewRegistry()
	registerCRLMetrics(registry, crlResult)

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	labels := map[string]string{"subject": "CN=Test Leaf", "issuer": "CN=Test CA"}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", labels); !ok || val != 1 {
		t.Errorf("Expected probe_ssl_crl_available=1 for leaf, got %v (found=%v)", val, ok)
	}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_revoked", labels); !ok || val != 0 {
		t.Errorf("Expected probe_ssl_crl_revoked=0 for leaf, got %v (found=%v)", val, ok)
	}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_stale", labels); !ok || val != 0 {
		t.Errorf("Expected probe_ssl_crl_stale=0 for leaf, got %v (found=%v)", val, ok)
	}
	if _, ok := getMetricValue(mfs, "probe_ssl_crl_fetch_time_seconds"); !ok {
		t.Error("Expected probe_ssl_crl_fetch_time_seconds metric")
	}
}

func TestRegisterCRLMetrics_CRLUrlLabel(t *testing.T) {
	ca, caKey := createTestCA()

	crlDER := createTestCRL(ca, caKey, nil)
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlDER)
	}))
	defer crlServer.Close()

	leaf, _ := createTestLeafCert(ca, caKey, big.NewInt(800), crlServer.URL)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	crlResult := checkChainCRL(context.Background(), state, 5*time.Second, logger)

	registry := prometheus.NewRegistry()
	registerCRLMetrics(registry, crlResult)

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	labels := map[string]string{"subject": "CN=Test Leaf", "crl_url": crlServer.URL}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", labels); !ok || val != 1 {
		t.Errorf("Expected probe_ssl_crl_available=1 with crl_url=%q, got %v (found=%v)", crlServer.URL, val, ok)
	}
}

func TestRegisterCRLMetrics_CRLUrlEmptyForNoCDP(t *testing.T) {
	ca, caKey := createTestCA()

	leaf, _ := createTestLeafCert(ca, caKey, big.NewInt(900), "")

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	crlResult := checkChainCRL(context.Background(), state, 5*time.Second, logger)

	registry := prometheus.NewRegistry()
	registerCRLMetrics(registry, crlResult)

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	labels := map[string]string{"subject": "CN=Test Leaf", "crl_url": ""}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_available", labels); !ok || val != 0 {
		t.Errorf("Expected probe_ssl_crl_available=0 with empty crl_url, got %v (found=%v)", val, ok)
	}
}

func TestRegisterCRLMetrics_RevokedCert(t *testing.T) {
	ca, caKey := createTestCA()

	leafSerial := big.NewInt(700)
	crlDER := createTestCRL(ca, caKey, []*big.Int{leafSerial})
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlDER)
	}))
	defer crlServer.Close()

	leaf, _ := createTestLeafCert(ca, caKey, leafSerial, crlServer.URL)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
	}

	logger := promslog.New(&promslog.Config{})
	crlResult := checkChainCRL(context.Background(), state, 5*time.Second, logger)

	registry := prometheus.NewRegistry()
	registerCRLMetrics(registry, crlResult)

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	labels := map[string]string{"subject": "CN=Test Leaf", "issuer": "CN=Test CA"}
	if val, ok := getMetricWithLabels(mfs, "probe_ssl_crl_revoked", labels); !ok || val != 1 {
		t.Errorf("Expected probe_ssl_crl_revoked=1 for leaf, got %v (found=%v)", val, ok)
	}
}
