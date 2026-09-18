// Copyright 2016 The Prometheus Authors
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
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"
)

// Check if expected results are in the registry
func checkRegistryResults(expRes map[string]float64, mfs []*dto.MetricFamily, t *testing.T) {
	res := make(map[string]float64)
	for i := range mfs {
		res[mfs[i].GetName()] = mfs[i].Metric[0].GetGauge().GetValue()
	}
	for k, v := range expRes {
		val, ok := res[k]
		if !ok {
			t.Fatalf("Expected metric %v not found in returned metrics", k)
		}
		if val != v {
			t.Fatalf("Expected: %v: %v, got: %v: %v", k, v, k, val)
		}
	}
}

// Check if expected labels are in the registry
func checkRegistryLabels(expRes map[string]map[string]string, mfs []*dto.MetricFamily, t *testing.T) {
	results := make(map[string]map[string]string)
	for _, mf := range mfs {
		result := make(map[string]string)
		for _, metric := range mf.Metric {
			for _, l := range metric.GetLabel() {
				result[l.GetName()] = l.GetValue()
			}
		}
		results[mf.GetName()] = result
	}

	for metric, labelValues := range expRes {
		if _, ok := results[metric]; !ok {
			t.Fatalf("Expected metric %v not found in returned metrics", metric)
		}
		for name, exp := range labelValues {
			val, ok := results[metric][name]
			if !ok {
				t.Fatalf("Expected label %v for metric %v not found in returned metrics", val, name)
			}
			if val != exp {
				t.Fatalf("Expected: %v{%q=%q}, got: %v{%q=%q}", metric, name, exp, metric, name, val)
			}
		}
	}
}

func generateCertificateTemplate(expiry time.Time, IPAddressSAN bool) *x509.Certificate {
	template := &x509.Certificate{
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1},
		SerialNumber:          big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Example",
			Organization: []string{"Example Org"},
		},
		NotBefore:   time.Now(),
		NotAfter:    expiry,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	template.DNSNames = append(template.DNSNames, "localhost")
	if IPAddressSAN {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
		template.IPAddresses = append(template.IPAddresses, net.ParseIP("::1"))
	}

	return template
}

func generateCertificate(template, _ *x509.Certificate, publickey *rsa.PublicKey, privatekey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	derCert, err := x509.CreateCertificate(rand.Reader, template, template, publickey, privatekey)
	if err != nil {
		panic(fmt.Sprintf("Error signing test-certificate: %s", err))
	}
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		panic(fmt.Sprintf("Error parsing test-certificate: %s", err))
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	return cert, pemCert

}

func generateSignedCertificate(template, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error creating rsa key: %s", err))
	}
	cert, pemCert := generateCertificate(template, parentCert, &privatekey.PublicKey, parentKey)
	return cert, pemCert, privatekey
}

func generateSelfSignedCertificate(template *x509.Certificate) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error creating rsa key: %s", err))
	}
	publickey := &privatekey.PublicKey

	cert, pemCert := generateCertificate(template, template, publickey, privatekey)
	return cert, pemCert, privatekey
}

func generateSelfSignedCertificateWithPrivateKey(template *x509.Certificate, privatekey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	publickey := &privatekey.PublicKey
	cert, pemCert := generateCertificate(template, template, publickey, privatekey)
	return cert, pemCert
}

// clientCertTLSConfig returns a TLS client config presenting a self-signed
// certificate, for probes that need to reach a server's client-certificate
// verification step (as opposed to presenting no certificate at all).
func clientCertTLSConfig(t *testing.T) pconfig.TLSConfig {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error creating rsa key: %s", err)
	}
	tmpl := generateCertificateTemplate(time.Now().Add(time.Hour), false)
	_, certPem := generateSelfSignedCertificateWithPrivateKey(tmpl, key)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return pconfig.TLSConfig{
		InsecureSkipVerify: true,
		Cert:               string(certPem),
		Key:                pconfig.Secret(keyPem),
	}
}

// crlCertOptions describes a certificate to generate for CRL tests.
type crlCertOptions struct {
	CommonName string
	Serial     int64
	CRLURL     string // CRL distribution point; empty means the cert has none
	IsCA       bool   // CA certs are allowed to sign certificates and CRLs
}

// generateCRLTestCert creates a certificate from opts, signed by parent. When
// parent is nil the certificate is self-signed. Unlike generateSignedCertificate
// this honours parent, so the resulting chain has correct issuer names.
func generateCRLTestCert(t *testing.T, opts crlCertOptions, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	template := generateCertificateTemplate(time.Now().Add(24*time.Hour), true)
	template.NotBefore = time.Now().Add(-1 * time.Hour)
	template.Subject.CommonName = opts.CommonName
	template.SerialNumber = big.NewInt(opts.Serial)
	template.IsCA = opts.IsCA
	if opts.IsCA {
		template.KeyUsage |= x509.KeyUsageCRLSign
	}
	if opts.CRLURL != "" {
		template.CRLDistributionPoints = []string{opts.CRLURL}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key for %q: %s", opts.CommonName, err)
	}

	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("creating certificate %q: %s", opts.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate %q: %s", opts.CommonName, err)
	}
	return cert, key
}

// createCRL creates a DER-encoded CRL signed by issuer. Serials in revoked are
// listed as revoked; thisUpdate/nextUpdate control validity and staleness.
func createCRL(t *testing.T, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, thisUpdate, nextUpdate time.Time, revoked ...int64) []byte {
	t.Helper()
	var revokedEntries []x509.RevocationListEntry
	for _, serial := range revoked {
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(serial),
			RevocationTime: time.Now().Add(-1 * time.Hour),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: revokedEntries,
	}, issuer, issuerKey)
	if err != nil {
		t.Fatalf("creating CRL: %s", err)
	}
	return der
}

// newCRLServer serves the given DER-encoded CRL and is torn down with the test.
func newCRLServer(t *testing.T, der []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		if _, err := w.Write(der); err != nil {
			t.Errorf("writing CRL response: %s", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// chainState builds a TLS connection state from an ordered certificate chain.
func chainState(chain ...*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: chain}
}

// serverTLSCert builds a tls.Certificate presenting the given chain, signed with key.
func serverTLSCert(key *rsa.PrivateKey, chain ...*x509.Certificate) tls.Certificate {
	raw := make([][]byte, 0, len(chain))
	for _, cert := range chain {
		raw = append(raw, cert.Raw)
	}
	return tls.Certificate{Certificate: raw, PrivateKey: key}
}

// newCRLLeafCert builds a CA + leaf certificate pair with a live CRL responder
// that reports the leaf as valid (not revoked). Useful for TLS servers whose
// certificate/CRL metrics need a real, verifiable chain rather than the plain
// self-signed certs used elsewhere.
func newCRLLeafCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	// The CA's expiry is set far later than the leaf's so getEarliestCertExpiry
	// (which scans the whole chain) deterministically returns the leaf's
	// NotAfter, regardless of any millisecond-level timing between creating
	// the two certificates straddling a whole-second boundary.
	caTmpl := generateCertificateTemplate(time.Now().Add(30*24*time.Hour), true)
	caTmpl.IsCA = true
	caTmpl.KeyUsage |= x509.KeyUsageCRLSign
	ca, _, caKey := generateSelfSignedCertificate(caTmpl)

	crlServer := newCRLServer(t, createCRL(t, ca, caKey, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour)))
	leaf, leafKey := generateCRLTestCert(t, crlCertOptions{CommonName: "Test Leaf", Serial: 2000, CRLURL: crlServer.URL}, ca, caKey)
	return leaf, leafKey, ca
}

// tlsRequireClientCertServerWithCert starts a TLS listener presenting the given
// leaf/ca chain and requiring (but not verifying) a client certificate,
// restricted to a single TLS version. Like tlsRequireClientCertServer, the
// probe never presents one, so the handshake is rejected with a
// version-specific alert.
func tlsRequireClientCertServerWithCert(t *testing.T, tlsVersion uint16, leaf *x509.Certificate, leafKey *rsa.PrivateKey, ca *x509.Certificate) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert(leafKey, leaf, ca)},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tlsVersion,
			MaxVersion:   tlsVersion,
		})
		defer tlsConn.Close()
		// The client never presents a certificate, so this always errors;
		// the alert it sent is what the test cares about.
		tlsConn.Handshake()
	}()

	return ln
}

// tlsRequireClientCertHTTPServerWithCert is the HTTP counterpart of
// tlsRequireClientCertServerWithCert.
func tlsRequireClientCertHTTPServerWithCert(t *testing.T, tlsVersion uint16, leaf *x509.Certificate, leafKey *rsa.PrivateKey, ca *x509.Certificate) *httptest.Server {
	t.Helper()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert(leafKey, leaf, ca)},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tlsVersion,
		MaxVersion:   tlsVersion,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// getMetricValue returns the value of the first metric in the named family.
func getMetricValue(mfs []*dto.MetricFamily, name string) (float64, bool) {
	for _, mf := range mfs {
		if mf.GetName() == name && len(mf.GetMetric()) > 0 {
			return mf.GetMetric()[0].GetGauge().GetValue(), true
		}
	}
	return 0, false
}

// getMetricWithLabels returns the value of the metric in the named family whose
// labels are a superset of the given labels.
func getMetricWithLabels(mfs []*dto.MetricFamily, name string, labels map[string]string) (float64, bool) {
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if metricHasLabels(m, labels) {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

func metricHasLabels(m *dto.Metric, labels map[string]string) bool {
	for wantName, wantValue := range labels {
		found := false
		for _, l := range m.GetLabel() {
			if l.GetName() == wantName && l.GetValue() == wantValue {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestChooseProtocol(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network dependent test")
	}
	ctx := context.Background()
	registry := prometheus.NewPedanticRegistry()
	logger := promslog.New(&promslog.Config{})

	ip, _, err := chooseProtocol(ctx, "ip4", true, "ipv6.google.com", registry, logger)
	if err != nil {
		t.Error(err)
	}
	if ip == nil || ip.IP.To4() != nil {
		t.Error("with fallback it should answer")
	}

	registry = prometheus.NewPedanticRegistry()

	ip, _, err = chooseProtocol(ctx, "ip4", false, "ipv6.google.com", registry, logger)
	if err != nil && !err.(*net.DNSError).IsNotFound {
		t.Error(err)
	} else if err == nil {
		t.Error("should set error")
	}
	if ip != nil {
		t.Error("without fallback it should not answer")
	}
}

func checkMetrics(expected map[string]map[string]map[string]struct{}, mfs []*dto.MetricFamily, t *testing.T) {
	type (
		valueValidation struct {
			found bool
		}
		labelValidation struct {
			found  bool
			values map[string]valueValidation
		}
		metricValidation struct {
			found  bool
			labels map[string]labelValidation
		}
	)

	foundMetrics := map[string]metricValidation{}

	for mname, labels := range expected {
		var mv metricValidation
		if labels != nil {
			mv.labels = map[string]labelValidation{}
			for lname, values := range labels {
				var lv labelValidation
				if values != nil {
					lv.values = map[string]valueValidation{}
					for vname := range values {
						lv.values[vname] = valueValidation{}
					}
				}
				mv.labels[lname] = lv
			}
		}
		foundMetrics[mname] = mv
	}

	for _, mf := range mfs {
		info, wanted := foundMetrics[mf.GetName()]
		if !wanted {
			continue
		}
		info.found = true
		for _, metric := range mf.GetMetric() {
			if info.labels == nil {
				continue
			}
			for _, lp := range metric.Label {
				if label, labelWanted := info.labels[lp.GetName()]; labelWanted {
					label.found = true
					if label.values != nil {
						if value, wanted := label.values[lp.GetValue()]; !wanted {
							t.Fatalf("Unexpected label %s=%s", lp.GetName(), lp.GetValue())
						} else if value.found {
							t.Fatalf("Label %s=%s duplicated", lp.GetName(), lp.GetValue())
						}
						label.values[lp.GetValue()] = valueValidation{found: true}
					}
					info.labels[lp.GetName()] = label
				}
			}
		}
		foundMetrics[mf.GetName()] = info
	}

	for mname, m := range foundMetrics {
		if !m.found {
			t.Fatalf("metric %s wanted, not found", mname)
		}
		for lname, label := range m.labels {
			if !label.found {
				t.Fatalf("metric %s, label %s wanted, not found", mname, lname)
			}
			for vname, value := range label.values {
				if !value.found {
					t.Fatalf("metric %s, label %s, value %s wanted, not found", mname, lname, vname)
				}
			}
		}
	}
}

func TestGetSerialNumber(t *testing.T) {
	tests := []struct {
		name         string
		serialNumber *big.Int
		expected     string
	}{
		{
			name: "Serial number with leading zeros",
			serialNumber: func() *big.Int {
				serialNumber, _ := new(big.Int).SetString("0BFFBC11F1907D02AF719AFCD64FB253", 16)
				return serialNumber
			}(),
			expected: "0bffbc11f1907d02af719afcd64fb253",
		},
		{
			name: "Serial number without leading zeros",
			serialNumber: func() *big.Int {
				serialNumber, _ := new(big.Int).SetString("BBFFBC11F1907D02AF719AFCD64FB253", 16)
				return serialNumber
			}(),
			expected: "bbffbc11f1907d02af719afcd64fb253",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				SerialNumber: tt.serialNumber,
			}
			state := &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			}
			result := getSerialNumber(state)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func checkAbsentMetrics(absent []string, mfs []*dto.MetricFamily, t *testing.T) {
	for _, v := range mfs {
		name := v.GetName()
		if slices.Contains(absent, name) {
			t.Fatalf("metric %s was found but should be absent", name)
		}
	}
}
