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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-kit/log"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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

func generateCertificate(template, parent *x509.Certificate, publickey *rsa.PublicKey, privatekey *rsa.PrivateKey) (*x509.Certificate, []byte) {
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

func TestChooseProtocol(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network dependent test")
	}
	ctx := context.Background()
	registry := prometheus.NewPedanticRegistry()
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)

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
