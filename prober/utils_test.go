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
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/go-kit/kit/log"

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

// Create test certificate with specified expiry date
// Certificate will be self-signed and use localhost/127.0.0.1
// Generated certificate and key are returned in PEM encoding
func generateTestCertificate(expiry time.Time, IPAddressSAN bool) ([]byte, []byte) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error creating rsa key: %s", err))
	}
	publickey := &privatekey.PublicKey

	cert := x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1},
		SerialNumber:          big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Org"},
		},
		NotBefore:   time.Now(),
		NotAfter:    expiry,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	cert.DNSNames = append(cert.DNSNames, "localhost")
	if IPAddressSAN {
		cert.IPAddresses = append(cert.IPAddresses, net.ParseIP("127.0.0.1"))
		cert.IPAddresses = append(cert.IPAddresses, net.ParseIP("::1"))
	}
	derCert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, publickey, privatekey)
	if err != nil {
		panic(fmt.Sprintf("Error signing test-certificate: %s", err))
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})
	return pemCert, pemKey
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
	if err != nil && err.Error() != "unable to find ip; no fallback" {
		t.Error(err)
	} else if err == nil {
		t.Error("should set error")
	}
	if ip != nil {
		t.Error("without fallback it should not answer")
	}
}

func TestSetDNSParamFromUrl(t *testing.T) {
	var int_value int = 0
	var bool_value bool = false
	var string_value string = "default"
	var float_value float64 = 0
	var array_value []string

	params := url.Values{}
	params.Add("a", "123")
	params.Add("b", "true")
	params.Add("c", "magic")

	SetParamFromUrl(params, []string{"a", "b", "c", "d"}, map[string]interface{}{
		"a": &int_value,
		"b": &bool_value,
		"c": &string_value,
		"d": &float_value,
		"e": &array_value,
	})

	if int_value != 123 {
		t.Error("int value parse fail")
	}
	if bool_value != true {
		t.Error("bool value parse fail")
	}
	if string_value != "magic" {
		t.Error("string value parse fail")
	}
}
