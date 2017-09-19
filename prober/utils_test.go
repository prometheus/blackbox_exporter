package prober

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

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
		IsCA: true,
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
