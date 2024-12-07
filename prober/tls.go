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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func getEarliestCertExpiry(state *tls.ConnectionState) time.Time {
	earliest := time.Time{}
	for _, cert := range state.PeerCertificates {
		if (earliest.IsZero() || cert.NotAfter.Before(earliest)) && !cert.NotAfter.IsZero() {
			earliest = cert.NotAfter
		}
	}
	return earliest
}

func getFingerprint(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}

func getSubject(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	return cert.Subject.String()
}

func getIssuer(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	return cert.Issuer.String()
}

func getDNSNames(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	return strings.Join(cert.DNSNames, ",")
}

func getLastChainExpiry(state *tls.ConnectionState) time.Time {
	lastChainExpiry := time.Time{}
	for _, chain := range state.VerifiedChains {
		earliestCertExpiry := time.Time{}
		for _, cert := range chain {
			if (earliestCertExpiry.IsZero() || cert.NotAfter.Before(earliestCertExpiry)) && !cert.NotAfter.IsZero() {
				earliestCertExpiry = cert.NotAfter
			}
		}
		if lastChainExpiry.IsZero() || lastChainExpiry.Before(earliestCertExpiry) {
			lastChainExpiry = earliestCertExpiry
		}

	}
	return lastChainExpiry
}

func getSerialNumber(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	// Actual serial number = 0B:FF:BC5:11:F1:90:7D:02:AF:71:9A:FC:D6:4F:B2:53
	// serialNumber := cert.SerialNumber.Text(16) // drops leading zeros outputs = BFFBC511F1907D02AF719AFCD64FB253 in lower case, telgraf follows this https://github.com/influxdata/telegraf/blob/a9c91f162ddbe453364f68a89799535c43328a3c/plugins/inputs/x509_cert/x509_cert.go#L218
	// https://github.com/atc0005/check-cert retains the leading zero with some aditional formatting

	serialNumber := strings.ToLower(fmt.Sprintf("%X", cert.SerialNumber.Bytes()))

	return serialNumber
}

func getTLSVersion(state *tls.ConnectionState) string {
	switch state.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func getTLSCipher(state *tls.ConnectionState) string {
	return tls.CipherSuiteName(state.CipherSuite)
}
