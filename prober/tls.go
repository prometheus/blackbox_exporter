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

func getEarliestCertStart(state *tls.ConnectionState) time.Time {
	earliestStart := time.Time{}
	for _, cert := range state.PeerCertificates {
		if (earliestStart.IsZero() || cert.NotBefore.Before(earliestStart)) && !cert.NotBefore.IsZero() {
			earliestStart = cert.NotBefore
		}
	}
	return earliestStart
}

func getEarliestCertExpiry(state *tls.ConnectionState) time.Time {
	earliestExpiry := time.Time{}
	for _, cert := range state.PeerCertificates {
		if (earliestExpiry.IsZero() || cert.NotAfter.Before(earliestExpiry)) && !cert.NotAfter.IsZero() {
			earliestExpiry = cert.NotAfter
		}
	}
	return earliestExpiry
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

func getLastChainStart(state *tls.ConnectionState) time.Time {
	lastChainStart := time.Time{}
	for _, chain := range state.VerifiedChains {
		earliestCertStart := time.Time{}
		for _, cert := range chain {
			if (earliestCertStart.IsZero() || cert.NotBefore.After(earliestCertStart)) && !cert.NotAfter.IsZero() {
				earliestCertStart = cert.NotBefore
			}
		}
		if lastChainStart.IsZero() || lastChainStart.After(earliestCertStart) {
			lastChainStart = earliestCertStart
		}

	}
	return lastChainStart
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
	// Using `cert.SerialNumber.Text(16)` will drop the leading zeros when converting the SerialNumber to String, see https://github.com/mozilla/tls-observatory/pull/245.
	// To avoid that, we format in lowercase the bytes with `%x` to base 16, with lower-case letters for a-f, see https://go.dev/play/p/Fylce70N2Zl.

	return fmt.Sprintf("%x", cert.SerialNumber.Bytes())
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
