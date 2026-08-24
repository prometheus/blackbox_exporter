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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
)

// checkCRL runs CRL checks if enabled in the module config and registers the metrics.
// CRLs are fetched through the probe's proxy configuration, and the fetch is
// bounded by the probe context deadline rather than a dedicated timeout.
func checkCRL(ctx context.Context, state *tls.ConnectionState, enabled bool, proxy *pconfig.ProxyConfig, registry *prometheus.Registry, logger *slog.Logger) {
	if !enabled {
		return
	}
	crlResult := checkChainCRL(ctx, state, proxy, logger)
	registerCRLMetrics(registry, crlResult)
}

// crlHTTPClient returns the client used to fetch CRLs. A non-nil proxy makes the
// fetch follow the same proxy settings as the probe itself; probes without proxy
// support pass nil, which leaves Go's default transport in place.
func crlHTTPClient(proxy *pconfig.ProxyConfig) *http.Client {
	if proxy == nil {
		return &http.Client{}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = proxy.Proxy()
	transport.ProxyConnectHeader = proxy.GetProxyConnectHeader()
	return &http.Client{Transport: transport}
}

// crlCertResult holds the CRL check result for a single certificate in the chain.
type crlCertResult struct {
	Fingerprint        string // SHA-256 fingerprint of the certificate
	Subject            string // certificate subject
	Issuer             string // certificate issuer
	SubjectAlternative string // DNS SANs, comma-separated
	SerialNumber       string // certificate serial number in hex
	ChainPos           int    // position in the certificate chain
	CRLUrl             string // CRL distribution point URL used (empty if no CDP / last attempted on failure)
	Available          bool   // cert has CRL distribution points and CRL was fetchable
	Revoked            bool   // cert serial found in CRL
	Stale              bool   // CRL is past its NextUpdate
	NextUpdate         time.Time
	FetchTime          float64 // seconds to fetch the CRL
	FetchErr           error   // non-nil if CRL fetch failed
}

// checkChainCRL performs CRL checking for all certificates in the TLS connection state.
func checkChainCRL(ctx context.Context, state *tls.ConnectionState, proxy *pconfig.ProxyConfig, logger *slog.Logger) []crlCertResult {
	// Use the best verified chain if available, otherwise fall back to PeerCertificates.
	var chain []*x509.Certificate
	if len(state.VerifiedChains) > 0 {
		chain = state.VerifiedChains[0]
	} else {
		chain = state.PeerCertificates
	}

	if len(chain) == 0 {
		return nil
	}

	var results []crlCertResult
	client := crlHTTPClient(proxy)

	// Check CRL for each certificate in the chain.
	for i, cert := range chain {
		var issuer *x509.Certificate
		if i+1 < len(chain) {
			issuer = chain[i+1]
		} else {
			// Last cert in chain (root) — it's self-signed, use itself as issuer.
			issuer = cert
		}

		certResult := checkCertCRL(ctx, cert, issuer, i, client, logger)
		results = append(results, certResult)
	}

	return results
}

// checkCertCRL checks a single certificate against its CRL.
func checkCertCRL(ctx context.Context, cert, issuer *x509.Certificate, chainPos int, client *http.Client, logger *slog.Logger) crlCertResult {
	fingerprint := sha256.Sum256(cert.Raw)

	result := crlCertResult{
		Fingerprint:        hex.EncodeToString(fingerprint[:]),
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SubjectAlternative: strings.Join(cert.DNSNames, ","),
		SerialNumber:       fmt.Sprintf("%x", cert.SerialNumber.Bytes()),
		ChainPos:           chainPos,
	}

	if len(cert.CRLDistributionPoints) == 0 {
		logger.Debug("No CRL distribution points", "subject", result.Subject, "chain_pos", chainPos)
		return result
	}

	// Try each CRL distribution point until one succeeds.
	for _, crlURL := range cert.CRLDistributionPoints {
		result.CRLUrl = crlURL
		crl, fetchTime, err := fetchCRL(ctx, client, crlURL)
		result.FetchTime += fetchTime

		if err != nil {
			logger.Warn("Failed to fetch CRL", "url", crlURL, "subject", result.Subject, "err", err)
			result.FetchErr = err
			continue
		}

		result.Available = true

		// Verify CRL signature against issuer.
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			logger.Warn("CRL signature verification failed", "url", crlURL, "subject", result.Subject, "err", err)
			result.Available = false
			result.FetchErr = fmt.Errorf("CRL signature verification failed: %w", err)
			continue
		}

		// A CRL whose thisUpdate is in the future is not valid yet; try the next distribution point.
		if !crl.ThisUpdate.IsZero() && crl.ThisUpdate.After(time.Now()) {
			logger.Warn("CRL is not yet valid", "url", crlURL, "subject", result.Subject, "this_update", crl.ThisUpdate)
			result.Available = false
			result.FetchErr = fmt.Errorf("CRL not yet valid: thisUpdate %s is in the future", crl.ThisUpdate)
			continue
		}

		result.NextUpdate = crl.NextUpdate
		if !crl.NextUpdate.IsZero() && crl.NextUpdate.Before(time.Now()) {
			result.Stale = true
			logger.Warn("CRL is stale", "url", crlURL, "subject", result.Subject, "next_update", crl.NextUpdate)
		}

		// Check if cert serial is on the revocation list.
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				result.Revoked = true
				logger.Warn("Certificate is revoked", "subject", result.Subject, "chain_pos", chainPos, "revocation_time", entry.RevocationTime)
				break
			}
		}

		// Successfully checked, no need to try other distribution points.
		break
	}

	return result
}

// fetchCRL downloads a CRL from the given URL and parses it.
// The request is bounded by the probe context deadline carried in ctx.
func fetchCRL(ctx context.Context, client *http.Client, url string) (*x509.RevocationList, float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("creating CRL request: %w", err)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, time.Since(start).Seconds(), fmt.Errorf("fetching CRL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, time.Since(start).Seconds(), fmt.Errorf("CRL fetch returned status %d", resp.StatusCode)
	}

	// Limit CRL size to 10MB to prevent memory issues.
	rawCRL, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	// Measure through the body read so the metric covers the whole fetch, not just time-to-first-byte.
	fetchTime := time.Since(start).Seconds()
	if err != nil {
		return nil, fetchTime, fmt.Errorf("reading CRL body: %w", err)
	}

	crl, err := x509.ParseRevocationList(rawCRL)
	if err != nil {
		return nil, fetchTime, fmt.Errorf("parsing CRL: %w", err)
	}

	return crl, fetchTime, nil
}

// registerCRLMetrics registers CRL-related metrics and populates them from the check results.
func registerCRLMetrics(registry *prometheus.Registry, results []crlCertResult) {
	crlLabels := []string{"fingerprint_sha256", "subject", "issuer", "subjectalternative", "serialnumber", "chain_pos", "crl_url"}

	crlRevoked := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_ssl_crl_revoked",
			Help: "Whether the certificate appears on its CRL (0/1)",
		},
		crlLabels,
	)
	crlFetchTime := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "probe_ssl_crl_fetch_time_seconds",
			Help: "Total time spent fetching CRLs in seconds",
		},
	)
	crlNextUpdate := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_ssl_crl_next_update_timestamp_seconds",
			Help: "CRL nextUpdate as a Unix timestamp in seconds",
		},
		crlLabels,
	)
	crlStale := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_ssl_crl_stale",
			Help: "Whether the CRL is past its nextUpdate (0/1)",
		},
		crlLabels,
	)
	crlAvailable := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_ssl_crl_available",
			Help: "Whether the cert has CRL distribution points and the CRL was fetchable (0/1)",
		},
		crlLabels,
	)

	registry.MustRegister(crlRevoked, crlFetchTime, crlNextUpdate, crlStale, crlAvailable)

	var totalFetchTime float64
	for _, cert := range results {
		lv := []string{cert.Fingerprint, cert.Subject, cert.Issuer, cert.SubjectAlternative, cert.SerialNumber, strconv.Itoa(cert.ChainPos), cert.CRLUrl}

		if cert.Available {
			crlAvailable.WithLabelValues(lv...).Set(1)
		} else {
			crlAvailable.WithLabelValues(lv...).Set(0)
		}

		if cert.Revoked {
			crlRevoked.WithLabelValues(lv...).Set(1)
		} else {
			crlRevoked.WithLabelValues(lv...).Set(0)
		}

		if cert.Stale {
			crlStale.WithLabelValues(lv...).Set(1)
		} else {
			crlStale.WithLabelValues(lv...).Set(0)
		}

		if !cert.NextUpdate.IsZero() {
			crlNextUpdate.WithLabelValues(lv...).Set(float64(cert.NextUpdate.Unix()))
		}

		totalFetchTime += cert.FetchTime
	}
	crlFetchTime.Set(totalFetchTime)
}
