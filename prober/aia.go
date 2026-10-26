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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	maxAIACertificateSize = 1 << 20
	maxAIAChainDepth      = 5
)

func enableAIAFetching(ctx context.Context, tlsConfig *tls.Config) {
	if tlsConfig.InsecureSkipVerify {
		return
	}

	tlsConfig.InsecureSkipVerify = true // Verification is performed by VerifyConnection below.
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		return verifyConnectionWithAIA(ctx, state, tlsConfig.RootCAs, http.DefaultClient)
	}
}

func verifyConnectionWithAIA(ctx context.Context, state tls.ConnectionState, roots *x509.CertPool, client *http.Client) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("server returned no TLS certificates")
	}

	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}

	options := x509.VerifyOptions{
		DNSName:       state.ServerName,
		Roots:         roots,
		Intermediates: intermediates,
	}
	leaf := state.PeerCertificates[0]
	if _, err := leaf.Verify(options); err == nil {
		return nil
	} else if !isUnknownAuthority(err) {
		return err
	}

	current := leaf
	for range maxAIAChainDepth {
		issuer, err := fetchIssuerCertificate(ctx, client, current.IssuingCertificateURL)
		if err != nil {
			return fmt.Errorf("fetching issuer certificate for %q: %w", current.Subject, err)
		}
		intermediates.AddCert(issuer)
		if _, err := leaf.Verify(options); err == nil {
			return nil
		} else if !isUnknownAuthority(err) {
			return err
		}
		if issuer.Equal(current) {
			break
		}
		current = issuer
	}

	_, err := leaf.Verify(options)
	return err
}

func isUnknownAuthority(err error) bool {
	var unknownAuthorityError x509.UnknownAuthorityError
	return errors.As(err, &unknownAuthorityError)
}

func fetchIssuerCertificate(ctx context.Context, client *http.Client, locations []string) (*x509.Certificate, error) {
	if len(locations) == 0 {
		return nil, errors.New("certificate has no issuing certificate URL")
	}

	var fetchErrors []error
	for _, location := range locations {
		parsed, err := url.Parse(location)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			fetchErrors = append(fetchErrors, fmt.Errorf("unsupported issuer URL %q", location))
			continue
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			fetchErrors = append(fetchErrors, err)
			continue
		}
		response, err := client.Do(request)
		if err != nil {
			fetchErrors = append(fetchErrors, err)
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxAIACertificateSize+1))
		response.Body.Close()
		if readErr != nil {
			fetchErrors = append(fetchErrors, readErr)
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			fetchErrors = append(fetchErrors, fmt.Errorf("issuer URL %q returned %s", location, response.Status))
			continue
		}
		if len(data) > maxAIACertificateSize {
			fetchErrors = append(fetchErrors, fmt.Errorf("issuer certificate from %q exceeds %d bytes", location, maxAIACertificateSize))
			continue
		}
		if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
			data = block.Bytes
		}
		certificate, err := x509.ParseCertificate(data)
		if err != nil {
			fetchErrors = append(fetchErrors, fmt.Errorf("parsing issuer certificate from %q: %w", location, err))
			continue
		}
		return certificate, nil
	}

	return nil, errors.Join(fetchErrors...)
}
