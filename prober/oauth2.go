// Copyright 2026 The Prometheus Authors
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
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	pconfig "github.com/prometheus/common/config"
	"go.yaml.in/yaml/v3"
)

// An OAuth2 token depends on the module's oauth2 settings, never on the probe
// target, but the HTTP client is rebuilt per probe because it does carry
// per-target state (TLS ServerName). That used to rebuild the token source as
// well, minting a token per probe per target. Share the OAuth2 round tripper
// instead; its token source reuses tokens until they expire.
//
// Entries are keyed by the oauth2 settings and live for the lifetime of the
// process, so settings that a reload drops leave their round tripper, and the
// token it holds, behind.
var oauth2Cache sync.Map // fingerprint -> *oauth2Entry

// oauth2MinDiscardInterval bounds how often a rejected token is thrown away. A
// target can answer 401 for reasons that have nothing to do with the token,
// and because the token is shared, one such target would otherwise cost a
// token per probe for every target using the same settings. A variable so
// tests do not have to wait.
var oauth2MinDiscardInterval = time.Minute

type oauth2BaseKey struct{}

// oauth2Base stands in for the per-probe transport, which is not known when
// the shared round tripper is built and so travels on the request context.
type oauth2Base struct{}

func (oauth2Base) RoundTrip(req *http.Request) (*http.Response, error) {
	base, ok := req.Context().Value(oauth2BaseKey{}).(http.RoundTripper)
	if !ok {
		return nil, errors.New("no base transport on request context")
	}
	return base.RoundTrip(req)
}

// oauth2Entry holds the round tripper shared by every probe using one oauth2
// config, and the client secret it was built for.
type oauth2Entry struct {
	mtx         sync.Mutex
	rt          http.RoundTripper
	secret      string
	warm        http.RoundTripper
	lastDiscard time.Time
}

// roundTripper returns the shared round tripper, building one if it is missing
// or was built for an older secret. Rebuilding it here, rather than handing
// common/config a secret it reloads itself, keeps it from writing to a round
// tripper that other probes are reading.
func (e *oauth2Entry) roundTripper(cfg *pconfig.OAuth2, secret string) http.RoundTripper {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if e.rt == nil || e.secret != secret {
		e.rt = pconfig.NewOAuth2RoundTripper(pconfig.NewInlineSecret(secret), cfg, oauth2Base{}, pconfig.WithKeepAlivesDisabled())
		e.secret = secret
	}
	return e.rt
}

// roundTrip serializes the first request through a round tripper, because the
// token source is built on first use and common/config looks for it without
// holding its write lock: concurrent first probes would each build one, and
// each fetch a token.
func (e *oauth2Entry) roundTrip(rt http.RoundTripper, req *http.Request) (*http.Response, error) {
	e.mtx.Lock()
	if e.warm == rt {
		e.mtx.Unlock()
		return rt.RoundTrip(req)
	}
	defer e.mtx.Unlock()
	resp, err := rt.RoundTrip(req)
	if err == nil {
		e.warm = rt
	}
	return resp, err
}

// discard drops rt so the next probe fetches a new token, unless it has
// already been replaced or one was discarded too recently.
func (e *oauth2Entry) discard(rt http.RoundTripper) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	if e.rt != rt || time.Since(e.lastDiscard) < oauth2MinDiscardInterval {
		return
	}
	e.rt = nil
	e.lastDiscard = time.Now()
}

type oauth2Transport struct {
	entry  *oauth2Entry
	shared http.RoundTripper
	base   http.RoundTripper
}

func (t *oauth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := context.WithValue(req.Context(), oauth2BaseKey{}, t.base)
	resp, err := t.entry.roundTrip(t.shared, req.WithContext(ctx))
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		t.entry.discard(t.shared)
	}
	return resp, err
}

// newOAuth2Transport authenticates through the OAuth2 round tripper shared by
// all probes using cfg, and sends requests through base.
func newOAuth2Transport(cfg *pconfig.OAuth2, base http.RoundTripper) (http.RoundTripper, error) {
	key, err := oauth2Fingerprint(cfg)
	if err != nil {
		return nil, err
	}
	// Resolved on every probe, so a rotated secret is picked up, and outside
	// the entry lock because it can read a file.
	secret, err := oauth2Secret(cfg)
	if err != nil {
		return nil, err
	}
	v, _ := oauth2Cache.LoadOrStore(key, &oauth2Entry{})
	entry := v.(*oauth2Entry)
	return &oauth2Transport{entry: entry, shared: entry.roundTripper(cfg, secret), base: base}, nil
}

// oauth2Secret resolves the client secret in the order common/config does.
func oauth2Secret(cfg *pconfig.OAuth2) (string, error) {
	text, file, ref := cfg.ClientSecret, cfg.ClientSecretFile, cfg.ClientSecretRef
	if cfg.GrantType == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		text, file, ref = cfg.ClientCertificateKey, cfg.ClientCertificateKeyFile, cfg.ClientCertificateKeyRef
	}
	switch {
	case text != "":
		return string(text), nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("unable to read %s: %w", file, err)
		}
		return strings.TrimSpace(string(b)), nil
	case ref != "":
		return "", errors.New("oauth2 secret references require a secret manager")
	}
	return "", nil
}

// oauth2Fingerprint identifies the token a config yields. Marshalling covers
// fields added later too, and skips the lazily built proxy function, which
// would otherwise change the fingerprint after first use.
func oauth2Fingerprint(cfg *pconfig.OAuth2) (string, error) {
	y, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(y)
	// Marshalling redacts secrets, including a password in proxy_url, so hash
	// those separately.
	proxyURL := ""
	if cfg.ProxyURL.URL != nil {
		proxyURL = cfg.ProxyURL.String()
	}
	fmt.Fprintf(h, "%q%q%q%q%q", cfg.ClientSecret, cfg.ClientCertificateKey,
		cfg.TLSConfig.Key, proxyURL, cfg.ProxyConnectHeader)
	return string(h.Sum(nil)), nil
}
